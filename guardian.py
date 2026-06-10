#!/usr/bin/env python3
"""
GitLab Security Guardian - Vertex AI Gemini Ensemble Orchestrator with Auto-Remediation

This script orchestrates the autonomous security auditing of GitLab Merge Requests.
It fetches MR code changes, queries Gemini models concurrently as an ensemble,
calculates a consensus score for each finding, synthesizes their descriptions,
automatically generates and applies security patches for findings >= 30% consensus,
and comments the consolidated report back on the Merge Request.
"""

import argparse
import concurrent.futures
import json
import logging
import os
import re
import subprocess
import urllib.parse
from collections import Counter
from typing import Dict, Any, List
import requests
from google import genai
from google.genai import types
from pydantic import BaseModel, Field
from tenacity import retry, wait_random_exponential, stop_after_attempt
import uuid
import queue
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver

# Pydantic schemas for structured LLM response output
class SecurityFinding(BaseModel):
    file: str = Field(description="File path where the vulnerability is found")
    line: int = Field(description="Line number of the finding")
    vulnerability: str = Field(description="Type of vulnerability detected")
    severity: str = Field(description="Severity classification: Critical, High, Medium, or Low")
    description: str = Field(description="Clear explanation of the issue and how to resolve it")

class FindingsList(BaseModel):
    findings: List[SecurityFinding]

def get_safety_settings() -> List[types.SafetySetting]:
    return [
        types.SafetySetting(
            category=types.HarmCategory.HARM_CATEGORY_HARASSMENT,
            threshold=types.HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
        ),
        types.SafetySetting(
            category=types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
            threshold=types.HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
        ),
        types.SafetySetting(
            category=types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
            threshold=types.HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
        ),
        types.SafetySetting(
            category=types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
            threshold=types.HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
        ),
    ]

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("security-guardian")


def parse_agents_config() -> Dict[str, Any]:
    """
    Parses repository-level AGENTS.md for custom instructions and configuration parameters.
    Supports YAML-like frontmatter.
    """
    config = {
        "consensus_threshold": 30.0,
        "excluded_vulnerabilities": [],
        "excluded_files": [],
        "instructions": ""
    }
    if not os.path.exists("AGENTS.md"):
        logger.info("AGENTS.md not found. Using default configurations.")
        return config
        
    logger.info("Parsing AGENTS.md configuration...")
    try:
        with open("AGENTS.md", "r", encoding="utf-8") as f:
            content = f.read()
            
        # Parse YAML frontmatter if it exists
        frontmatter_match = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", content, re.DOTALL)
        markdown_body = content
        if frontmatter_match:
            yaml_text = frontmatter_match.group(1)
            markdown_body = frontmatter_match.group(2)
            
            # Simple YAML-like parser
            current_key = None
            for line in yaml_text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line and not line.startswith("-"):
                    parts = line.split(":", 1)
                    key = parts[0].strip()
                    val = parts[1].strip()
                    if not val:
                        current_key = key
                        if key not in config:
                            config[key] = []
                    else:
                        current_key = None
                        if val.lower() == "true":
                            config[key] = True
                        elif val.lower() == "false":
                            config[key] = False
                        else:
                            try:
                                config[key] = float(val)
                            except ValueError:
                                if (val.startswith("'") and val.endswith("'")) or (val.startswith('"') and val.endswith('"')):
                                    val = val[1:-1]
                                config[key] = val
                elif line.startswith("-") and current_key:
                    val = line[1:].strip()
                    if (val.startswith("'") and val.endswith("'")) or (val.startswith('"') and val.endswith('"')):
                        val = val[1:-1]
                    if isinstance(config.get(current_key), list):
                        config[current_key].append(val)
                    else:
                        config[current_key] = [val]
                        
        config["instructions"] = markdown_body.strip()
        logger.info(f"AGENTS.md parsed successfully: consensus_threshold={config['consensus_threshold']}, "
                    f"excluded_vulnerabilities={config['excluded_vulnerabilities']}, "
                    f"excluded_files={config['excluded_files']}")
    except Exception as e:
        logger.error(f"Error parsing AGENTS.md: {e}")
        
    return config


def fetch_merge_request_diff(project_id: str, mr_iid: int, gitlab_url: str, token: str) -> List[Dict[str, Any]]:
    """
    Fetches the changes/diff of a target Merge Request using the GitLab API.
    
    API Endpoint: GET /projects/:id/merge_requests/:merge_request_iid/changes
    """
    logger.info(f"Fetching diff for MR !{mr_iid} in project {project_id}...")
    
    safe_project_id = urllib.parse.quote_plus(project_id)
    url = f"{gitlab_url.rstrip('/')}/api/v4/projects/{safe_project_id}/merge_requests/{mr_iid}/changes"
    
    headers = {
        "PRIVATE-TOKEN": token,
        "Accept": "application/json"
    }
    
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    
    data = response.json()
    changes = data.get("changes", [])
    logger.info(f"Successfully fetched diff. Total modified files: {len(changes)}")
    return changes


def get_ensemble_models() -> List[Dict[str, Any]]:
    """
    Returns the configurations for the Gemini Vertex AI ensemble.
    Different configurations run with varying temperatures and prompt targets to build consensus.
    """
    return [
        {"name": "gemini-1.5-flash", "temperature": 0.1, "system_suffix": "Focus on high-precision syntax issues and direct security risks.", "id": "Gemini-1.5-Flash (Precision)"},
        {"name": "gemini-1.5-pro", "temperature": 0.2, "system_suffix": "Perform deep logical path analysis, trace data flows, and find subtle logic flaws.", "id": "Gemini-1.5-Pro (Deep)"},
        {"name": "gemini-1.5-flash", "temperature": 0.7, "system_suffix": "Look widely for architectural design issues, dependency vulnerabilities, and configuration flaws.", "id": "Gemini-1.5-Flash (Creative)"},
        {"name": "gemini-1.5-pro", "temperature": 0.8, "system_suffix": "Look closely for hidden race conditions, authorization issues (IDOR), and cryptographic weaknesses.", "id": "Gemini-1.5-Pro (Logical)"}
    ]


@retry(wait=wait_random_exponential(min=2, max=10), stop=stop_after_attempt(5))
def call_gemini_model(client: genai.Client, model_name: str, diff_content: str, temperature: float, system_prompt: str) -> str:
    """
    Sends the git diff to a specific Gemini model on Vertex AI.
    Uses exponential backoff retry to prevent timeouts under load.
    """
    logger.info(f"Sending request to Gemini model {model_name}...")
    response = client.models.generate_content(
        model=model_name,
        contents=f"Please review this git diff:\n\n{diff_content}",
        config=types.GenerateContentConfig(
            system_instruction=system_prompt,
            temperature=temperature,
            response_mime_type="application/json",
            response_schema=FindingsList,
            safety_settings=get_safety_settings()
        )
    )
    return response.text


def extract_json(raw_text: str) -> List[Dict[str, Any]]:
    """
    Parses the structured JSON output returned by the Gemini API.
    """
    cleaned = re.sub(r"<think>.*?</think>", "", raw_text, flags=re.DOTALL).strip()
    code_block_match = re.search(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", cleaned, flags=re.DOTALL)
    if code_block_match:
        json_str = code_block_match.group(1)
    else:
        json_str = cleaned

    try:
        data = json.loads(json_str)
        if isinstance(data, dict) and "findings" in data:
            findings_raw = data["findings"]
        elif isinstance(data, list):
            findings_raw = data
        elif isinstance(data, dict):
            findings_raw = [data]
        else:
            findings_raw = []
            
        # Standardize structure to dictionary
        standardized = []
        for item in findings_raw:
            if isinstance(item, dict):
                standardized.append(item)
            elif hasattr(item, "model_dump"):
                standardized.append(item.model_dump())
            elif hasattr(item, "__dict__"):
                standardized.append(item.__dict__)
        return standardized
    except Exception as e:
        logger.error(f"Failed to parse JSON: {e}")
        return []


@retry(wait=wait_random_exponential(min=2, max=10), stop=stop_after_attempt(5))
def synthesize_descriptions_with_llm(grouped_list: List[Dict[str, Any]], client: genai.Client) -> Dict[str, str]:
    """
    Calls Gemini 1.5 Pro to synthesize multiple descriptions for each grouped vulnerability.
    """
    if not grouped_list:
        return {}
        
    logger.info("Calling Gemini 1.5 Pro to synthesize vulnerability descriptions...")
    
    input_data = []
    for g in grouped_list:
        input_data.append({
            "key": f"{g['file']}:{g['line']}",
            "vulnerability": g["vulnerability"],
            "descriptions": list(set([d for d in g["descriptions"] if d]))
        })
        
    system_prompt = (
        "You are an expert technical editor and security writer. "
        "You will receive a JSON list of grouped security findings. Each finding has a key (file:line), a vulnerability type, and a list of descriptions from different scanner configurations.\n"
        "Your task is to synthesize the descriptions for each finding into a single, clean, concise summary (1-3 sentences) that combines the best points and recommendations.\n"
        "Respond ONLY with a JSON object where the keys are the finding keys (file:line) and the values are the synthesized description strings. Do not include any markdown formatting outside the JSON itself."
    )
    
    try:
        response = client.models.generate_content(
            model="gemini-1.5-pro",
            contents=json.dumps(input_data),
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                temperature=0.2,
                response_mime_type="application/json",
                safety_settings=get_safety_settings()
            )
        )
        content = response.text.strip()
        cleaned = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
        code_block_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, flags=re.DOTALL)
        if code_block_match:
            json_str = code_block_match.group(1)
        else:
            json_str = cleaned
            
        synthesized_map = json.loads(json_str)
        if isinstance(synthesized_map, dict):
            logger.info("Successfully synthesized descriptions.")
            return synthesized_map
    except Exception as e:
        logger.warning(f"Failed to synthesize descriptions with LLM: {str(e)}. Falling back to local concatenation.")
        
    return {}


@retry(wait=wait_random_exponential(min=2, max=10), stop=stop_after_attempt(5))
def generate_remediation_patch(client: genai.Client, file_path: str, vuln_type: str, line_num: int, description: str, file_content: str) -> str:
    system_prompt = (
        "You are an expert security engineer.\n"
        "Your task is to fix the security vulnerability in the provided file content.\n"
        "You must return the correction in the following search-and-replace format:\n\n"
        "<<<<<<< ORIGINAL\n"
        "[exact original code block from the file to be replaced]\n"
        "=======\n"
        "[corrected code block]\n"
        ">>>>>>> CORRECTED\n\n"
        "Ensure the ORIGINAL section matches the file content exactly (including spaces, indentation, and comments).\n"
        "Make the ORIGINAL section large enough to contain the vulnerable code and any surrounding context needed to locate it uniquely.\n"
        "Return ONLY the conflict markers block. Do not include any introductory or concluding text, explanations, or markdown code fences outside the markers."
    )
    
    user_content = (
        f"File: {file_path}\n"
        f"Vulnerability Type: {vuln_type}\n"
        f"Line: {line_num}\n"
        f"Description: {description}\n\n"
        f"File Content:\n"
        f"```\n{file_content}\n```"
    )
    
    response = client.models.generate_content(
        model="gemini-1.5-pro",
        contents=user_content,
        config=types.GenerateContentConfig(
            system_instruction=system_prompt,
            temperature=0.1,
            safety_settings=get_safety_settings()
        )
    )
    return response.text


def validate_patch_ast_and_safety(corrected_code: str, file_path: str) -> str:
    """
    Parses the corrected code using Python's ast module if it's a Python file,
    and checks for forbidden insecure functions.
    Returns None if valid, or an error status string if invalid.
    """
    import ast
    # 1. AST Validation for Python files
    if file_path.endswith(".py"):
        try:
            ast.parse(corrected_code)
        except SyntaxError as se:
            logger.warning(f"AST validation failed for patch in {file_path}: {se}")
            return f"❌ Failed validation (Syntax error in AI generated patch: {str(se)})"

    # 2. Insecure Call Detection (General/Python)
    forbidden_terms = ["eval(", "exec(", "__import__(", "os.system(", "os.popen(", "subprocess.Popen(", "subprocess.run("]
    for term in forbidden_terms:
        if term in corrected_code:
            logger.warning(f"Safety guardrail failed: forbidden call '{term}' found in patch for {file_path}")
            return f"❌ Failed validation (Insecure call '{term}' detected in AI patch)"
            
    return None


def generate_remediations(consolidated_findings: List[Dict[str, Any]], client: genai.Client, consensus_threshold: float = 30.0, apply_to_disk: bool = True) -> tuple:
    """
    Loops through findings with Consensus Score >= consensus_threshold and calls Gemini to secure the code.
    Writes the corrected code blocks directly to local files and verifies their success if apply_to_disk is True.
    Returns:
        (remediated_results, modified_files)
    """
    remediated_results = []
    modified_files = set()
    
    # Filter findings with score >= consensus_threshold
    high_confidence_findings = [g for g in consolidated_findings if g.get("score", 0) >= consensus_threshold]
    
    if not high_confidence_findings:
        logger.info(f"No high-confidence findings (Consensus Score >= {consensus_threshold:.0f}%) to auto-remediate.")
        return [], []
        
    logger.info(f"Attempting to generate remediations for {len(high_confidence_findings)} findings...")
    
    # Group findings by file path to process each file
    findings_by_file = {}
    for g in high_confidence_findings:
        file_path = g.get("file")
        if not file_path or not os.path.exists(file_path):
            logger.warning(f"File {file_path} does not exist or was not specified. Skipping.")
            continue
        if file_path not in findings_by_file:
            findings_by_file[file_path] = []
        findings_by_file[file_path].append(g)

    for file_path, file_findings in findings_by_file.items():
        # Sort findings by line number descending to avoid line shift issues when applying patches
        file_findings.sort(key=lambda x: int(x.get("line", 0)) if str(x.get("line", "")).isdigit() else 0, reverse=True)
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                file_content = f.read().replace("\r\n", "\n")
        except Exception as e:
            logger.error(f"Failed to read file {file_path}: {str(e)}")
            continue

        file_modified = False
        for g in file_findings:
            line_val = g.get("line")
            description = g.get("synthesized_description", "")
            vuln_type = g.get("vulnerability", "N/A")
            
            try:
                line_num = int(line_val)
            except (ValueError, TypeError):
                logger.warning(f"Invalid line number {line_val} for finding in {file_path}. Skipping.")
                continue

            lines = file_content.splitlines()
            line_idx = line_num - 1
            if line_idx < 0 or line_idx >= len(lines):
                logger.warning(f"Line number {line_num} out of bounds for file {file_path}. Skipping.")
                continue

            # Apply patch
            try:
                corrected_raw = generate_remediation_patch(client, file_path, vuln_type, line_num, description, file_content)
                
                # Parse the conflict markers
                pattern = r"<<<<<<< ORIGINAL\n(.*?)\n=======\n(.*?)\n>>>>>>> CORRECTED"
                match = re.search(pattern, corrected_raw, re.DOTALL)
                
                original_clean = None
                corrected_clean = None
                
                if match:
                    original_code = match.group(1)
                    corrected_code = match.group(2)
                    
                    original_clean = original_code.replace("\r\n", "\n")
                    corrected_clean = corrected_code.replace("\r\n", "\n")
                    
                    # Run AST and Safety Validation
                    validation_status = validate_patch_ast_and_safety(corrected_clean, file_path)
                    if validation_status:
                        status = validation_status
                    elif original_clean in file_content:
                        if apply_to_disk:
                            # Apply the patch in memory
                            file_content = file_content.replace(original_clean, corrected_clean, 1)
                            file_modified = True
                            status = "✅ Patched & Applied"
                        else:
                            status = "Pending Approval"
                        logger.info(f"Remediation patch validated for {file_path} at line {line_num}. Status: {status}")
                    else:
                        status = "❌ Failed to apply (Original block match failed)"
                        logger.warning(f"Original block not found in {file_path} for line {line_num}.")
                else:
                    status = "❌ Failed to apply (Response format unparseable)"
                    logger.warning(f"Failed to parse conflict markers in response for {file_path} at line {line_num}.")
                
                remediated_results.append({
                    "file": file_path,
                    "line": line_num,
                    "vulnerability": vuln_type,
                    "status": status,
                    "original_code": original_clean,
                    "corrected_code": corrected_clean
                })
                
            except Exception as e:
                logger.error(f"Failed to remediate {file_path} at line {line_num}: {str(e)}")
                remediated_results.append({
                    "file": file_path,
                    "line": line_num,
                    "vulnerability": vuln_type,
                    "status": f"❌ Failed to apply ({str(e)})",
                    "original_code": None,
                    "corrected_code": None
                })

        if file_modified and apply_to_disk:
            try:
                # Write back the final modified content to disk
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(file_content)
                
                # Verify successful write by reading it back
                with open(file_path, "r", encoding="utf-8") as f:
                    check_content = f.read()
                
                if check_content:
                    modified_files.add(file_path)
                    logger.info(f"Successfully wrote and verified local file updates for {file_path}")
                else:
                    raise IOError("Read back content was empty.")
            except Exception as e:
                logger.error(f"Failed to write/verify modifications for {file_path}: {str(e)}")
                # Adjust status of findings for this file to failed since writing failed
                for r in remediated_results:
                    if r["file"] == file_path and r["status"] == "✅ Patched & Applied":
                        r["status"] = f"❌ Failed to apply (Write verification failed: {str(e)})"

    return remediated_results, list(modified_files)


def analyze_diff_ensemble(changes: List[Dict[str, Any]], client: genai.Client, auto_remediate: bool = True) -> str:
    """
    Runs concurrent analysis of the diff using Google Cloud Vertex AI (Gemini) ensemble configurations,
    then aggregates findings using a consensus and confidence score calculation,
    and runs the auto-remediation engine for high-confidence issues.
    """
    # 1. Parse repository-level configurations from AGENTS.md
    config = parse_agents_config()
    consensus_threshold = config.get("consensus_threshold", 30.0)
    excluded_files = [f.lower().strip() for f in config.get("excluded_files", [])]
    excluded_vulns = [v.lower().strip() for v in config.get("excluded_vulnerabilities", [])]
    custom_instructions = config.get("instructions", "")

    logger.info("Preparing diff content for Gemini analysis...")
    
    diff_content_parts = []
    for change in changes:
        new_path = change.get("new_path")
        if new_path:
            is_excluded = False
            for exc_f in excluded_files:
                if exc_f in new_path.lower():
                    is_excluded = True
                    break
            if is_excluded:
                logger.info(f"Skipping diff analysis for excluded file: {new_path}")
                continue
                
        diff = change.get("diff", "")
        if diff:
            diff_content_parts.append(f"File: {new_path}\nDiff:\n{diff}\n" + "="*80)
            
    diff_content = "\n".join(diff_content_parts)
    
    # Input size/token limits safety validation
    MAX_DIFF_CHARS = 50000
    if len(diff_content) > MAX_DIFF_CHARS:
        logger.warning(f"Diff content length ({len(diff_content)} chars) exceeds safety guardrail limit ({MAX_DIFF_CHARS} chars). Truncating diff to protect safety classifiers.")
        diff_content = diff_content[:MAX_DIFF_CHARS] + "\n\n... [DIFF TRUNCATED FOR SAFETY AND TOKEN LIMITS] ..."
    
    if not diff_content.strip():
        logger.info("No code changes detected in the diff.")
        return "✅ **No code changes detected in this Merge Request.**", [], [], []
        
    ensemble = get_ensemble_models()
    
    findings_by_model = {}
    successful_models_count = 0

    logger.info(f"Spawning concurrent threads with max_workers=4 to query {len(ensemble)} model configurations...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = {}
        for config_model in ensemble:
            system_instruction = f"You are a strict Application Security Engineer. Analyze the provided git diff for security vulnerabilities, logical flaws, injection risks, and bad practices. {config_model['system_suffix']}"
            if custom_instructions:
                system_instruction += f"\n\nAdditional instructions from AGENTS.md:\n{custom_instructions}"
                
            futures[executor.submit(
                call_gemini_model, 
                client, 
                config_model["name"], 
                diff_content, 
                config_model["temperature"],
                system_instruction
            )] = config_model["id"]
            
        for future in concurrent.futures.as_completed(futures):
            model_id = futures[future]
            try:
                raw_response = future.result()
                parsed_findings = extract_json(raw_response)
                if parsed_findings:
                    findings_by_model[model_id] = parsed_findings
                successful_models_count += 1
            except Exception as exc:
                logger.warning(f"Silently ignoring failure from configuration {model_id} (Error: {exc})")

    if successful_models_count == 0:
        return "❌ **All Vertex AI Gemini configurations failed to return results or timed out.**", [], [], []

    # Group findings by file and line number
    groups = {}
    for model_name, findings in findings_by_model.items():
        for f in findings:
            file_path = f.get("file", "N/A")
            line_val = str(f.get("line", "N/A"))
            key = (file_path, line_val)
            
            if key not in groups:
                groups[key] = {
                    "file": file_path,
                    "line": line_val,
                    "vulnerability_types": [],
                    "descriptions": [],
                    "models": []
                }
            groups[key]["vulnerability_types"].append(f.get("vulnerability", "N/A"))
            groups[key]["descriptions"].append(f.get("description", ""))
            groups[key]["models"].append(model_name)

    # Process grouped vulnerabilities
    final_groups = []
    for (file_path, line_val), data in groups.items():
        # Double check file exclusion
        is_file_excluded = False
        for exc_f in excluded_files:
            if exc_f in file_path.lower():
                is_file_excluded = True
                break
        if is_file_excluded:
            logger.info(f"Skipping grouped finding due to excluded file: {file_path}")
            continue
            
        unique_models = set(data["models"])
        score_pct = (len(unique_models) / successful_models_count) * 100
        vuln_type = Counter(data["vulnerability_types"]).most_common(1)[0][0]
        
        # Check vulnerability exclusion
        if any(exc_v in vuln_type.lower() for exc_v in excluded_vulns):
            logger.info(f"Skipping finding due to excluded vulnerability: {vuln_type} at {file_path}:{line_val}")
            continue
            
        final_groups.append({
            "file": file_path,
            "line": line_val,
            "score": score_pct,
            "vulnerability": vuln_type,
            "descriptions": data["descriptions"]
        })

    if not final_groups:
        return "✅ **No security vulnerabilities or exposed secrets detected by any active model configuration.**", [], [], []

    # Sort grouped findings by Consensus Score descending
    final_groups.sort(key=lambda x: x["score"], reverse=True)

    # Synthesize descriptions
    synthesized_map = {}
    try:
        synthesized_map = synthesize_descriptions_with_llm(final_groups, client)
    except Exception as e:
        logger.warning(f"Failed to run synthesis: {str(e)}")

    # Map the synthesized descriptions back
    for g in final_groups:
        key = f"{g['file']}:{g['line']}"
        if key in synthesized_map:
            g["synthesized_description"] = synthesized_map[key]
        else:
            unique_descs = list(set([d for d in g["descriptions"] if d]))
            g["synthesized_description"] = max(unique_descs, key=len) if unique_descs else "No description provided."

    # Run Auto-Remediation Engine (Always run to generate patches for HITL if disabled)
    try:
        remediated_results, remediated_files = generate_remediations(
            final_groups, client, consensus_threshold, apply_to_disk=auto_remediate
        )
    except Exception as e:
        logger.error(f"Remediation engine failed: {str(e)}")

    # Format the report table
    markdown = [
        "### 📊 Security Consensus & Confidence Report",
        "| File | Line | Consensus Score | Vulnerability Type | Synthesized Description |",
        "| :--- | :--- | :--- | :--- | :--- |"
    ]
    
    for g in final_groups:
        safe_desc = g["synthesized_description"].replace('\n', ' ').replace('|', '\\|')
        markdown.append(
            f"| `{g['file']}` | {g['line']} | **{g['score']:.0f}%** | {g['vulnerability']} | {safe_desc} |"
        )
        
    # Add Auto-Remediation report section
    markdown.append("\n### 🛠️ Automated Patches Applied")
    if remediated_results:
        markdown.append("The Guardian attempted automatic security patches for the following findings:")
        markdown.append("")
        markdown.append("| File | Line | Vulnerability Type | Status |")
        markdown.append("| :--- | :--- | :--- | :--- |")
        for r in remediated_results:
            markdown.append(f"| `{r['file']}` | {r['line']} | **{r['vulnerability']}** | {r['status']} |")
    else:
        markdown.append("No automated patches were applied (either no high-confidence findings were identified, or remediation was skipped).")
        
    return "\n".join(markdown), remediated_files, final_groups, remediated_results


def post_mr_comment(project_id: str, mr_iid: int, comment: str, gitlab_url: str, token: str) -> Dict[str, Any]:
    """
    Posts a summary comment back to the Merge Request with findings.
    
    API Endpoint: POST /projects/:id/merge_requests/:merge_request_iid/notes
    """
    logger.info(f"Posting security summary comment to MR !{mr_iid}...")
    
    safe_project_id = urllib.parse.quote_plus(project_id)
    url = f"{gitlab_url.rstrip('/')}/api/v4/projects/{safe_project_id}/merge_requests/{mr_iid}/notes"
    
    headers = {
        "PRIVATE-TOKEN": token,
        "Content-Type": "application/json"
    }
    
    payload = {"body": comment}
    
    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()
    
    logger.info("Successfully posted comment to Merge Request.")
    return response.json()


def git_commit_and_push(remediated_files: List[str], token: str, project_id: str, gitlab_url: str):
    """
    Stages, commits, and pushes the modified files back to the GitLab repository.
    Creates a new remediation branch if on a protected branch like main/master/production.
    Appends [skip ci] to prevent CI infinite pipeline loops.
    """
    if not remediated_files:
        logger.info("No modified files to commit.")
        return
        
    logger.info("Starting Git operations at the end of the execution...")
    try:
        # Check current status
        status_res = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True)
        logger.info(f"Current git status:\n{status_res.stdout}")
        
        # Configure user info if not configured
        subprocess.run(["git", "config", "user.name", "GitLab Security Guardian"], check=True)
        subprocess.run(["git", "config", "user.email", "guardian@gitlab.local"], check=True)
        
        # Get current branch name
        branch_res = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True, check=True)
        current_branch = branch_res.stdout.strip()
        logger.info(f"Current git branch is: {current_branch}")
        
        # If we are on a protected branch, checkout a new branch for safety
        target_branch = current_branch
        if current_branch in ["main", "master", "production", "development"]:
            import time
            target_branch = f"guardian/remediation-{int(time.time())}"
            logger.info(f"Currently on protected branch '{current_branch}'. Creating new sub-branch '{target_branch}' for safety...")
            subprocess.run(["git", "checkout", "-b", target_branch], check=True)
            
        # Stage the files
        for f in remediated_files:
            logger.info(f"Adding file to git: {f}")
            subprocess.run(["git", "add", f], check=True)
            
        commit_msg = "chore: apply automated security patches [skip ci]"
        commit_res = subprocess.run(["git", "commit", "-m", commit_msg], capture_output=True, text=True)
        logger.info(f"Git commit output:\n{commit_res.stdout}\n{commit_res.stderr}")
        
        # Configure remote URL with token for push authentication
        parsed_url = urllib.parse.urlparse(gitlab_url)
        git_remote_url = f"https://oauth2:{token}@{parsed_url.netloc}/{project_id}.git"
        
        # Push targeting target_branch
        logger.info(f"Pushing changes to remote repository branch {target_branch}...")
        push_res = subprocess.run(["git", "push", git_remote_url, f"HEAD:{target_branch}"], capture_output=True, text=True)
        logger.info(f"Git push output:\n{push_res.stdout}\n{push_res.stderr}")
        
        # If we checked out a new branch, switch back to the original branch
        if target_branch != current_branch:
            logger.info(f"Switching back to original branch '{current_branch}'...")
            subprocess.run(["git", "checkout", current_branch], check=True)
            
    except Exception as e:
        logger.error(f"Git operations failed: {str(e)}")


def check_db_auto_remediation(guardian_user_id: str) -> bool:
    if not guardian_user_id:
        return True # Default to True if no SaaS user linked
    db_path = os.path.join(os.path.dirname(__file__), "web", "guardian.db")
    if not os.path.exists(db_path):
        return True
    try:
        import sqlite3
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT auto_remediation FROM users WHERE guardian_user_id = ?", (guardian_user_id,))
        row = cursor.fetchone()
        conn.close()
        if row is not None:
            return bool(row[0])
    except Exception as e:
        logger.warning(f"Could not read auto_remediation from database: {e}")
    return True


def report_scans_to_portal(guardian_user_id: str, repo_name: str, scans: List[Dict[str, Any]], portal_url: str = None):
    if not portal_url:
        portal_url = os.environ.get("GUARDIAN_PORTAL_URL", "http://localhost:3000")
        
    url = f"{portal_url.rstrip('/')}/api/scans/report"
    payload = {
        "guardian_user_id": guardian_user_id,
        "repo_name": repo_name,
        "scans": scans
    }
    logger.info(f"Reporting {len(scans)} findings to Guardian portal at {url}...")
    try:
        response = requests.post(url, json=payload, timeout=15)
        if response.status_code == 200:
            logger.info("Successfully reported scans to Guardian portal.")
        else:
            logger.warning(f"Guardian portal responded with status {response.status_code}: {response.text}")
    except Exception as e:
        logger.error(f"Failed to report scans to Guardian portal: {str(e)}")


sse_sessions = {}

def handle_mcp_request(request: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(request, dict) or "method" not in request:
        return None
        
    method = request["method"]
    req_id = request.get("id")
    
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "gitlab-security-guardian",
                    "version": "1.0.0"
                }
            }
        }
    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "run_security_scan",
                        "description": "Runs the GitLab Security Guardian ensemble scan and remediation orchestrator on a GitLab Merge Request.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "project_id": {
                                    "type": "string",
                                    "description": "The GitLab Project ID or Path (e.g. soft-hive-group/project)"
                                },
                                "mr_iid": {
                                    "type": "integer",
                                    "description": "The Merge Request IID (Internal ID)"
                                },
                                "gitlab_url": {
                                    "type": "string",
                                    "description": "Optional GitLab base URL (defaults to https://gitlab.com)"
                                },
                                "gcp_project": {
                                    "type": "string",
                                    "description": "The GCP Project ID where Vertex AI is set up"
                                },
                                "gcp_location": {
                                    "type": "string",
                                    "description": "Optional Vertex AI region/location (defaults to us-central1)"
                                }
                            },
                            "required": ["project_id", "mr_iid", "gcp_project"]
                        }
                    }
                ]
            }
        }
    elif method == "tools/call":
        params = request.get("params", {})
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        
        if tool_name == "run_security_scan":
            project_id = arguments.get("project_id")
            mr_iid = arguments.get("mr_iid")
            gitlab_url = arguments.get("gitlab_url", "https://gitlab.com")
            gcp_project = arguments.get("gcp_project")
            gcp_location = arguments.get("gcp_location", "us-central1")
            
            if not project_id or not mr_iid or not gcp_project:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "isError": True,
                        "content": [
                            {
                                "type": "text",
                                "text": "Error: project_id, mr_iid, and gcp_project are required arguments."
                            }
                        ]
                    }
                }
                
            try:
                logger.info(f"MCP Scan Request started for MR !{mr_iid} in project {project_id}...")
                client = genai.Client(
                    vertexai=True,
                    project=gcp_project,
                    location=gcp_location
                )
                
                gitlab_token = os.environ.get("GITLAB_TOKEN")
                if not gitlab_token:
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "isError": True,
                            "content": [
                                {
                                    "type": "text",
                                    "text": "Error: GITLAB_TOKEN environment variable is not set."
                                }
                            ]
                        }
                    }
                    
                changes = fetch_merge_request_diff(project_id, int(mr_iid), gitlab_url, gitlab_token)
                
                guardian_user_id = os.environ.get("GUARDIAN_USER_ID")
                auto_remediate_arg = arguments.get("auto_remediate", None)
                if auto_remediate_arg is not None:
                    auto_remediate = bool(auto_remediate_arg)
                else:
                    auto_remediate = check_db_auto_remediation(guardian_user_id)
                
                report_markdown, remediated_files, final_groups, remediated_results = analyze_diff_ensemble(changes, client, auto_remediate=auto_remediate)
                if guardian_user_id:
                    scans_to_report = []
                    for g in final_groups:
                        status = "✅ No patch needed (Consensus low)"
                        original_code = None
                        corrected_code = None
                        for r in remediated_results:
                            if r["file"] == g["file"] and str(r["line"]) == str(g["line"]):
                                status = r["status"]
                                original_code = r.get("original_code")
                                corrected_code = r.get("corrected_code")
                                break
                        scans_to_report.append({
                            "file": g["file"],
                            "line": int(g["line"]) if str(g["line"]).isdigit() else 0,
                            "consensus_score": int(g["score"]),
                            "vulnerability": g["vulnerability"],
                            "description": g["synthesized_description"],
                            "status": status,
                            "original_code": original_code,
                            "corrected_code": corrected_code
                        })
                    report_scans_to_portal(guardian_user_id, project_id, scans_to_report)
                
                full_comment = f"## 🛡️ GitLab Security Guardian Consensus Report\n\n{report_markdown}"
                post_mr_comment(project_id, int(mr_iid), full_comment, gitlab_url, gitlab_token)
                
                if remediated_files:
                    git_commit_and_push(remediated_files, gitlab_token, project_id, gitlab_url)
                    
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"Scan completed successfully.\n\n{report_markdown}"
                            }
                        ]
                    }
                }
            except Exception as e:
                logger.error(f"Error during security scan: {e}")
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "isError": True,
                        "content": [
                            {
                                "type": "text",
                                "text": f"Scan execution failed: {str(e)}"
                            }
                        ]
                    }
                }
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {tool_name}"
                }
            }
    return None

class MCPHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        logger.info(f"HTTP Server: {format % args}")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        # Health check endpoint for Cloud Run startup probe
        if parsed_path.path == "/" or parsed_path.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({"status": "ok", "service": "guardian-mcp-runner"}).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed_path.path == "/sse":
            session_id = str(uuid.uuid4())
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            def send_chunk(data_str: str):
                data_bytes = data_str.encode("utf-8")
                self.wfile.write(f"{len(data_bytes):x}\r\n".encode("utf-8"))
                self.wfile.write(data_bytes)
                self.wfile.write(b"\r\n")
                self.wfile.flush()

            host = self.headers.get("Host", "localhost:8000")
            message_url = f"http://{host}/message?session_id={session_id}"
            
            send_chunk(f"event: endpoint\ndata: {message_url}\n\n")
            
            q = queue.Queue()
            sse_sessions[session_id] = q
            logger.info(f"New SSE session established: {session_id}")
            
            try:
                while True:
                    try:
                        msg = q.get(timeout=15)
                        if msg == "SHUTDOWN":
                            break
                        send_chunk(f"event: message\ndata: {json.dumps(msg)}\n\n")
                    except queue.Empty:
                        send_chunk(":\n\n")
            except Exception as e:
                logger.info(f"SSE session {session_id} disconnected: {e}")
            finally:
                if session_id in sse_sessions:
                    del sse_sessions[session_id]
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_POST(self):
        parsed_path = urllib.parse.urlparse(self.path)
        if parsed_path.path == "/message":
            query_params = urllib.parse.parse_qs(parsed_path.query)
            session_id = query_params.get("session_id", [None])[0]
            
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)
            
            try:
                request = json.loads(post_data.decode("utf-8"))
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            def process_and_respond():
                response = handle_mcp_request(request)
                if response and session_id in sse_sessions:
                    sse_sessions[session_id].put(response)
                    
            threading.Thread(target=process_and_respond).start()
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

def run_stdio_mcp_server():
    logger.info("Starting Stdio MCP Server...")
    import sys
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stdin.reconfigure(encoding='utf-8')
    
    # Direct logging to stderr exclusively in stdio mode to avoid JSON stream corruption
    for handler in logging.getLogger().handlers:
        if isinstance(handler, logging.StreamHandler):
            handler.stream = sys.stderr
            
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            request = json.loads(line)
            response = handle_mcp_request(request)
            if response:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
        except Exception as e:
            logger.error(f"Error in stdio server loop: {e}")

class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True

def run_sse_mcp_server(port: int):
    logger.info(f"Starting SSE HTTP MCP Server on port {port}...")
    server = ThreadingHTTPServer(("0.0.0.0", port), MCPHTTPRequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        logger.info("SSE HTTP MCP Server stopped.")


def main():
    parser = argparse.ArgumentParser(description="GitLab Security Guardian Vertex AI Ensemble Orchestrator")
    parser.add_argument("--project-id", help="GitLab Project ID or Path (e.g. soft-hive-group/project)")
    parser.add_argument("--mr-iid", type=int, help="Merge Request Internal ID (IID)")
    parser.add_argument("--gitlab-url", default=os.getenv("GITLAB_API_URL", "https://gitlab.com"), help="GitLab base URL")
    parser.add_argument("--gcp-project", default=os.getenv("GCP_PROJECT_ID"), help="GCP Project ID")
    parser.add_argument("--gcp-location", default=os.getenv("GCP_LOCATION", "us-central1"), help="Vertex AI location")
    parser.add_argument("--mcp-stdio", action="store_true", help="Run in Stdio Model Context Protocol (MCP) server mode")
    parser.add_argument("--mcp-sse", action="store_true", help="Run in HTTP/SSE Model Context Protocol (MCP) server mode")
    parser.add_argument("--mcp-port", type=int, default=8000, help="Port to bind the SSE MCP server to (defaults to 8000)")
    parser.add_argument("--auto-remediate", action="store_true", default=None, help="Force enable auto-remediation (database override)")
    parser.add_argument("--no-auto-remediate", action="store_true", help="Force disable auto-remediation (database override)")
    
    args = parser.parse_args()
    
    if args.mcp_stdio:
        run_stdio_mcp_server()
        return
        
    if args.mcp_sse:
        run_sse_mcp_server(args.mcp_port)
        return
        
    # Standard CLI validation
    if not args.project_id or not args.mr_iid:
        parser.error("--project-id and --mr-iid are required when not running in MCP mode.")
        
    token = os.environ.get('GITLAB_TOKEN')
    
    if not token:
        logger.error("Environment variable 'GITLAB_TOKEN' is missing.")
        exit(1)
        
    if not args.gcp_project:
        logger.error("GCP Project ID is missing. Provide it via --gcp-project or setting GCP_PROJECT_ID env var.")
        exit(1)
        
    # Setup Vertex AI GenAI Client
    logger.info(f"Initializing Google GenAI Client targeting GCP project: {args.gcp_project} in region: {args.gcp_location}...")
    try:
        client = genai.Client(
            vertexai=True,
            project=args.gcp_project,
            location=args.gcp_location
        )
    except Exception as e:
        logger.critical(f"Failed to initialize Vertex AI client: {e}")
        exit(1)
        
    try:
        # 1. Fetch changes
        changes = fetch_merge_request_diff(args.project_id, args.mr_iid, args.gitlab_url, token)
        
        # Determine auto-remediation behavior: CLI flags override the database settings
        guardian_user_id = os.environ.get("GUARDIAN_USER_ID")
        if args.no_auto_remediate:
            auto_remediate = False
        elif args.auto_remediate:
            auto_remediate = True
        else:
            auto_remediate = check_db_auto_remediation(guardian_user_id)

        # 2. Analyze using Vertex AI Gemini Ensemble with Consensus & Auto-Remediation
        # Local file modifications are performed and verified inside this call
        report_markdown, remediated_files, final_groups, remediated_results = analyze_diff_ensemble(changes, client, auto_remediate=auto_remediate)
        
        # Report results back to the web application if GUARDIAN_USER_ID is set
        guardian_user_id = os.environ.get("GUARDIAN_USER_ID")
        if guardian_user_id:
            scans_to_report = []
            for g in final_groups:
                # Find matching remediation status
                status = "✅ No patch needed (Consensus low)"
                original_code = None
                corrected_code = None
                for r in remediated_results:
                    if r["file"] == g["file"] and str(r["line"]) == str(g["line"]):
                        status = r["status"]
                        original_code = r.get("original_code")
                        corrected_code = r.get("corrected_code")
                        break
                
                scans_to_report.append({
                    "file": g["file"],
                    "line": int(g["line"]) if str(g["line"]).isdigit() else 0,
                    "consensus_score": int(g["score"]),
                    "vulnerability": g["vulnerability"],
                    "description": g["synthesized_description"],
                    "status": status,
                    "original_code": original_code,
                    "corrected_code": corrected_code
                })
            
            report_scans_to_portal(guardian_user_id, args.project_id, scans_to_report)
        else:
            logger.info("GUARDIAN_USER_ID not set. Skipping report back to portal.")
        
        # 3. Post comment back to GitLab MR
        full_comment = f"## 🛡️ GitLab Security Guardian Consensus Report\n\n{report_markdown}"
        post_mr_comment(args.project_id, args.mr_iid, full_comment, args.gitlab_url, token)
        
        # 4. Git operations occur at the absolute end of guardian.py after all reports are compiled and commented
        if remediated_files:
            git_commit_and_push(remediated_files, token, args.project_id, args.gitlab_url)
        
        logger.info("Orchestration pipeline finished successfully.")
        
    except Exception as e:
        logger.critical(f"Guardian orchestrator failed: {str(e)}")
        exit(1)


if __name__ == "__main__":
    main()
