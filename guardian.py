#!/usr/bin/env python3
"""
GitLab Security Guardian - OpenRouter Mega-Ensemble Orchestrator with Auto-Remediation

This script orchestrates the autonomous security auditing of GitLab Merge Requests.
It fetches MR code changes, queries all free OpenRouter models concurrently,
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

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("security-guardian")


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


def get_free_models() -> List[str]:
    """
    Queries the OpenRouter models API and filters for free models.
    """
    logger.info("Fetching dynamic models list from OpenRouter...")
    url = "https://openrouter.ai/api/v1/models"
    
    fallback_models = [
        "meta-llama/llama-3.3-70b-instruct:free",
        "google/gemma-3-27b-it:free",
        "qwen/qwen-2.5-72b-instruct:free"
    ]
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        models_list = data.get("data", [])
        
        free_ids = []
        for m in models_list:
            model_id = m.get("id", "")
            pricing = m.get("pricing", {})
            
            is_free_by_name = model_id.endswith(":free")
            try:
                is_free_by_price = (
                    float(pricing.get("prompt", "1")) == 0.0 and
                    float(pricing.get("completion", "1")) == 0.0
                )
            except (ValueError, TypeError):
                is_free_by_price = False
                
            if is_free_by_name or is_free_by_price:
                if model_id:
                    free_ids.append(model_id)
                    
        free_ids = sorted(list(set(free_ids)))
        logger.info(f"Successfully fetched {len(models_list)} models. Found {len(free_ids)} free models.")
        
        return free_ids if free_ids else fallback_models
        
    except Exception as e:
        logger.error(f"Failed to fetch dynamic models list: {str(e)}. Using fallback list.")
        return fallback_models


def call_openrouter_model(model_name: str, diff_content: str, api_key: str) -> str:
    """
    Sends the git diff to a specific OpenRouter model.
    """
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://gitlab.com/soft-hive-group/guardianagent-autonomous-gitlab-security-orchestrator",
        "X-Title": "GitLab Security Guardian"
    }
    
    system_prompt = (
        "You are a strict Application Security Engineer. Analyze the provided git diff for security vulnerabilities, "
        "logical flaws, injection risks, and bad practices.\n"
        "Respond ONLY with a JSON array containing the list of findings. Do not include any introductory or concluding text, "
        "warnings, or explanations outside the JSON array itself.\n\n"
        "Each item in the JSON array must be an object with the following fields:\n"
        "- \"file\": (string) File path of the finding\n"
        "- \"line\": (string/number) Line number of the finding\n"
        "- \"vulnerability\": (string) Type of vulnerability detected\n"
        "- \"severity\": (string) \"Critical\", \"High\", \"Medium\", or \"Low\"\n"
        "- \"description\": (string) Clear description of the vulnerability and how to fix it\n\n"
        "Example Output:\n"
        "[\n"
        "  {\n"
        "    \"file\": \"app.py\",\n"
        "    \"line\": 4,\n"
        "    \"vulnerability\": \"Hardcoded Secret\",\n"
        "    \"severity\": \"High\",\n"
        "    \"description\": \"Exposed AWS API key detected. Move it to environment variables.\"\n"
        "  }\n"
        "]"
    )
    
    payload = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Please review this git diff:\n\n{diff_content}"}
        ]
    }
    
    logger.info(f"Sending request to model {model_name}...")
    response = requests.post(url, headers=headers, json=payload, timeout=90)
    response.raise_for_status()
    result = response.json()
    choices = result.get("choices", [])
    if not choices:
        raise ValueError(f"No choices returned from OpenRouter for model {model_name}")
    content = choices[0].get("message", {}).get("content", "")
    logger.info(f"Successfully received response from model {model_name}.")
    return content


def extract_json(raw_text: str) -> List[Dict[str, Any]]:
    """
    Cleans model response (specifically handling DeepSeek-R1 <think> blocks)
    and parses the JSON array.
    """
    # Remove DeepSeek think blocks if present
    cleaned = re.sub(r"<think>.*?</think>", "", raw_text, flags=re.DOTALL).strip()
    
    # Try to extract content inside code blocks
    code_block_match = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", cleaned, flags=re.DOTALL)
    if code_block_match:
        json_str = code_block_match.group(1)
    else:
        # Try to find the first [ and last ] to extract the JSON array
        array_match = re.search(r"(\[.*\])", cleaned, flags=re.DOTALL)
        if array_match:
            json_str = array_match.group(1)
        else:
            json_str = cleaned

    try:
        data = json.loads(json_str)
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            return [data]
        return []
    except Exception as e:
        logger.error(f"Failed to parse JSON from text: {str(e)}")
        return []


def synthesize_descriptions_with_llm(grouped_list: List[Dict[str, Any]], api_key: str) -> Dict[str, str]:
    """
    Calls Llama 3.3 to synthesize multiple descriptions for each grouped vulnerability.
    """
    if not grouped_list:
        return {}
        
    logger.info("Calling OpenRouter model to synthesize vulnerability descriptions...")
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://gitlab.com/soft-hive-group/guardianagent-autonomous-gitlab-security-orchestrator",
        "X-Title": "GitLab Security Guardian"
    }
    
    input_data = []
    for g in grouped_list:
        input_data.append({
            "key": f"{g['file']}:{g['line']}",
            "vulnerability": g["vulnerability"],
            "descriptions": list(set([d for d in g["descriptions"] if d]))
        })
        
    system_prompt = (
        "You are an expert technical editor and security writer. "
        "You will receive a JSON list of grouped security findings. Each finding has a key (file:line), a vulnerability type, and a list of descriptions from different scanner models.\n"
        "Your task is to synthesize the descriptions for each finding into a single, clean, concise summary (1-3 sentences) that combines the best points and recommendations.\n"
        "Respond ONLY with a JSON object where the keys are the finding keys (file:line) and the values are the synthesized description strings. Do not include any introductory or concluding text."
    )
    
    payload = {
        "model": "meta-llama/llama-3.3-70b-instruct:free",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(input_data)}
        ]
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=60)
        response.raise_for_status()
        result = response.json()
        content = result.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
        
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


def generate_remediations(consolidated_findings: List[Dict[str, Any]]) -> tuple:
    """
    Loops through findings with Consensus Score >= 30% and calls Llama to secure the code.
    Writes the corrected code blocks directly to local files and verifies their success.
    Returns:
        (remediated_results, modified_files)
    """
    api_key = os.environ.get('OPENROUTER_API_KEY')
    if not api_key:
        logger.error("OPENROUTER_API_KEY is not set in environment. Skipping auto-remediation.")
        return [], []

    remediated_results = []
    modified_files = set()
    
    # Filter findings with score >= 30%
    high_confidence_findings = [g for g in consolidated_findings if g.get("score", 0) >= 30.0]
    
    if not high_confidence_findings:
        logger.info("No high-confidence findings (Consensus Score >= 30%) to auto-remediate.")
        return [], []
        
    logger.info(f"Attempting to auto-remediate {len(high_confidence_findings)} findings...")
    
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

    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://gitlab.com/soft-hive-group/guardianagent-autonomous-gitlab-security-orchestrator",
        "X-Title": "GitLab Security Guardian"
    }

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

            # Extract context window (5 lines before, 5 lines after the target line)
            start_idx = max(0, line_idx - 5)
            end_idx = min(len(lines), line_idx + 6)
            original_block = "\n".join(lines[start_idx:end_idx])

            if not original_block.strip():
                continue

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
            
            payload = {
                "model": "meta-llama/llama-3.3-70b-instruct:free",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content}
                ]
            }
            
            try:
                logger.info(f"Requesting remediation patch for {file_path} at line {line_num}...")
                response = requests.post(url, headers=headers, json=payload, timeout=60)
                response.raise_for_status()
                result = response.json()
                corrected_raw = result.get("choices", [{}])[0].get("message", {}).get("content", "")
                
                # Parse the conflict markers
                pattern = r"<<<<<<< ORIGINAL\n(.*?)\n=======\n(.*?)\n>>>>>>> CORRECTED"
                match = re.search(pattern, corrected_raw, re.DOTALL)
                
                if match:
                    original_code = match.group(1)
                    corrected_code = match.group(2)
                    
                    original_clean = original_code.replace("\r\n", "\n")
                    corrected_clean = corrected_code.replace("\r\n", "\n")
                    
                    # Verify if the original block matches the target file content
                    if original_clean in file_content:
                        # Apply the patch in memory
                        file_content = file_content.replace(original_clean, corrected_clean, 1)
                        file_modified = True
                        status = "✅ Patched & Applied"
                        logger.info(f"Remediation patch validated for {file_path} at line {line_num}.")
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
                    "status": status
                })
                
            except Exception as e:
                logger.error(f"Failed to auto-remediate {file_path} at line {line_num}: {str(e)}")
                remediated_results.append({
                    "file": file_path,
                    "line": line_num,
                    "vulnerability": vuln_type,
                    "status": f"❌ Failed to apply ({str(e)})"
                })

        if file_modified:
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


def analyze_diff_ensemble(changes: List[Dict[str, Any]], api_key: str) -> str:
    """
    Runs concurrent analysis of the diff using all available free OpenRouter models,
    then aggregates findings using a consensus and confidence score calculation,
    and runs the auto-remediation engine for high-confidence issues.
    """
    logger.info("Preparing diff content for OpenRouter analysis...")
    
    diff_content_parts = []
    for change in changes:
        new_path = change.get("new_path")
        diff = change.get("diff", "")
        if diff:
            diff_content_parts.append(f"File: {new_path}\nDiff:\n{diff}\n" + "="*80)
            
    diff_content = "\n".join(diff_content_parts)
    
    if not diff_content.strip():
        logger.info("No code changes detected in the diff.")
        return "✅ **No code changes detected in this Merge Request.**"
        
    models = get_free_models()
    
    findings_by_model = {}
    successful_models_count = 0

    logger.info(f"Spawning concurrent threads with max_workers=5 to query {len(models)} models...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_model = {
            executor.submit(call_openrouter_model, model, diff_content, api_key): model
            for model in models
        }
        
        for future in concurrent.futures.as_completed(future_to_model):
            model = future_to_model[future]
            try:
                raw_response = future.result()
                parsed_findings = extract_json(raw_response)
                if parsed_findings:
                    findings_by_model[model] = parsed_findings
                successful_models_count += 1
            except Exception as exc:
                logger.warning(f"Silently ignoring failure from model {model} (Error: {exc})")

    if successful_models_count == 0:
        return "❌ **All scanner models failed to return results or timed out.**"

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
        unique_models = set(data["models"])
        score_pct = (len(unique_models) / successful_models_count) * 100
        vuln_type = Counter(data["vulnerability_types"]).most_common(1)[0][0]
        
        final_groups.append({
            "file": file_path,
            "line": line_val,
            "score": score_pct,
            "vulnerability": vuln_type,
            "descriptions": data["descriptions"]
        })

    if not final_groups:
        return "✅ **No security vulnerabilities or exposed secrets detected by any active model.**"

    # Sort grouped findings by Consensus Score descending
    final_groups.sort(key=lambda x: x["score"], reverse=True)

    # Synthesize descriptions
    synthesized_map = {}
    try:
        synthesized_map = synthesize_descriptions_with_llm(final_groups, api_key)
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

    # Run Auto-Remediation Engine
    remediated_results = []
    remediated_files = []
    try:
        remediated_results, remediated_files = generate_remediations(final_groups)
    except Exception as e:
        logger.error(f"Auto-remediation engine failed: {str(e)}")

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
    Stages, commits, and pushes the modified files back to the GitLab Merge Request repository.
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
        
        # Push to origin targeting current branch
        logger.info("Pushing changes to remote repository...")
        push_res = subprocess.run(["git", "push", git_remote_url, "HEAD"], capture_output=True, text=True)
        logger.info(f"Git push output:\n{push_res.stdout}\n{push_res.stderr}")
        
    except Exception as e:
        logger.error(f"Git operations failed: {str(e)}")


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


def main():
    parser = argparse.ArgumentParser(description="GitLab Security Guardian OpenRouter Mega-Ensemble Orchestrator")
    parser.add_argument("--project-id", required=True, help="GitLab Project ID or Path (e.g. soft-hive-group/project)")
    parser.add_argument("--mr-iid", required=True, type=int, help="Merge Request Internal ID (IID)")
    parser.add_argument("--gitlab-url", default=os.getenv("GITLAB_API_URL", "https://gitlab.com"), help="GitLab base URL")
    
    args = parser.parse_args()
    
    token = os.environ.get('GITLAB_TOKEN')
    openrouter_key = os.environ.get('OPENROUTER_API_KEY')
    
    if not token:
        logger.error("Environment variable 'GITLAB_TOKEN' is missing.")
        exit(1)
        
    if not openrouter_key:
        logger.error("Environment variable 'OPENROUTER_API_KEY' is missing.")
        exit(1)
        
    try:
        # 1. Fetch changes
        changes = fetch_merge_request_diff(args.project_id, args.mr_iid, args.gitlab_url, token)
        
        # 2. Analyze using OpenRouter Ensemble with Consensus & Auto-Remediation
        # Local file modifications are performed and verified inside this call
        report_markdown, remediated_files, final_groups, remediated_results = analyze_diff_ensemble(changes, openrouter_key)
        
        # Report results back to the web application if GUARDIAN_USER_ID is set
        guardian_user_id = os.environ.get("GUARDIAN_USER_ID")
        if guardian_user_id:
            scans_to_report = []
            for g in final_groups:
                # Find matching remediation status
                status = "✅ No patch needed (Consensus low)"
                for r in remediated_results:
                    if r["file"] == g["file"] and str(r["line"]) == str(g["line"]):
                        status = r["status"]
                        break
                
                scans_to_report.append({
                    "file": g["file"],
                    "line": int(g["line"]) if str(g["line"]).isdigit() else 0,
                    "consensus_score": int(g["score"]),
                    "vulnerability": g["vulnerability"],
                    "description": g["synthesized_description"],
                    "status": status
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
