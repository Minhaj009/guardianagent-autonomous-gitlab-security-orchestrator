#!/usr/bin/env python3
"""
GitLab Security Guardian - OpenRouter Mega-Ensemble Orchestrator with Consensus Engine

This script orchestrates the autonomous security auditing of GitLab Merge Requests.
It fetches MR code changes, queries all free OpenRouter models concurrently,
calculates a consensus score for each finding, synthesizes their descriptions,
and comments the consolidated report back on the Merge Request.
"""

import argparse
import concurrent.futures
import json
import logging
import os
import re
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
            
            # Check if model is free (ends with :free, or cost is 0)
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
                    
        # Remove duplicates
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
    Returns a dict mapping 'file:line' to the synthesized description.
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
        
        # Clean and parse JSON
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


def analyze_diff_ensemble(changes: List[Dict[str, Any]], api_key: str) -> str:
    """
    Runs concurrent analysis of the diff using all available free OpenRouter models,
    then aggregates findings using a consensus and confidence score calculation.
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
        
    # Get free models dynamically
    models = get_free_models()
    
    findings_by_model = {}
    successful_models_count = 0

    # ThreadPoolExecutor with max_workers=5 to avoid HTTP 429 Rate Limits
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
                # Silently ignore model execution failures (404, 429, 503)
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
        
        # Consensus Score = (models flagging this line) / (total successful models)
        score_pct = (len(unique_models) / successful_models_count) * 100
        
        # Select the most common vulnerability type reported for this group
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

    # Synthesize descriptions using LLM
    synthesized_map = {}
    try:
        synthesized_map = synthesize_descriptions_with_llm(final_groups, api_key)
    except Exception as e:
        logger.warning(f"Failed to run synthesis: {str(e)}")

    # Format the report table
    markdown = [
        "### 📊 Security Consensus & Confidence Report",
        "| File | Line | Consensus Score | Vulnerability Type | Synthesized Description |",
        "| :--- | :--- | :--- | :--- | :--- |"
    ]
    
    for g in final_groups:
        key = f"{g['file']}:{g['line']}"
        
        # Determine description
        if key in synthesized_map:
            syn_desc = synthesized_map[key]
        else:
            # Fallback: pick the longest unique description
            unique_descs = list(set([d for d in g["descriptions"] if d]))
            syn_desc = max(unique_descs, key=len) if unique_descs else "No description provided."
            
        safe_desc = syn_desc.replace('\n', ' ').replace('|', '\\|')
        markdown.append(
            f"| `{g['file']}` | {g['line']} | **{g['score']:.0f}%** | {g['vulnerability']} | {safe_desc} |"
        )
        
    return "\n".join(markdown)


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
        
        # 2. Analyze using OpenRouter Ensemble with Consensus Engine
        report_markdown = analyze_diff_ensemble(changes, openrouter_key)
        
        # 3. Post comment back to GitLab MR
        full_comment = f"## 🛡️ GitLab Security Guardian Consensus Report\n\n{report_markdown}"
        post_mr_comment(args.project_id, args.mr_iid, full_comment, args.gitlab_url, token)
        
        logger.info("Orchestration pipeline finished successfully.")
        
    except Exception as e:
        logger.critical(f"Guardian orchestrator failed: {str(e)}")
        exit(1)


if __name__ == "__main__":
    main()
