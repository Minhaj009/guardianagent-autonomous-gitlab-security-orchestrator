#!/usr/bin/env python3
"""
GitLab Security Guardian - OpenRouter Ensemble Orchestrator

This script orchestrates the autonomous security auditing of GitLab Merge Requests.
It fetches MR code changes, runs concurrent security analysis using OpenRouter models
(DeepSeek R1 Free and Qwen 2.5 72B Free), aggregates findings, and comments back on the MR.
"""

import argparse
import concurrent.futures
import json
import logging
import os
import re
import urllib.parse
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
        "    \"description\": \"Exposed API key detected. Move it to environment variables.\"\n"
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
        return [{
            "file": "N/A",
            "line": "N/A",
            "vulnerability": "Parsing Error",
            "severity": "Low",
            "description": f"Failed to parse structured output. Raw response: {cleaned[:300]}..."
        }]


def analyze_diff_ensemble(changes: List[Dict[str, Any]], api_key: str) -> str:
    """
    Runs concurrent analysis of the diff using OpenRouter models.
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
        
    models = ["deepseek/deepseek-r1:free", "qwen/qwen-2.5-72b-instruct:free"]
    findings_by_model = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(models)) as executor:
        future_to_model = {
            executor.submit(call_openrouter_model, model, diff_content, api_key): model
            for model in models
        }
        
        for future in concurrent.futures.as_completed(future_to_model):
            model = future_to_model[future]
            try:
                raw_response = future.result()
                parsed_findings = extract_json(raw_response)
                findings_by_model[model] = parsed_findings
            except Exception as exc:
                logger.error(f"Model {model} generated an exception: {exc}")
                findings_by_model[model] = [{
                    "file": "N/A",
                    "line": "N/A",
                    "vulnerability": "Model Failure",
                    "severity": "High",
                    "description": f"Model {model} failed to execute. Error: {str(exc)}"
                }]

    # Aggregate findings
    aggregated_findings = []
    for model, findings in findings_by_model.items():
        short_model_name = model.split("/")[-1]
        for finding in findings:
            aggregated_findings.append({
                "model": short_model_name,
                "file": finding.get("file", "N/A"),
                "line": finding.get("line", "N/A"),
                "vulnerability": finding.get("vulnerability", "N/A"),
                "severity": finding.get("severity", "N/A"),
                "description": finding.get("description", "N/A")
            })

    if not aggregated_findings:
        return "✅ **No security vulnerabilities or exposed secrets detected by any model.**"
        
    # Generate Markdown Table
    markdown = [
        "### 📊 Security Findings Summary",
        "| Model | File | Line | Vulnerability Type | Severity | Description / Recommendation |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |"
    ]
    for f in aggregated_findings:
        # Strip newlines or escape markdown characters in the description
        safe_desc = str(f['description']).replace('\n', ' ').replace('|', '\\|')
        markdown.append(
            f"| `{f['model']}` | `{f['file']}` | {f['line']} | **{f['vulnerability']}** | {str(f['severity']).upper()} | {safe_desc} |"
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
    parser = argparse.ArgumentParser(description="GitLab Security Guardian OpenRouter Ensemble Orchestrator")
    parser.add_argument("--project-id", required=True, help="GitLab Project ID or Path (e.g. soft-hive-group/project)")
    parser.add_argument("--mr-iid", required=True, type=int, help="Merge Request Internal ID (IID)")
    parser.add_argument("--gitlab-url", default=os.getenv("GITLAB_API_URL", "https://gitlab.com"), help="GitLab base URL")
    parser.add_argument("--token", default=os.getenv("GITLAB_TOKEN"), help="GitLab Private Access Token")
    parser.add_argument("--openrouter-key", default=os.getenv("OPENROUTER_API_KEY"), help="OpenRouter API Key")
    
    args = parser.parse_args()
    
    token = args.token or os.getenv("GITLAB_PERSONAL_ACCESS_TOKEN")
    if not token:
        logger.error("GitLab access token not provided. Use --token or set GITLAB_TOKEN/GITLAB_PERSONAL_ACCESS_TOKEN env variables.")
        exit(1)
        
    openrouter_key = args.openrouter_key
    if not openrouter_key:
        logger.error("OpenRouter API Key not provided. Use --openrouter-key or set OPENROUTER_API_KEY env variable.")
        exit(1)
        
    try:
        # 1. Fetch changes
        changes = fetch_merge_request_diff(args.project_id, args.mr_iid, args.gitlab_url, token)
        
        # 2. Analyze using OpenRouter Ensemble
        report_markdown = analyze_diff_ensemble(changes, openrouter_key)
        
        # 3. Post comment back to GitLab MR
        full_comment = f"## 🛡️ GitLab Security Guardian Ensemble Report\n\n{report_markdown}"
        post_mr_comment(args.project_id, args.mr_iid, full_comment, args.gitlab_url, token)
        
        logger.info("Orchestration pipeline finished successfully.")
        
    except Exception as e:
        logger.critical(f"Guardian orchestrator failed: {str(e)}")
        exit(1)


if __name__ == "__main__":
    main()
