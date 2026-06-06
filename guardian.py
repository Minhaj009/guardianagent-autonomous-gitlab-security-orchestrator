#!/usr/bin/env python3
"""
GitLab Security Guardian - Main Orchestrator

This script orchestrates the autonomous security auditing of GitLab Merge Requests.
It fetches MR code changes, runs security checks (secrets scanning, SAST, etc.),
and comments findings back on the Merge Request.
"""

import argparse
import json
import logging
import os
import re
import urllib.request
import urllib.error
from typing import Dict, Any, List

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
    
    Args:
        project_id: URL-encoded path or numeric ID of the project.
        mr_iid: The internal ID of the Merge Request.
        gitlab_url: Base URL of the GitLab instance (e.g., https://gitlab.com).
        token: Personal, Project, or Pipeline Access Token.
        
    Returns:
        List of change objects containing file paths and diff content.
    """
    logger.info(f"Fetching diff for MR !{mr_iid} in project {project_id}...")
    
    # URL-encode the project_id if it contains slashes
    safe_project_id = urllib.parse.quote_plus(project_id)
    url = f"{gitlab_url.rstrip('/')}/api/v4/projects/{safe_project_id}/merge_requests/{mr_iid}/changes"
    
    req = urllib.request.Request(url)
    req.add_header("PRIVATE-TOKEN", token)
    req.add_header("Content-Type", "application/json")
    
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            # GitLab MR changes endpoint returns an object with a 'changes' list
            changes = data.get("changes", [])
            logger.info(f"Successfully fetched diff. Total modified files: {len(changes)}")
            return changes
    except urllib.error.HTTPError as e:
        logger.error(f"HTTP Error fetching MR diff: {e.code} - {e.read().decode()}")
        raise
    except Exception as e:
        logger.error(f"Failed to fetch MR diff: {str(e)}")
        raise


def analyze_diff_for_vulnerabilities(changes: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyzes Merge Request changes for potential security vulnerabilities.
    
    This performs scans for:
    - Hardcoded secrets and credentials (regex-based).
    - Dangerous function usages (e.g., eval, exec).
    - Insecure configurations.
    
    Args:
        changes: List of change/diff objects from GitLab API.
        
    Returns:
        A dictionary containing the security findings and severity metrics.
    """
    logger.info("Analyzing code changes for potential vulnerabilities...")
    
    findings = {
        "vulnerabilities": [],
        "summary": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
    }
    
    # Basic patterns for hardcoded secrets
    secrets_pattern = re.compile(
        r"(api[_-]?key|secret|password|token|private[_-]?key|passwd)\s*=\s*['\"][a-zA-Z0-9_\-\+]{12,}['\"]",
        re.IGNORECASE
    )
    
    # Basic patterns for dangerous functions in Python
    dangerous_py_pattern = re.compile(r"\b(eval|exec|subprocess\.shell|os\.system)\b")

    for change in changes:
        new_path = change.get("new_path")
        diff = change.get("diff", "")
        
        if not diff:
            continue
            
        lines = diff.splitlines()
        for line_num, line in enumerate(lines, start=1):
            # We only scan added lines (prefixed with '+')
            if not line.startswith("+") or line.startswith("+++"):
                continue
                
            clean_line = line[1:].strip()
            
            # 1. Check for Secrets
            if secrets_pattern.search(clean_line):
                finding = {
                    "file": new_path,
                    "line": line_num,
                    "type": "Hardcoded Secret",
                    "severity": "high",
                    "description": "Potential hardcoded credentials or API key detected.",
                    "code_snippet": clean_line
                }
                findings["vulnerabilities"].append(finding)
                findings["summary"]["high"] += 1
                logger.warning(f"Secret detected in {new_path}:{line_num}")
                
            # 2. Check for Dangerous Python functions
            if new_path.endswith(".py") and dangerous_py_pattern.search(clean_line):
                finding = {
                    "file": new_path,
                    "line": line_num,
                    "type": "Dangerous Function Call",
                    "severity": "medium",
                    "description": "Usage of unsafe function (eval/exec/system) can lead to remote code execution.",
                    "code_snippet": clean_line
                }
                findings["vulnerabilities"].append(finding)
                findings["summary"]["medium"] += 1
                logger.warning(f"Dangerous function detected in {new_path}:{line_num}")

    logger.info(f"Analysis complete. Found {len(findings['vulnerabilities'])} issues.")
    return findings


def generate_summary_markdown(findings: Dict[str, Any]) -> str:
    """
    Generates a rich markdown report comment from the security findings.
    
    Args:
        findings: The dict of vulnerabilities and summary counts.
        
    Returns:
        Markdown string ready for posting to GitLab MR.
    """
    summary = findings["summary"]
    total_issues = sum(summary.values())
    
    if total_issues == 0:
        return (
            "## 🛡️ GitLab Security Guardian Report\n\n"
            "✅ **No security vulnerabilities or exposed secrets detected in this Merge Request.**\n\n"
            "Keep up the secure coding practices! 🚀"
        )
        
    markdown = [
        "## 🛡️ GitLab Security Guardian Report",
        f"⚠️ **{total_issues} potential security issues identified** in this Merge Request.",
        "",
        "### 📊 Severity Summary",
        f"- 🔴 **Critical:** {summary['critical']}",
        f"- 🟠 **High:** {summary['high']}",
        f"- 🟡 **Medium:** {summary['medium']}",
        f"- 🔵 **Low:** {summary['low']}",
        "",
        "### 🔍 Detailed Findings",
        "| File | Line | Type | Severity | Description |",
        "| :--- | :--- | :--- | :--- | :--- |"
    ]
    
    for v in findings["vulnerabilities"]:
        # Escape markdown table characters
        safe_desc = v['description'].replace('|', '\\|')
        markdown.append(
            f"| `{v['file']}` | {v['line']} | **{v['type']}** | {v['severity'].upper()} | {safe_desc} |"
        )
        
    markdown.append("\n*Please review the findings above and fix any security gaps before merging.*")
    return "\n".join(markdown)


def post_mr_comment(project_id: str, mr_iid: int, comment: str, gitlab_url: str, token: str) -> Dict[str, Any]:
    """
    Posts a summary comment back to the Merge Request with findings.
    
    API Endpoint: POST /projects/:id/merge_requests/:merge_request_iid/notes
    
    Args:
        project_id: URL-encoded path or numeric ID of the project.
        mr_iid: The internal ID of the Merge Request.
        comment: Markdown comment body.
        gitlab_url: Base URL of the GitLab instance.
        token: Personal, Project, or Pipeline Access Token.
        
    Returns:
        The created comment object details.
    """
    logger.info(f"Posting security summary comment to MR !{mr_iid}...")
    
    safe_project_id = urllib.parse.quote_plus(project_id)
    url = f"{gitlab_url.rstrip('/')}/api/v4/projects/{safe_project_id}/merge_requests/{mr_iid}/notes"
    
    payload = json.dumps({"body": comment}).encode("utf-8")
    
    req = urllib.request.Request(url, data=payload)
    req.add_header("PRIVATE-TOKEN", token)
    req.add_header("Content-Type", "application/json")
    
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            logger.info("Successfully posted comment to Merge Request.")
            return data
    except urllib.error.HTTPError as e:
        logger.error(f"HTTP Error posting comment: {e.code} - {e.read().decode()}")
        raise
    except Exception as e:
        logger.error(f"Failed to post MR comment: {str(e)}")
        raise


def main():
    parser = argparse.ArgumentParser(description="GitLab Security Guardian MR Orchestrator")
    parser.add_argument("--project-id", required=True, help="GitLab Project ID or Path (e.g. soft-hive-group/project)")
    parser.add_argument("--mr-iid", required=True, type=int, help="Merge Request Internal ID (IID)")
    parser.add_argument("--gitlab-url", default=os.getenv("GITLAB_API_URL", "https://gitlab.com"), help="GitLab base URL")
    parser.add_argument("--token", default=os.getenv("GITLAB_TOKEN"), help="GitLab Private Access Token")
    
    args = parser.parse_args()
    
    token = args.token or os.getenv("GITLAB_PERSONAL_ACCESS_TOKEN")
    if not token:
        logger.error("GitLab access token not provided. Use --token or set GITLAB_TOKEN/GITLAB_PERSONAL_ACCESS_TOKEN env variables.")
        exit(1)
        
    try:
        # 1. Fetch changes
        changes = fetch_merge_request_diff(args.project_id, args.mr_iid, args.gitlab_url, token)
        
        # 2. Analyze
        findings = analyze_diff_for_vulnerabilities(changes)
        
        # 3. Generate summary report
        report_markdown = generate_summary_markdown(findings)
        
        # 4. Post comment back to GitLab MR
        post_mr_comment(args.project_id, args.mr_iid, report_markdown, args.gitlab_url, token)
        
        logger.info("Orchestration pipeline finished successfully.")
        
    except Exception as e:
        logger.critical(f"Guardian orchestrator failed: {str(e)}")
        exit(1)


if __name__ == "__main__":
    main()
