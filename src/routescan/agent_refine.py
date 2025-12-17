import json
import re
import logging
from pathlib import Path

from src.routescan.ai_models import RouteFlow, SecurityIssue
from src.routescan.claude_client import ClaudeClient

log = logging.getLogger(__name__)


def _parse_json_object(raw: str) -> dict:
    json_match = re.search(r"```json\s*(.*?)```", raw, re.DOTALL)
    if json_match:
        clean_text = json_match.group(1).strip()
    else:
        start = raw.find("{")
        end = raw.rfind("}")
        if start != -1 and end != -1:
            clean_text = raw[start : end + 1]
        else:
            clean_text = raw

    try:
        return json.loads(clean_text)
    except json.JSONDecodeError:
        log.warning("Failed to parse JSON from refinement response")
        return {}


def refine_security_analysis(
    client: ClaudeClient,
    flow: RouteFlow,
    existing_issues: list[SecurityIssue],
    project_root: str,
    iteration: int,
) -> list[SecurityIssue]:
    """
    Refines security analysis by reviewing existing issues and looking for additional ones.
    Returns a combined list of refined/new issues.
    """
    route = flow.route
    file_path = Path(route.file)

    try:
        code = file_path.read_text(encoding="utf-8", errors="ignore")[:50000]
    except OSError:
        log.warning("Could not read file: %s", file_path)
        code = "[File not found or unreadable]"

    prompt = _refinement_prompt(flow, code, existing_issues, iteration)
    raw = client.complete(prompt, max_tokens=2048)
    data = _parse_json_object(raw)

    new_issues = []
    for item in data.get("issues", []):
        new_issues.append(
            SecurityIssue(
                route=route,
                severity=item.get("severity", "info").lower(),
                title=item.get("title", "Potential Security Issue"),
                description=item.get("description", ""),
                payload=item.get("payload", ""),
                poc_info=item.get("poc_info", ""),
            )
        )

    return new_issues


def _refinement_prompt(
    flow: RouteFlow,
    code: str,
    existing_issues: list[SecurityIssue],
    iteration: int,
) -> list[tuple[str, str]]:
    instructions = """
You are a security review refinement agent. You have been given:
1. A route and its data flow analysis
2. Existing security issues found in previous analysis

Your task:
- Review the existing issues and verify they are valid
- Look for ADDITIONAL security issues that may have been missed
- Pay special attention to edge cases, logic flaws, and less obvious vulnerabilities
- Be thorough: prefer false positives over missing real issues

Return ONLY a JSON object with this structure:
{
  "issues": [
    {
      "severity": "critical|high|medium|low",
      "title": "Concise technical title",
      "description": "Detailed explanation",
      "payload": "Example exploit payload/request",
      "poc_info": "Step-by-step PoC instructions"
    }
  ]
}

Include ALL issues you find (both new ones and any refinements to existing ones).
If no additional issues are found, return {"issues": []}.
"""

    existing_issues_json = []
    for issue in existing_issues:
        existing_issues_json.append(
            {
                "severity": issue.severity,
                "title": issue.title,
                "description": issue.description,
            }
        )

    meta = {
        "endpoint": flow.route.endpoint,
        "http_method": flow.endpoint_input.http_method,
        "user_inputs": flow.endpoint_input.parameters,
        "sensitive_sinks": flow.sink_summary,
        "execution_trace": flow.call_stack,
        "iteration": iteration,
        "existing_issues": existing_issues_json,
    }

    content = (
        f"{instructions}\n"
        f"--- METADATA ---\n{json.dumps(meta, indent=2)}\n\n"
        f"--- SOURCE CODE ---\n{code}\n"
    )
    return [("user", content)]

