import json
import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Any, Dict

from src.routescan.ai_models import RouteFlow, SecurityIssue
from src.routescan.claude_client import ClaudeClient

# Configure logging
logger = logging.getLogger(__name__)

def extract_json_from_response(response_text: str) -> Dict[str, Any]:
    """
    Robustly extracts JSON from an LLM response, handling Markdown blocks
    and potential trailing characters.
    """
    # 1. Try to find a JSON block within Markdown
    json_match = re.search(r"```json\s*(.*?)```", response_text, re.DOTALL)
    if json_match:
        clean_text = json_match.group(1).strip()
    else:
        # 2. If no block, try to find the first '{' and last '}'
        start = response_text.find("{")
        end = response_text.rfind("}")
        if start != -1 and end != -1:
            clean_text = response_text[start : end + 1]
        else:
            clean_text = response_text

    try:
        return json.loads(clean_text)
    except json.JSONDecodeError:
        logger.warning(f"Failed to parse JSON from AI response. Raw: {response_text[:100]}...")
        return {}

def analyze_single_flow(
    client: ClaudeClient,
    flow: RouteFlow,
    project_root: Path
) -> List[SecurityIssue]:
    """
    Helper function to process a single flow, used for parallel execution.
    """
    route = flow.route
    file_path = Path(route.file)
    
    # Read code safely
    try:
        # Limit file size read to ~50KB to prevent context window overflow
        # You can adjust this limit based on your specific Claude model context size
        code = file_path.read_text(encoding="utf-8", errors="ignore")[:50000] 
    except OSError:
        logger.warning(f"Could not read file: {file_path}")
        code = "[File not found or unreadable]"

    prompt = _enhanced_security_prompt(flow, code)
    
    # Increased max_tokens to allow for detailed analysis in the JSON
    raw_response = client.complete(prompt, max_tokens=2048)
    data = extract_json_from_response(raw_response)

    issues = []
    for item in data.get("issues", []):
        issues.append(
            SecurityIssue(
                route=route,
                severity=item.get("severity", "info").lower(),
                title=item.get("title", "Potential Security Issue"),
                description=item.get("description", ""),
                payload=item.get("payload", ""),
                poc_info=item.get("poc_info", ""),
            )
        )
    return issues

def review_security(
    client: ClaudeClient,
    flows: list[RouteFlow],
    project_root: str,
    max_workers: int = 4
) -> list[SecurityIssue]:
    root = Path(project_root)
    all_issues: list[SecurityIssue] = []

    # Use ThreadPoolExecutor to parallelize LLM calls
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_flow = {
            executor.submit(analyze_single_flow, client, flow, root): flow 
            for flow in flows
        }

        for future in as_completed(future_to_flow):
            try:
                issues = future.result()
                all_issues.extend(issues)
            except Exception as e:
                logger.error(f"Error analyzing flow: {e}")

    return all_issues

def _enhanced_security_prompt(flow: RouteFlow, code: str):
    meta = {
        "endpoint": flow.route.endpoint,
        "http_method": flow.endpoint_input.http_method,
        "user_inputs": flow.endpoint_input.parameters,
        "taint_sources": flow.endpoint_input.source_summary,
        "sensitive_sinks": flow.sink_summary,
        "execution_trace": flow.call_stack,
    }

    instructions = """
You are an expert Senior Application Security Engineer conducting a deep-dive security audit.
Your goal is to identify vulnerabilities in the provided code snippet and data flow metadata.

### Analysis Methodology
1. **Taint Analysis**: Trace the `user_inputs` through the `execution_trace` and code. Assume all user input is malicious.
2. **Sink verification**: Check if user data reaches `sensitive_sinks` (DB, OS, filesystem, logs) without validation/sanitization.
3. **Logic Flaws**: Look beyond syntax errors for broken business logic.

### Vulnerability Targets
You must check for the following categories, ranging from common to obscure:

**1. Critical & Common:**
* **Injection**: SQLi, NoSQLi, Command Injection (OS), LDAP Injection.
* **Web Standard**: XSS (Reflected/Stored), CSRF, SSRF.
* **Auth**: Broken Object Level Authorization (BOLA/IDOR), Broken Authentication.

**2. Advanced & Obscure (Pay close attention):**
* **Prototype Pollution**: (If JS/Python) Look for unsafe recursive merges or object attribute modifications.
* **ReDoS**: Regular Expression Denial of Service in validation logic.
* **Race Conditions**: Time-of-check Time-of-use (TOCTOU) in file handling or database transactions.
* **Mass Assignment**: Auto-binding user input into internal objects/models without filtering.
* **Insecure Deserialization**: Pickle, YAML, or object serialization attacks.
* **Timing Attacks**: Insecure comparison of secrets/hashes.
* **HTTP Parameter Pollution**: Handling of duplicate parameters in a way that bypasses WAFs or logic.
* **Type Juggling**: Loose comparisons (== vs ===) leading to logic bypass.

### Output Format
Return ONLY a valid JSON object. Do not add markdown formatting or conversational text.
{
  "issues": [
    {
      "severity": "critical|high|medium|low",
      "title": "Concise technical title (e.g., 'Possible ReDoS in Email Validation')",
      "description": "Detailed explanation of the chain of attack. Mention the specific variable or line number.",
      "payload": "Concrete example HTTP request or payload fragment that could exploit the issue.",
      "poc_info": "Step-by-step text PoC describing how to exploit this issue in practice (endpoint, method, parameters)."
    }
  ]
}
If no issues are found, return {\"issues\": []}.
"""

    # We format the prompt to separate context clearly
    content = (
        f"{instructions}\n"
        f"--- METADATA ---\n{json.dumps(meta, indent=2)}\n\n"
        f"--- SOURCE CODE ---\n{code}\n"
    )
    return [("user", content)]