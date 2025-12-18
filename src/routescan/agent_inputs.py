import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

from routescan.ai_models import EndpointInput
from routescan.claude_client import ClaudeClient
from routescan.models import Route

# Configure logging
logger = logging.getLogger(__name__)

def extract_json_clean(text: str) -> dict:
    """
    Robustly extracts JSON from LLM output, handling Markdown code blocks
    and surrounding conversational text.
    """
    # Attempt to find JSON inside markdown code blocks first
    match = re.search(r"```json\s*(.*?)```", text, re.DOTALL)
    if match:
        text = match.group(1)

    # Fallback: Attempt to find the outermost braces
    start = text.find("{")
    end = text.rfind("}")

    if start != -1 and end != -1:
        text = text[start : end + 1]

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        logger.warning(f"Failed to parse JSON from response: {text[:50]}...")
        return {}

def analyze_route_worker(
    client: ClaudeClient,
    route: Route,
    root: Path
) -> Optional[EndpointInput]:
    """
    Worker function for parallel processing of a single route.
    """
    file_path = Path(route.file)
    try:
        # Limit read size to avoid context window issues with massive files
        code = file_path.read_text(encoding="utf-8", errors="ignore")[:50000]
    except OSError:
        logger.warning(f"Could not read source file: {file_path}")
        return None

    prompt = _enhanced_endpoint_prompt(route, code)

    # max_tokens increased slightly to allow for richer source summaries
    raw_response = client.complete(prompt, max_tokens=1024)
    data = extract_json_clean(raw_response)

    if not data:
        return None

    # Fallback to route.method if AI returns null/None
    http_method = data.get("http_method") or "GET"

    # Ensure parameters is a list of strings
    raw_params = data.get("parameters", [])
    clean_params = [str(p) for p in raw_params] if isinstance(raw_params, list) else []

    return EndpointInput(
        route=route,
        http_method=http_method,
        source_summary=data.get("source_summary", "Analysis failed"),
        parameters=clean_params,
    )

def build_endpoint_inputs(
    client: ClaudeClient,
    routes: list[Route],
    project_root: str,
    max_workers: int = 4
) -> list[EndpointInput]:

    root = Path(project_root)
    results: list[EndpointInput] = []

    # Parallelize the I/O-bound LLM calls
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Map futures to their route for debugging if needed
        future_to_route = {
            executor.submit(analyze_route_worker, client, r, root): r
            for r in routes
        }

        for future in as_completed(future_to_route):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                logger.error(f"Unexpected error processing route: {e}")

    return results

def _enhanced_endpoint_prompt(route: Route, code: str):
    instructions = """
You are a Static Application Security Testing (SAST) expert specializing in API surface analysis.
Analyze the provided source code for a specific web route.

### Objectives
1. **Determine HTTP Method**: Infer from decorators (e.g., `@post`, `@route(..., methods=['GET'])`) or function names.
2. **Identify ALL Input Vectors (The "Parameters")**:
   - Explicit function arguments (e.g., `def view(user_id):`).
   - **Implicit Inputs**: Look for direct access to request objects inside the function body.
     - Examples: `request.args.get('token')`, `request.headers['X-API-Key']`, `request.json`, `request.cookies`.
     - Framework specific: `kwargs`, `**params`, or specific dependency injection objects.
3. **Summarize Data Flow**: Briefly explain how data enters the function.

### Output Format
Return valid JSON only. No markdown. No conversational filler.
{
  "http_method": "GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS",
  "source_summary": "One sentence describing data ingress (e.g., 'JSON body parsed into User model and query param 'id' used for lookup').",
  "parameters": [
    "user_id (path)",
    "search_term (query)",
    "X-Auth-Token (header)",
    "profile_data (body)"
  ]
}

Note: For the 'parameters' list, try to append the location (path, query, body, header) in parentheses if inferable.
"""

    # Context block
    route_meta = f"Route Pattern: {route.endpoint}\nLocation: {route.file}:{route.line}"

    content = (
        f"{instructions}\n"
        f"--- CONTEXT ---\n{route_meta}\n\n"
        f"--- SOURCE CODE ---\n{code}\n"
    )
    return [("user", content)]