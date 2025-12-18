import json
from pathlib import Path

from routescan.ai_models import EndpointInput, RouteFlow
from routescan.claude_client import ClaudeClient


def build_route_flows(
    client: ClaudeClient,
    inputs: list[EndpointInput],
    project_root: str,
) -> list[RouteFlow]:
    root = Path(project_root)
    results: list[RouteFlow] = []

    for endpoint_input in inputs:
        route = endpoint_input.route
        file_path = Path(route.file)
        try:
            code = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            code = ""

        prompt = _flow_prompt(endpoint_input, code, root)
        raw = client.complete(prompt, max_tokens=1200)

        data = _parse_json_object(raw)

        sink_summary = data.get("sink_summary", "")
        call_stack = data.get("call_stack", "")

        results.append(
            RouteFlow(
                route=route,
                endpoint_input=endpoint_input,
                sink_summary=sink_summary,
                call_stack=call_stack,
            )
        )

    return results


def _parse_json_object(raw: str) -> dict:
    raw = raw.strip()
    if not raw:
        return {}

    if raw.startswith("```"):
        lines = raw.splitlines()
        raw = "\n".join(lines[1:-1]).strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end != -1 and end > start:
        snippet = raw[start : end + 1]
        try:
            return json.loads(snippet)
        except json.JSONDecodeError:
            pass

    return {}


def _flow_prompt(endpoint_input: EndpointInput, code: str, project_root: Path):
    instructions = """
You are a static analysis assistant.
Given a route and its inputs, follow the data flow to potential sinks (DB, file IO, subprocess, HTTP calls, templating, eval, etc.).

Return a compact JSON object with these keys only:
  "sink_summary": short text describing where user-controlled data can end up,
  "call_stack": a MULTI-LINE string where each line is a transformation chain for a single user-controlled parameter.

Format of call_stack:
  - Each line starts with "<param_name>: ".
  - After that, show the sequence of important transformations and calls, separated by " -> ".
  - Example line:
      "id: param{id} -> .lower()-> db.query("SELECT * FROM items WHERE id = ?", id) -> save_to_db() -> load_user() -> render(template, id)"

Prefer including possible transformations and sinks even if they might be false-positives.
Respond with JSON only, no extra text.
"""
    meta = {
        "http_method": endpoint_input.http_method,
        "endpoint": endpoint_input.route.endpoint,
        "parameters": endpoint_input.parameters,
        "source_summary": endpoint_input.source_summary,
    }
    content = f"{instructions}\nROUTE_META:\n{json.dumps(meta, indent=2)}\n\nCODE:\n{code}\n"
    return [("user", content)]


