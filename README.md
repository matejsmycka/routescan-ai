## routescan

Multi-language route scanner with AI-powered security analysis. Biased toward false positives over false negatives.

### Overview

1. It first tries to identify route definitions in source code using regex patterns.
example:
```python
@routes.get("/api/items/{item_id}")
```
2. First agent analyzes and identifies user-controlled parameters.
```python
def get_item(item_id: str):
    item = get_item_from_db(item_id)
    return {"item": item}
```
3. Second agent tries to trace parameter flows into sensitive sinks and builds a pseudo data flow graph.
```python
id -> db.query("SELECT * FROM items WHERE id = ?", id) -> {"item": item}
```
4. Third agent performs security review to identify vulnerabilities and generate PoCs.
```json
...
"title": "SQL Injection",
"description": "The 'item_id' parameter is directly used in a SQL query without sanitization",
"payload": "' OR '1'='1",
"poc_info": {
  "language": "python",
  "code": "db.query(\"SELECT * FROM items WHERE id = ?\", ' OR '1'='1')"
}
...
```
5. Fourth agent refines the results iteratively to catch missed issues.

### Installation

```bash
uv sync
export ANTHROPIC_API_KEY=your_key
```

### Usage

```bash
uv run routescan /path --out-dir /output

```

### Route Patterns

Route patterns: `routescan/rules.yaml`

```yaml
patterns:
  - name: pattern_name
    extensions: [".py"]
    regex: "pattern(?P<path>.*?)"
    endpoint_group: "path"
    flags: ["IGNORECASE"]  # optional
```

### Output

`security_report.json`:
```json
{
  "issues": [{
    "project": "...",
    "file": "...",
    "line": 123,
    "endpoint": "/api/...",
    "severity": "high",
    "title": "...",
    "description": "...",
    "payload": "...",
    "poc_info": "..."
  }]
}
```
