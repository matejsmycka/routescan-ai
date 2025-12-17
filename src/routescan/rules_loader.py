from pathlib import Path
import re

from src.routescan.models import RoutePattern


def load_patterns_from_yaml(config_path: Path) -> dict[str, list[RoutePattern]]:
    try:
        import yaml  # type: ignore
    except ImportError:
        msg = "PyYAML is required to load route patterns. Install it with 'uv add pyyaml'."
        raise RuntimeError(msg) from None

    if not config_path.is_file():
        msg = f"Rules YAML not found: {config_path}"
        raise FileNotFoundError(msg)

    with config_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    patterns_by_ext: dict[str, list[RoutePattern]] = {}

    for entry in data.get("patterns", []):
        regex_source = entry.get("regex")
        extensions = entry.get("extensions") or []
        endpoint_group = entry.get("endpoint_group")
        flags_list = entry.get("flags") or []

        flags_value = 0
        for flag_name in flags_list:
            flag = getattr(re, flag_name, None)
            if isinstance(flag, int):
                flags_value |= flag

        if not regex_source or not extensions:
            continue

        compiled = re.compile(regex_source, flags_value)
        route_pattern = RoutePattern(regex=compiled, endpoint_group=endpoint_group)

        for ext in extensions:
            ext = ext.lower()
            patterns_by_ext.setdefault(ext, []).append(route_pattern)

    return patterns_by_ext


