import logging
import os
from collections.abc import Iterable
from pathlib import Path

from routescan.models import Route
from routescan.rules_loader import load_patterns_from_yaml

log = logging.getLogger(__name__)


def scan_directory(directory: str) -> list[Route]:
    routes: list[Route] = []

    rules_path = Path(__file__).with_name("rules.yaml")
    log.info("Loading route patterns from %s", rules_path)
    patterns_by_ext = load_patterns_from_yaml(rules_path)

    log.info("Scanning directory %s", directory)
    for root, _, files in os.walk(directory):
        for file in files:
            _, ext = os.path.splitext(file)
            ext = ext.lower()
            if ext not in patterns_by_ext:
                continue

            file_path = os.path.join(root, file)
            routes.extend(_scan_file(file_path, directory, patterns_by_ext[ext]))

    log.info("Found %d route candidates", len(routes))
    return routes


def _scan_file(path: str, project_root: str, patterns: Iterable) -> list[Route]:
    routes: list[Route] = []
    project_name = os.path.basename(os.path.abspath(project_root))

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f, 1):
                for pattern in patterns:
                    match = pattern.regex.search(line)
                    if not match:
                        continue
                    endpoint = _extract_endpoint(match, pattern.endpoint_group)
                    routes.append(
                        Route(
                            project=project_name,
                            file=path,
                            line=i,
                            endpoint=endpoint or "",
                        )
                    )
    except Exception as exc:
        log.warning("Error reading file %s: %s", path, exc)

    return routes


def _extract_endpoint(match, endpoint_group: str | None) -> str | None:
    if endpoint_group and endpoint_group in match.groupdict():
        return match.group(endpoint_group)

    path = match.groupdict().get("path")
    if path is not None:
        return path

    if match.lastindex:
        return match.group(match.lastindex)

    return None


