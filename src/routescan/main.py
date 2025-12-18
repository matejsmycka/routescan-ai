import argparse
import json
import logging
from pathlib import Path

from routescan.agent_flows import build_route_flows
from routescan.agent_inputs import build_endpoint_inputs
from routescan.agent_refine import refine_security_analysis
from routescan.agent_security import review_security
from routescan.claude_client import ClaudeClient
from routescan.core import scan_directory

log = logging.getLogger(__name__)


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def _issues_to_dicts(issues):
    output = []
    for issue in issues:
        output.append(
            {
                "project": issue.route.project,
                "file": issue.route.file,
                "line": issue.route.line,
                "endpoint": issue.route.endpoint,
                "severity": issue.severity,
                "title": issue.title,
                "description": issue.description,
                "payload": issue.payload,
                "poc_info": issue.poc_info,
            }
        )
    return output


def _write_report_if_needed(out_dir: Path | None, issues) -> None:
    if not out_dir:
        return
    out_dir.mkdir(parents=True, exist_ok=True)
    data = {"issues": _issues_to_dicts(issues)}
    out_path = out_dir / "security_report.json"
    out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    log.info("Wrote security report with %d issues to %s", len(issues), out_path)


def main():
    parser = argparse.ArgumentParser(
        description="AI-assisted security review over discovered routes.",
    )
    parser.add_argument("directory", help="Project directory to scan.")
    parser.add_argument(
        "--model",
        default="claude-haiku-4-5",
        help="Claude model name (default: claude-haiku-4-5).",
    )
    parser.add_argument(
        "--out-dir",
        type=str,
        help="Directory to write security_report.json with all issues.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Automatically answer yes to all prompts.",
    )
    args = parser.parse_args()

    configure_logging(args.verbose)

    project_root = str(Path(args.directory).resolve())

    log.info("Scanning project at %s", project_root)
    routes = scan_directory(project_root)
    if not routes:
        log.info("No routes found.")
        print("No routes found.")
        return

    log.info("Found %d routes, grouping by file", len(routes))
    client = ClaudeClient(model=args.model)

    routes_by_file: dict[str, list] = {}
    for route in routes:
        routes_by_file.setdefault(route.file, []).append(route)

    all_issues = []
    out_dir: Path | None = None
    if args.out_dir:
        out_dir = Path(args.out_dir).expanduser().resolve()

    file_idx = 0
    total_files = len(routes_by_file)
    route_counter = 0

    for file_path, file_routes in routes_by_file.items():
        file_idx += 1
        print()
        print("=" * 80)
        print(f"[File {file_idx}/{total_files}] {file_path}")
        print(f"Routes in this file ({len(file_routes)}):")
        for route in file_routes:
            print(f"  - {route.endpoint} (line {route.line})")
        print("=" * 80)
        if not args.yes:
            answer = input("Analyze routes in this file with AI? [y/N]: ").strip().lower()
            if answer not in ("y", "yes"):
                log.info("Skipping file %s", file_path)
                continue
        else:
            print("Analyzing routes in this file with AI? [y/N]: y")

        log.info("Analyzing file %s with %d routes", file_path, len(file_routes))

        for route in file_routes:
            route_counter += 1
            log.info("Analyzing route %d/%d: %s (%s:%d)", route_counter, len(routes), route.endpoint, route.file, route.line)

            endpoint_inputs = build_endpoint_inputs(client, [route], project_root)
            if not endpoint_inputs:
                log.info("No endpoint input produced for route %s", route.endpoint)
                continue

            flows = build_route_flows(client, endpoint_inputs, project_root)
            if not flows:
                log.info("No flow produced for route %s", route.endpoint)
                continue

            flow = flows[0]

            print()
            print("=" * 80)
            print(f"[Route {route_counter}/{len(routes)}] {route.endpoint}")
            print(f"File: {route.file}:{route.line}")
            print(f"HTTP method: {flow.endpoint_input.http_method}")
            print("Call stack (AI-estimated):")
            print(flow.call_stack or "<no call stack>")
            print("=" * 80)
            if not args.yes:
                answer = input("Run security review for this route? [y/N]: ").strip().lower()
                if answer not in ("y", "yes"):
                    log.info("Skipping security review for route %s", route.endpoint)
                    continue
            else:
                print("Run security review for this route? [y/N]: y")

            log.info("Running security review for route %s", route.endpoint)
            issues = review_security(client, [flow], project_root)
            log.info(
                "Security review produced %d issues for route %s",
                len(issues),
                route.endpoint,
            )

            if issues:
                log.info("Found issues, starting refinement iterations (max 3)")
                current_issues = issues.copy()
                for iteration in range(1, 4):
                    log.info("Refinement iteration %d/3 for route %s", iteration, route.endpoint)
                    new_issues = refine_security_analysis(
                        client, flow, current_issues, project_root, iteration
                    )
                    if not new_issues:
                        log.info("No new issues found in iteration %d, stopping refinement", iteration)
                        break
                    log.info("Refinement iteration %d found %d new issues", iteration, len(new_issues))
                    current_issues.extend(new_issues)
                issues = current_issues
                log.info("Final issue count after refinement: %d", len(issues))

            all_issues.extend(issues)
            _write_report_if_needed(out_dir, all_issues)

    report = {"issues": _issues_to_dicts(all_issues)}
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

