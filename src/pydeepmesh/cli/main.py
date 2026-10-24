"""PyDeepMesh command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pydeepmesh.advisories.base import AdvisoryQuery
from pydeepmesh.advisories.cache import Cache
from pydeepmesh.advisories.registry import build_provider
from pydeepmesh.api import audit_directory, scan_directory
from pydeepmesh.config import Config
from pydeepmesh.errors import ConfigError, PyDeepMeshError, SecurityError, UsageError
from pydeepmesh.graph.algorithms import find_cycles, find_paths, reverse_dependencies
from pydeepmesh.io import ensure_output_path
from pydeepmesh.models.finding import AnalysisResult, Priority
from pydeepmesh.models.graph import NodeKind
from pydeepmesh.pipeline import ScanResult
from pydeepmesh.report.json_report import ReportOptions, build_report, render_json
from pydeepmesh.report.sarif import build_sarif, render_sarif
from pydeepmesh.report.terminal import render_terminal
from pydeepmesh.report.viewer import build_viewer_document, render_viewer
from pydeepmesh.risk.analysis import concentration
from pydeepmesh.sbom.cyclonedx import build_cyclonedx, render_cyclonedx
from pydeepmesh.sbom.spdx import build_spdx, render_spdx
from pydeepmesh.version import __version__

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INPUT = 3
EXIT_UNAVAILABLE = 4

_FAIL_ORDER = ["never", "info", "low", "medium", "high", "critical"]
_PRIORITY_BY_NAME = {
    "info": Priority.INFO,
    "low": Priority.LOW,
    "medium": Priority.MEDIUM,
    "high": Priority.HIGH,
    "critical": Priority.CRITICAL,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pydeepmesh",
        description="Deterministic dependency-graph and vulnerability intelligence.",
    )
    parser.add_argument("--version", action="version", version=f"pydeepmesh {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan", help="discover, parse, and build the dependency graph"
    )
    _add_scan_args(scan_parser)
    scan_parser.add_argument("--format", choices=["terminal", "json"], default="terminal")
    scan_parser.set_defaults(func=_cmd_scan)

    graph_parser = subparsers.add_parser("graph", help="query the canonical dependency graph")
    _add_scan_args(graph_parser)
    graph_parser.add_argument("--format", choices=["terminal", "json", "html"], default="terminal")
    graph_parser.add_argument("--roots", action="store_true", help="list project roots")
    graph_parser.add_argument(
        "--paths", nargs=2, metavar=("SOURCE", "TARGET"), help="dependency paths"
    )
    graph_parser.add_argument("--reverse", metavar="NODE", help="transitive reverse dependencies")
    graph_parser.add_argument("--cycles", action="store_true", help="detect dependency cycles")
    graph_parser.add_argument(
        "--concentrate", type=int, metavar="N", help="most depended-on packages"
    )
    graph_parser.set_defaults(func=_cmd_graph)

    audit_parser = subparsers.add_parser("audit", help="evaluate vulnerabilities and exposure")
    _add_scan_args(audit_parser)
    _add_advisory_args(audit_parser)
    audit_parser.add_argument("--format", choices=["terminal", "json", "sarif"], default="terminal")
    audit_parser.add_argument("--fail-on", choices=_FAIL_ORDER, default=None)
    audit_parser.add_argument(
        "--require-advisory",
        action="store_true",
        help="exit non-zero (4) if advisory data is unavailable",
    )
    audit_parser.set_defaults(func=_cmd_audit)

    image_parser = subparsers.add_parser(
        "image", help="catalog packages inside a container image via Syft"
    )
    image_parser.add_argument("image", help="container image reference")
    image_parser.add_argument("--syft", default="syft", help="path to the Syft binary")
    image_parser.add_argument("--format", choices=["terminal", "json"], default="terminal")
    image_parser.add_argument("--output", help="write output to a file")
    image_parser.set_defaults(func=_cmd_image)

    sbom_parser = subparsers.add_parser("sbom", help="emit a CycloneDX 1.5 or SPDX 2.3 SBOM")
    _add_scan_args(sbom_parser)
    sbom_parser.add_argument(
        "--format",
        choices=["cyclonedx", "spdx"],
        default="cyclonedx",
        help="SBOM format (default: cyclonedx)",
    )
    sbom_parser.set_defaults(func=_cmd_sbom)

    report_parser = subparsers.add_parser(
        "report", help="combined dependency and vulnerability report"
    )
    _add_scan_args(report_parser)
    _add_advisory_args(report_parser)
    report_parser.add_argument("--format", choices=["terminal", "json", "sarif"], default="json")
    report_parser.add_argument("--fail-on", choices=_FAIL_ORDER, default=None)
    report_parser.add_argument("--require-advisory", action="store_true")
    report_parser.set_defaults(func=_cmd_report)

    advisories_parser = subparsers.add_parser("advisories", help="manage the advisory cache")
    advisory_sub = advisories_parser.add_subparsers(dest="advisory_command", required=True)
    update_parser = advisory_sub.add_parser(
        "update", help="populate the local advisory cache from a live provider"
    )
    update_parser.add_argument("path", nargs="?", default=".")
    _add_scan_args(update_parser, include_path=False)
    update_parser.set_defaults(func=_cmd_advisories_update)
    clear_parser = advisory_sub.add_parser("clear", help="clear the local advisory cache")
    clear_parser.add_argument("--cache-dir", default=None)
    clear_parser.set_defaults(func=_cmd_advisories_clear)

    return parser


def _add_scan_args(parser: argparse.ArgumentParser, *, include_path: bool = True) -> None:
    if include_path:
        parser.add_argument("path", nargs="?", default=".", help="project or directory to scan")
    parser.add_argument("--config", help="path to a PyDeepMesh config file")
    parser.add_argument("--output", help="write output to a file instead of stdout")
    parser.add_argument("--include", action="append", default=[], metavar="GLOB")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB")
    parser.add_argument("--max-file-bytes", type=int, default=None)
    parser.add_argument("--cache-dir", default=None)
    parser.add_argument(
        "--output-root", default=None, help="directory that outputs must stay within"
    )
    parser.add_argument("--timestamp", action="store_true", help="include a generation timestamp")
    parser.add_argument("--color", action="store_true", help="force color output")
    parser.add_argument("--no-color", action="store_true", help="disable color output")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")


def _add_advisory_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--online", action="store_true", help="query live advisory providers")
    group.add_argument("--offline", action="store_true", help="never use the network (default)")
    parser.add_argument("--advisory-dir", help="directory of offline OSV snapshot records")


def _load_config(args: argparse.Namespace) -> Config:
    config_path = Path(args.config) if getattr(args, "config", None) else None
    config = Config.load(config_path)
    if getattr(args, "include", None):
        config.include = tuple(args.include)
    if getattr(args, "exclude", None):
        config.exclude = tuple(args.exclude)
    if getattr(args, "max_file_bytes", None) is not None:
        config.max_file_bytes = args.max_file_bytes
    if getattr(args, "cache_dir", None):
        config.cache_dir = Path(args.cache_dir)
    if getattr(args, "advisory_dir", None):
        config.advisory_dir = Path(args.advisory_dir)
    if getattr(args, "output_root", None):
        config.output_root = Path(args.output_root)
    if getattr(args, "online", False):
        config.online = True
    elif getattr(args, "offline", False):
        config.online = False
    return config


def _use_color(args: argparse.Namespace) -> bool:
    if getattr(args, "no_color", False):
        return False
    if getattr(args, "color", False):
        return True
    return sys.stdout.isatty()


def _emit(text: str, output: str | None, *, output_root: Path) -> None:
    if not output:
        sys.stdout.write(text)
        return
    target = Path(output).expanduser()
    resolved = target if target.is_absolute() else (output_root / target)
    resolved = ensure_output_path(resolved, output_root)
    try:
        resolved.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise SecurityError(f"cannot create output directory for {resolved}: {exc}") from exc
    resolved.write_text(text, encoding="utf-8")


def _report_options(args: argparse.Namespace) -> ReportOptions:
    from datetime import datetime, timezone

    generated_at = None
    if getattr(args, "timestamp", False):
        generated_at = datetime.now(timezone.utc).isoformat()
    return ReportOptions(generated_at=generated_at)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args, parser))
    except UsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except SecurityError as exc:
        print(f"security error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:  # pragma: no cover
        print("interrupted", file=sys.stderr)
        return 130
    except PyDeepMeshError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT


def _scan_or_fail(path: str, config: Config) -> ScanResult:
    root = Path(path)
    if not root.exists():
        raise UsageError(f"path does not exist: {path}")
    return scan_directory(root, config)


def _cmd_scan(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    config = _load_config(args)
    result = _scan_or_fail(args.path, config)
    output_root = (config.output_root if config.output_root else Path.cwd()).resolve()
    if args.format == "json":
        document = build_report(result, options=_report_options(args))
        _emit(render_json(document), args.output, output_root=output_root)
    else:
        text = render_terminal(result, color=_use_color(args))
        _emit(text, args.output, output_root=output_root)
    return EXIT_OK


def _cmd_graph(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    config = _load_config(args)
    result = _scan_or_fail(args.path, config)
    output_root = (config.output_root if config.output_root else Path.cwd()).resolve()
    if args.format == "html":
        _emit(render_viewer(build_viewer_document(result)), args.output, output_root=output_root)
        return EXIT_OK
    payload: dict[str, object] = {}
    graph = result.graph
    if args.roots:
        payload["roots"] = list(graph.roots)
    if args.paths:
        source, target = args.paths
        payload["paths"] = [
            list(path) for path in find_paths(graph, source, target, max_paths=config.max_paths)
        ]
    if args.reverse:
        payload["reverse_dependencies"] = reverse_dependencies(graph, args.reverse)
    if args.cycles:
        payload["cycles"] = find_cycles(graph)
    if args.concentrate is not None:
        payload["concentration"] = [
            {"package": pkg, "dependent_count": count}
            for pkg, count in concentration(graph, top=args.concentrate)
        ]
    if not payload:
        payload = build_report(result, options=_report_options(args))
    if args.format == "json":
        _emit(json.dumps(payload, indent=2) + "\n", args.output, output_root=output_root)
    else:
        _emit(_render_graph_terminal(result, payload), args.output, output_root=output_root)
    return EXIT_OK


def _render_graph_terminal(result: ScanResult, payload: dict[str, object]) -> str:
    lines = [f"Graph nodes: {len(result.graph.nodes)}  edges: {len(result.graph.edges)}"]
    roots = payload.get("roots")
    if isinstance(roots, list):
        lines.append("Roots:")
        lines.extend(f"  {root}" for root in roots)
    paths = payload.get("paths")
    if isinstance(paths, list):
        lines.append("Paths:")
        for path in paths:
            lines.append("  " + " -> ".join(path))
    reverse = payload.get("reverse_dependencies")
    if isinstance(reverse, list):
        lines.append("Reverse dependencies:")
        lines.extend(f"  {dep}" for dep in reverse)
    cycles = payload.get("cycles")
    if isinstance(cycles, list):
        lines.append("Cycles:")
        for cycle in cycles:
            lines.append("  " + " -> ".join(cycle))
    concentration_items = payload.get("concentration")
    if isinstance(concentration_items, list):
        lines.append("Concentration (fan-in):")
        for item in concentration_items:
            lines.append(f"  {item['dependent_count']:>4}  {item['package']}")
    return "\n".join(lines) + "\n"


def _cmd_audit(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    config = _load_config(args)
    result, match_report, analysis = audit_directory(args.path, config)
    output_root = (config.output_root if config.output_root else Path.cwd()).resolve()
    provider = match_report.provider_result

    if args.format == "json":
        document = build_report(result, analysis, match_report, _report_options(args))
        text = render_json(document)
    elif args.format == "sarif":
        text = render_sarif(build_sarif(result, analysis))
    else:
        text = render_terminal(result, analysis, match_report, color=_use_color(args))
    _emit(text, args.output, output_root=output_root)

    if args.require_advisory and provider is not None and not provider.available:
        return EXIT_UNAVAILABLE
    fail_on = args.fail_on if args.fail_on is not None else config.fail_on
    return _fail_code(analysis, fail_on)


def _cmd_image(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    del parser
    from pydeepmesh.integrations import SyftScanner, SyftUnavailable

    try:
        result = SyftScanner(syft_path=args.syft).scan(args.image)
    except SyftUnavailable as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_UNAVAILABLE
    except (RuntimeError, ValueError) as exc:
        print(f"image scan failed: {exc}", file=sys.stderr)
        return EXIT_INPUT

    if args.format == "json":
        payload = {
            "image": result.image,
            "components": result.components,
            "graph": {
                "nodes": [node.to_dict() for node in result.graph.nodes.values()],
                "edges": [edge.to_dict() for edge in result.graph.edges],
            },
        }
        text = json.dumps(payload, indent=2)
    else:
        lines = [f"Image: {result.image}", f"Packages: {len(result.components)}", ""]
        for component in result.components:
            version = f"@{component['version']}" if component.get("version") else ""
            lines.append(f"  {component['name']}{version}")
        text = "\n".join(lines)

    if args.output:
        _emit(f"{text}\n", args.output, output_root=Path.cwd().resolve())
    else:
        print(text)
    return EXIT_OK


def _cmd_sbom(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    config = _load_config(args)
    result = _scan_or_fail(args.path, config)
    output_root = (config.output_root if config.output_root else Path.cwd()).resolve()
    timestamp = None
    if getattr(args, "timestamp", False):
        from datetime import datetime, timezone

        timestamp = datetime.now(timezone.utc).isoformat()
    if getattr(args, "format", "cyclonedx") == "spdx":
        document = build_spdx(result, timestamp=timestamp)
        _emit(render_spdx(document), args.output, output_root=output_root)
    else:
        document = build_cyclonedx(result, timestamp=timestamp)
        _emit(render_cyclonedx(document), args.output, output_root=output_root)
    return EXIT_OK


def _cmd_report(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    return _cmd_audit(args, parser)


def _cmd_advisories_update(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    config = _load_config(args)
    if not config.online:
        print(
            "error: 'advisories update' requires --online (or PYDEEPMESH_ONLINE=1)",
            file=sys.stderr,
        )
        return EXIT_USAGE
    result = _scan_or_fail(args.path, config)
    provider = build_provider(config)
    queries = _resolved_queries(result)
    if not queries:
        print("no resolvable packages found to update", file=sys.stderr)
        return EXIT_OK
    provider_result = provider.query(queries)
    if not provider_result.available:
        print(f"error: advisory provider unavailable: {provider_result.error}", file=sys.stderr)
        return EXIT_UNAVAILABLE
    cache = Cache(config.cache_dir, ttl_seconds=config.cache_ttl_seconds)
    unique_advisories = {advisory.id for advisory in provider_result.advisories}
    print(
        f"updated cache: queried {len(queries)} package(s), cached {len(unique_advisories)} advisory record(s)"
    )
    _ = cache
    return EXIT_OK


def _cmd_advisories_clear(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    config = _load_config(args)
    cache = Cache(config.cache_dir, ttl_seconds=config.cache_ttl_seconds)
    removed = cache.clear()
    print(f"cleared {removed} cache file(s) from {config.cache_dir}")
    return EXIT_OK


def _resolved_queries(result: ScanResult) -> list[AdvisoryQuery]:
    queries: list[AdvisoryQuery] = []
    for node in result.graph.iter_nodes_sorted():
        if node.kind is not NodeKind.PACKAGE or node.key is None or not node.version:
            continue
        if node.key.ecosystem.osv_name is None:
            continue
        queries.append(
            AdvisoryQuery(ecosystem=node.key.ecosystem, name=node.key.name, version=node.version)
        )
    return queries


def _fail_code(analysis: AnalysisResult, fail_on: str) -> int:
    if fail_on == "never":
        return EXIT_OK
    threshold = _PRIORITY_BY_NAME.get(fail_on, Priority.CRITICAL)
    for finding in analysis.findings:
        if finding.priority.rank >= threshold.rank:
            return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
