from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path

from . import __version__
from .models import ScanOptions
from .report import render_markdown, write_report_files
from .scanner import AuthorizationRequired, scan_target
from .target import TargetError


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "scan":
            return _scan(args)
        if args.command == "serve":
            return _serve(args)
        if args.command == "doctor":
            return _doctor()
        parser.print_help()
        return 1
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="orbit",
        description="ORBIT authorized reconnaissance and breach-impact reporting.",
    )
    parser.add_argument("--version", action="version", version=f"ORBIT {__version__}")
    subcommands = parser.add_subparsers(dest="command")

    scan = subcommands.add_parser("scan", help="Run an authorized exposure assessment.")
    scan.add_argument("target", help="Target URL, hostname, or IP address.")
    scan.add_argument("--authorized", action="store_true", help="Confirm you are authorized to assess this target.")
    scan.add_argument("--depth", choices=["standard", "aggressive"], default="standard", help="Scan depth. Aggressive checks a few additional service ports.")
    scan.add_argument("--timeout", type=float, default=4.0, help="Network timeout in seconds.")
    scan.add_argument("--out", type=Path, default=Path("reports"), help="Directory for JSON and Markdown reports.")
    scan.add_argument("--json", action="store_true", help="Print the full JSON report to stdout.")
    scan.add_argument("--markdown", action="store_true", help="Print the Markdown report to stdout.")
    scan.add_argument("--ai", action="store_true", help="Request AI breach-impact analysis from the configured ORBIT AI gateway.")
    scan.add_argument("--ai-gateway-url", default=None, help="Override ORBIT_AI_GATEWAY_URL for this scan.")
    scan.add_argument("--api-token", default=None, help="ORBIT gateway token. Defaults to ORBIT_API_TOKEN.")

    serve = subcommands.add_parser("serve", help="Start the local dashboard.")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)

    subcommands.add_parser("doctor", help="Check optional dependencies and relevant environment.")
    return parser


def _scan(args: argparse.Namespace) -> int:
    try:
        report = scan_target(
            args.target,
            ScanOptions(
                authorized=args.authorized,
                depth=args.depth,
                timeout=args.timeout,
                include_ai=args.ai,
                ai_gateway_url=args.ai_gateway_url,
                api_token=args.api_token,
            ),
        )
    except AuthorizationRequired as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except TargetError as exc:
        print(f"Invalid target: {exc}", file=sys.stderr)
        return 2

    json_path, md_path = write_report_files(report, args.out)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    elif args.markdown:
        print(render_markdown(report))
    else:
        print(f"Target: {report.target.origin}")
        print(f"Risk score: {report.risk_score}/100")
        print(report.summary)
        if report.ai_summary:
            print("\nAI breach-impact summary:")
            print(report.ai_summary)
        print(f"\nWrote JSON: {json_path}")
        print(f"Wrote Markdown: {md_path}")
    return 0


def _serve(args: argparse.Namespace) -> int:
    from .server import run

    print(f"Starting ORBIT dashboard at http://{args.host}:{args.port}")
    run(args.host, args.port)
    return 0


def _doctor() -> int:
    checks = {
        "fastapi": importlib.util.find_spec("fastapi") is not None,
        "uvicorn": importlib.util.find_spec("uvicorn") is not None,
    }
    print(f"ORBIT {__version__}")
    for name, available in checks.items():
        print(f"{name}: {'ok' if available else 'missing'}")
    print(f"ORBIT_AI_GATEWAY_URL: {os.getenv('ORBIT_AI_GATEWAY_URL', 'not set')}")
    print(f"ORBIT_API_TOKEN: {'set' if os.getenv('ORBIT_API_TOKEN') else 'not set'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
