"""Command-line interface for sysguard."""

from __future__ import annotations

import argparse
import json
import sys

from .detectors import ALL_DETECTORS
from .engine import run_scan
from .findings import Severity

_COLORS = {
    "HIGH": "\033[1;31m",    # bold red
    "MEDIUM": "\033[0;33m",  # yellow
    "LOW": "\033[0;36m",     # cyan
    "INFO": "\033[0;37m",    # grey
}
_RESET = "\033[0m"


def _c(text: str, sev: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_COLORS.get(sev, '')}{text}{_RESET}"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sysguard",
        description="Read-only scanner for keyloggers and other local threats.",
    )
    p.add_argument(
        "-d", "--detector", action="append", choices=list(ALL_DETECTORS),
        help="Run only this detector (repeatable). Default: all.",
    )
    p.add_argument(
        "--min-severity", choices=[s.label for s in Severity], default="INFO",
        help="Hide findings below this severity (default: INFO).",
    )
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colours.")
    p.add_argument("--list", action="store_true", help="List available detectors and exit.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list:
        print("Available detectors:")
        for name in ALL_DETECTORS:
            print(f"  {name}")
        return 0

    min_sev = Severity[args.min_severity]
    result = run_scan(args.detector)
    findings = [f for f in result.sorted_findings() if f.severity >= min_sev]

    if args.json:
        data = result.to_dict()
        data["findings"] = [f.to_dict() for f in findings]
        print(json.dumps(data, indent=2))
        return 0 if not _has_actionable(result) else 2

    use_color = sys.stdout.isatty() and not args.no_color

    print("=" * 70)
    print("  sysguard — local threat scan")
    print("=" * 70)
    if not result.ran_as_root:
        print("  NOTE: running without root. Some processes, sockets and files")
        print("        owned by other users are invisible. Re-run with sudo for")
        print("        full coverage.")
    print(f"  Scanned in {result.duration:.2f}s — {len(result.findings)} finding(s)")
    counts = result.counts()
    summary = "  ".join(
        _c(f"{sev}: {counts[sev]}", sev, use_color) for sev in ("HIGH", "MEDIUM", "LOW", "INFO")
    )
    print("  " + summary)
    print("-" * 70)

    if not findings:
        print("  No findings at or above the chosen severity. (Not a clean bill of")
        print("  health — only that these specific checks found nothing.)")
    for f in findings:
        tag = _c(f"[{f.severity.label}]", f.severity.label, use_color)
        print(f"\n{tag} {f.title}  ({f.category})")
        print(f"    {f.detail}")
        if f.remediation:
            print(f"    -> {f.remediation}")

    if result.errors:
        print("\n" + "-" * 70)
        print(f"  {len(result.errors)} detector(s) errored (see --json for tracebacks):")
        for name, _ in result.errors:
            print(f"    - {name}")

    return 2 if _has_actionable(result) else 0


def _has_actionable(result) -> bool:
    return any(f.severity >= Severity.MEDIUM for f in result.findings)


if __name__ == "__main__":
    raise SystemExit(main())
