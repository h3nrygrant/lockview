"""
LockView Backend — CLI entry point
Called by the VS Code extension via: python3 -m lockview.main <command> <file> [options]

Commands:
  analyze <file> [--sensitivity low|medium|high]
      Full analysis: parse + coverage + lint. Returns JSON.

  coverage <file>
      Coverage report only.

  lint <file> [--sensitivity low|medium|high]
      Lint report only.
"""

import sys
import json
import argparse
from pathlib import Path
from dataclasses import asdict

from .parser import parse
from .coverage import compute_coverage
from .linter import lint
from .corruptibility import compute_corruptibility
from .simulator import measure_corruptibility


def _read(filepath: str) -> tuple[str, str]:
    p = Path(filepath)
    return p.read_text(encoding="utf-8"), p.name


def cmd_measure(args: argparse.Namespace) -> dict:
    orig_content, orig_name = _read(args.original)
    locked_content, locked_name = _read(args.locked)
    original = parse(orig_content, orig_name)
    locked = parse(locked_content, locked_name)

    # Parse key string "0,1,1,0" → {keyinput0: 0, keyinput1: 1, ...}
    key_bits = [int(b.strip()) for b in args.key.split(",")]
    if len(key_bits) != len(locked.key_inputs):
        return {
            "ok": False,
            "error": (
                f"Key length mismatch: provided {len(key_bits)} bits "
                f"but netlist has {len(locked.key_inputs)} key inputs "
                f"({', '.join(locked.key_inputs)})"
            )
        }
    correct_key = {locked.key_inputs[i]: key_bits[i] for i in range(len(key_bits))}

    report = measure_corruptibility(
        original, locked, correct_key,
        n_input_samples=args.samples,
        n_wrong_key_samples=args.wrong_keys,
        seed=args.seed,
    )
    return {"ok": True, "measure": asdict(report)}


def cmd_analyze(args: argparse.Namespace) -> dict:
    content, filename = _read(args.file)
    netlist = parse(content, filename)
    coverage = compute_coverage(netlist)
    lint_report = lint(netlist, sensitivity=args.sensitivity)
    corruptibility = compute_corruptibility(netlist)

    return {
        "ok": True,
        "file": filename,
        "format": netlist.format,
        "module": netlist.module_name,
        "parse_errors": netlist.errors,
        "coverage": asdict(coverage),
        "corruptibility": asdict(corruptibility),
        "lint": {
            "summary": lint_report.summary,
            "diagnostics": [asdict(d) for d in lint_report.diagnostics],
        },
    }


def cmd_coverage(args: argparse.Namespace) -> dict:
    content, filename = _read(args.file)
    netlist = parse(content, filename)
    coverage = compute_coverage(netlist)
    return {"ok": True, "file": filename, "coverage": asdict(coverage)}


def cmd_lint(args: argparse.Namespace) -> dict:
    content, filename = _read(args.file)
    netlist = parse(content, filename)
    lr = lint(netlist, sensitivity=getattr(args, "sensitivity", "medium"))
    return {
        "ok": True,
        "file": filename,
        "summary": lr.summary,
        "diagnostics": [asdict(d) for d in lr.diagnostics],
    }


def main():
    parser = argparse.ArgumentParser(prog="lockview", description="LockView backend analysis")
    sub = parser.add_subparsers(dest="command", required=True)

    p_analyze = sub.add_parser("analyze")
    p_analyze.add_argument("file")
    p_analyze.add_argument("--sensitivity", choices=["low", "medium", "high"], default="medium")

    p_cov = sub.add_parser("coverage")
    p_cov.add_argument("file")

    p_lint = sub.add_parser("lint")
    p_lint.add_argument("file")
    p_lint.add_argument("--sensitivity", choices=["low", "medium", "high"], default="medium")

    p_measure = sub.add_parser("measure")
    p_measure.add_argument("original", help="Original unlocked bench file")
    p_measure.add_argument("locked", help="Locked bench file")
    p_measure.add_argument(
        "--key", required=True,
        help='Correct key as comma-separated bit values e.g. "0,1,1,0" in order of keyinput0,keyinput1,...'
    )
    p_measure.add_argument("--samples", type=int, default=10000, help="Number of input patterns (default 10000)")
    p_measure.add_argument("--wrong-keys", type=int, default=50, help="Wrong keys per input pattern (default 50)")
    p_measure.add_argument("--seed", type=int, default=42)

    args = parser.parse_args()

    try:
        if args.command == "analyze":
            result = cmd_analyze(args)
        elif args.command == "coverage":
            result = cmd_coverage(args)
        elif args.command == "lint":
            result = cmd_lint(args)
        elif args.command == "measure":
            result = cmd_measure(args)
        else:
            result = {"ok": False, "error": f"Unknown command: {args.command}"}
    except FileNotFoundError as e:
        result = {"ok": False, "error": str(e)}
    except Exception as e:
        result = {"ok": False, "error": f"Internal error: {e}"}

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
