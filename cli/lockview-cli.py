#!/usr/bin/env python3
"""
lockview-cli — Standalone CLI for LockView analysis
Usage:
  lockview-cli analyze <file> [--sensitivity low|medium|high] [--format json|text]
  lockview-cli coverage <file>
  lockview-cli lint <file> [--sensitivity low|medium|high]

Exit codes:
  0 — no errors found
  1 — errors found (use in CI to fail the build)
  2 — tool/parse failure
"""

import sys
import json
import argparse
from pathlib import Path
from dataclasses import asdict
import time

# Allow running from repo root without installing
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from lockview.parser import parse
from lockview.coverage import compute_coverage
from lockview.linter import lint, Severity
from lockview.corruptibility import compute_corruptibility


SEVERITY_SYMBOLS = {
    Severity.ERROR: "✗",
    Severity.WARNING: "⚠",
    Severity.INFO: "ℹ",
}

SEVERITY_COLORS = {
    Severity.ERROR: "\033[91m",
    Severity.WARNING: "\033[93m",
    Severity.INFO: "\033[94m",
}
RESET = "\033[0m"


def bar(pct: float, width: int = 20) -> str:
    filled = round(pct / 100 * width)
    return "█" * filled + "░" * (width - filled)


def print_coverage(cov, use_color: bool = True):
    c = "\033[96m" if use_color else ""
    g = "\033[92m" if use_color else ""
    y = "\033[93m" if use_color else ""
    r = "\033[91m" if use_color else ""
    b = "\033[1m" if use_color else ""
    re = RESET if use_color else ""

    pct = cov.coverage_pct
    col = g if pct >= 60 else y if pct >= 30 else r

    print(f"\n{b}━━━ LockView Coverage Report ━━━{re}")
    print(f"  Module       : {c}{cov.module_name}{re}")
    print(f"  Coverage     : {col}{pct}%  {bar(pct)}{re}")
    print(f"  Locked Gates : {cov.locked_gates} / {cov.total_gates}")
    print(f"  Key Bits     : {cov.key_bits}  {', '.join(cov.key_inputs[:8])}{'…' if len(cov.key_inputs) > 8 else ''}")
    print(f"  Avg Key Fanin: {cov.avg_key_fanin}")
    print(f"  Output Cone  : {cov.output_cone_coverage}%")

    if cov.per_output_coverage:
        print(f"\n  {b}Per-Output Coverage:{re}")
        for out, p in cov.per_output_coverage.items():
            col2 = g if p >= 60 else y if p >= 30 else r
            print(f"    {out:20s}  {col2}{p:5.1f}%  {bar(p, 10)}{re}")

    if cov.warnings:
        print(f"\n  {y}Coverage Warnings:{re}")
        for w in cov.warnings:
            print(f"    ⚠  {w}")


def print_lint(lint_report, filename: str, use_color: bool = True):
    b = "\033[1m" if use_color else ""
    re = RESET if use_color else ""

    s = lint_report.summary
    total = sum(s.values())
    print(f"\n{b}━━━ LockView Lint — {filename} ━━━{re}")
    print(f"  {s.get('error',0)} error(s)  {s.get('warning',0)} warning(s)  {s.get('info',0)} info(s)\n")

    for d in lint_report.diagnostics:
        col = SEVERITY_COLORS.get(d.severity, "") if use_color else ""
        sym = SEVERITY_SYMBOLS.get(d.severity, "?")
        loc = f"line {d.line_number}" if d.line_number > 0 else "file"
        print(f"  {col}{sym} [{d.rule_id}] {d.gate_name} ({loc}){re}")
        print(f"    {d.message}")
        if d.detail:
            # Word-wrap detail to 72 chars
            words = d.detail.split()
            line_, lines_ = "", []
            for w in words:
                if len(line_) + len(w) + 1 > 72:
                    lines_.append(line_)
                    line_ = w
                else:
                    line_ = (line_ + " " + w).strip()
            if line_:
                lines_.append(line_)
            for l in lines_:
                print(f"    \033[2m{l}{re}")
        print()


def print_real_corruptibility(report, use_color: bool = True):
    g = "\033[92m" if use_color else ""
    y = "\033[93m" if use_color else ""
    r = "\033[91m" if use_color else ""
    b = "\033[1m" if use_color else ""
    d = "\033[2m" if use_color else ""
    c = "\033[96m" if use_color else ""
    re = RESET if use_color else ""

    risk_color = {"balanced": g, "medium": y, "high": r}.get(report.risk_level, y)
    pct = report.corruptibility_pct
    ecr_color = g if pct >= 40 else y if pct >= 20 else r

    print(f"\n{b}━━━ LockView Real Corruptibility Measurement ━━━{re}")
    print(f"  Method         : {c}Monte Carlo simulation{re} {d}(not an estimate){re}")
    print(f"  Evaluations    : {report.total_evaluations:,}  "
          f"{d}({report.n_input_samples:,} inputs × {report.n_wrong_key_samples} wrong keys){re}")
    print(f"  Key Bits       : {report.key_bits}")
    print(f"  Corruptibility : {ecr_color}{pct}%  {bar(pct)}{re}  {d}(target: ~50%){re}")
    print(f"  Output Cov.    : {report.output_corruption_coverage}%  "
          f"{d}(outputs corrupted at least once){re}")
    print(f"  Risk Level     : {risk_color}{report.risk_level.upper()}{re}")

    print(f"\n  {b}Per-Output Corruption:{re}")
    for net, prob in report.per_output_corruption.items():
        col = g if prob >= 0.4 else y if prob >= 0.2 else r
        print(f"    {net:20s}  {col}{prob*100:5.1f}%{re}  {bar(prob*100, 10)}")

    if report.risk_flags:
        print(f"\n  {b}Risk Flags:{re}")
        for flag in report.risk_flags:
            col = r if "AppSAT" in flag or "Very low" in flag else y
            words = flag.split()
            line_, lines_ = "", []
            for w in words:
                if len(line_) + len(w) + 1 > 70:
                    lines_.append(line_)
                    line_ = w
                else:
                    line_ = (line_ + " " + w).strip()
            if line_:
                lines_.append(line_)
            print(f"    {col}⚑{re}  {lines_[0]}")
            for l in lines_[1:]:
                print(f"       {d}{l}{re}")


def print_corruptibility(cr, use_color: bool = True):
    g = "\033[92m" if use_color else ""
    y = "\033[93m" if use_color else ""
    r = "\033[91m" if use_color else ""
    b = "\033[1m" if use_color else ""
    d = "\033[2m" if use_color else ""
    re = RESET if use_color else ""

    risk_color = {"balanced": g, "medium": y, "high": r, "low": r}.get(cr.risk_level, y)
    ecr_color = g if cr.estimated_corruption_pct >= 40 else y if cr.estimated_corruption_pct >= 20 else r

    print(f"\n{b}━━━ LockView Corruptibility Report ━━━{re}")
    print(f"  Output Corruption Coverage : {cr.output_corruption_coverage}%  "
          f"({cr.outputs_with_locked_cone}/{cr.total_outputs} outputs have locked cones)")
    print(f"  Estimated Corruption Rate  : {ecr_color}{cr.estimated_corruption_pct}%{re}  "
          f"{bar(cr.estimated_corruption_pct)}  {d}(target: ~50%){re}")
    print(f"  Risk Level                 : {risk_color}{cr.risk_level.upper()}{re}")

    print(f"\n  {b}Per-Output Corruptibility:{re}")
    for o in cr.per_output:
        col = g if o.estimated_corruption_prob >= 0.4 else y if o.estimated_corruption_prob >= 0.2 else r
        locked_info = f"{o.locked_gates_in_cone} locked gates" if o.has_locked_cone else "NO locked gates"
        types = ', '.join(o.dominant_gate_types) if o.dominant_gate_types else "—"
        print(f"    {o.output_net:20s}  {col}{o.estimated_corruption_prob*100:5.1f}%{re}  "
              f"{bar(o.estimated_corruption_prob*100, 10)}  {d}{locked_info} · depth {o.locked_gate_depth_avg} · {types}{re}")

    if cr.risk_flags:
        print(f"\n  {b}Risk Flags:{re}")
        for flag in cr.risk_flags:
            col = r if "AppSAT" in flag or "very low" in flag.lower() or "No locked" in flag else y
            words = flag.split()
            line_, lines_ = "", []
            for w in words:
                if len(line_) + len(w) + 1 > 70:
                    lines_.append(line_)
                    line_ = w
                else:
                    line_ = (line_ + " " + w).strip()
            if line_:
                lines_.append(line_)
            print(f"    {col}⚑{re}  {lines_[0]}")
            for l in lines_[1:]:
                print(f"       {d}{l}{re}")

    print(f"\n  {d}Note: ECR is a structural estimate — not a simulation result.{re}")
    print(f"  {d}For formal SAT resistance evaluation use a SAT-based tool (CycSAT, DLSim).{re}")


def main():
    parser = argparse.ArgumentParser(
        prog="lockview-cli",
        description="LockView — Logic locking analysis CLI"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_file_arg(p):
        p.add_argument("file", help="Path to .v, .sv, or .bench netlist")

    p_analyze = sub.add_parser("analyze", help="Full analysis (parse + coverage + lint)")
    add_file_arg(p_analyze)
    p_analyze.add_argument("--sensitivity", choices=["low", "medium", "high"], default="medium")
    p_analyze.add_argument("--format", choices=["text", "json"], default="text")
    p_analyze.add_argument("--no-color", action="store_true")

    p_cov = sub.add_parser("coverage", help="Coverage report only")
    add_file_arg(p_cov)
    p_cov.add_argument("--format", choices=["text", "json"], default="text")
    p_cov.add_argument("--no-color", action="store_true")

    p_measure = sub.add_parser("measure", help="Real corruptibility via simulation (requires original + locked + key)")
    p_measure.add_argument("original", help="Original unlocked bench file")
    p_measure.add_argument("locked", help="Locked bench file")
    p_measure.add_argument("--key", required=True, help='Correct key bits e.g. "0,1,1,0" (keyinput0,keyinput1,...)')
    p_measure.add_argument("--samples", type=int, default=10000)
    p_measure.add_argument("--wrong-keys", type=int, default=50)
    p_measure.add_argument("--seed", type=int, default=42)
    p_measure.add_argument("--format", choices=["text", "json"], default="text")
    p_measure.add_argument("--no-color", action="store_true")

    args = parser.parse_args()
    use_color = not getattr(args, "no_color", False) and sys.stdout.isatty()
    fmt = getattr(args, "format", "text")

    # measure command has different file args — handle separately
    if args.command == "measure":
        try:
            from lockview.parser import parse as _parse
            from lockview.simulator import measure_corruptibility
            from dataclasses import asdict as _asdict

            orig = Path(args.original).read_text(encoding="utf-8")
            lckd = Path(args.locked).read_text(encoding="utf-8")
            original_nl = _parse(orig, args.original)
            locked_nl = _parse(lckd, args.locked)

            key_bits_list = [int(b.strip()) for b in args.key.split(",")]
            if len(key_bits_list) != len(locked_nl.key_inputs):
                print(f"Error: key has {len(key_bits_list)} bits but netlist has "
                      f"{len(locked_nl.key_inputs)} key inputs: {', '.join(locked_nl.key_inputs)}",
                      file=sys.stderr)
                sys.exit(2)

            correct_key = {locked_nl.key_inputs[i]: key_bits_list[i] for i in range(len(key_bits_list))}
            _start = time.time()
            print(f"  Running simulation: {args.samples:,} input patterns × "
                  f"{args.wrong_keys} wrong keys = {args.samples * args.wrong_keys:,} evaluations...")

            report = measure_corruptibility(
                original_nl, locked_nl, correct_key,
                n_input_samples=args.samples,
                n_wrong_key_samples=args.wrong_keys,
                seed=args.seed,
            )

            _elapsed = round(time.time() - _start, 2)
            if fmt == "json":
                from dataclasses import asdict as _asdict
                print(json.dumps(_asdict(report), indent=2))
            else:
                print_real_corruptibility(report, use_color)
                print(f"  Completed in {_elapsed}s")
            sys.exit(0)

        except FileNotFoundError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(2)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(2)

    try:
        filepath = args.file
        content = Path(filepath).read_text(encoding="utf-8")
        netlist = parse(content, filepath)

        if netlist.errors:
            for e in netlist.errors:
                print(f"Parse warning: {e}", file=sys.stderr)

        if args.command == "coverage":
            cov = compute_coverage(netlist)
            if fmt == "json":
                print(json.dumps(asdict(cov), indent=2))
            else:
                print_coverage(cov, use_color)
            sys.exit(0)

        elif args.command == "lint":
            lr = lint(netlist, sensitivity=args.sensitivity)
            if fmt == "json":
                print(json.dumps({"summary": lr.summary, "diagnostics": [asdict(d) for d in lr.diagnostics]}, indent=2))
            else:
                print_lint(lr, Path(filepath).name, use_color)
            sys.exit(1 if lr.summary.get("error", 0) > 0 else 0)

        elif args.command == "measure":
            from lockview.simulator import measure_corruptibility
            orig = Path(args.original).read_text(encoding="utf-8")
            lckd = Path(args.locked).read_text(encoding="utf-8")
            original_nl = parse(orig, args.original)
            locked_nl = parse(lckd, args.locked)

            key_bits_list = [int(b.strip()) for b in args.key.split(",")]
            if len(key_bits_list) != len(locked_nl.key_inputs):
                print(f"Error: key has {len(key_bits_list)} bits but netlist has "
                      f"{len(locked_nl.key_inputs)} key inputs.", file=sys.stderr)
                sys.exit(2)

            correct_key = {locked_nl.key_inputs[i]: key_bits_list[i] for i in range(len(key_bits_list))}
            print(f"  Running simulation: {args.samples:,} input patterns × "
                  f"{args.wrong_keys} wrong keys = {args.samples * args.wrong_keys:,} evaluations...")

            report = measure_corruptibility(
                original_nl, locked_nl, correct_key,
                n_input_samples=args.samples,
                n_wrong_key_samples=args.wrong_keys,
                seed=args.seed,
            )

            if fmt == "json":
                from dataclasses import asdict as _asdict
                print(json.dumps(_asdict(report), indent=2))
            else:
                print_real_corruptibility(report, use_color)
            sys.exit(0)

        elif args.command == "analyze":
            cov = compute_coverage(netlist)
            cr = compute_corruptibility(netlist)
            lr = lint(netlist, sensitivity=args.sensitivity)
            if fmt == "json":
                print(json.dumps({
                    "file": filepath,
                    "module": netlist.module_name,
                    "coverage": asdict(cov),
                    "corruptibility": asdict(cr),
                    "lint": {"summary": lr.summary, "diagnostics": [asdict(d) for d in lr.diagnostics]},
                }, indent=2))
            else:
                print_coverage(cov, use_color)
                print_corruptibility(cr, use_color)
                print_lint(lr, Path(filepath).name, use_color)
            sys.exit(1 if lr.summary.get("error", 0) > 0 else 0)

    except FileNotFoundError:
        print(f"Error: file not found — {args.file}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
