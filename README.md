# LockView 🔒

**Logic locking analysis for hardware security engineers — directly inside VS Code.**

LockView brings security-aware feedback into the hardware design workflow. Open a gate-level Verilog or Bench netlist and get instant locking coverage metrics, attack surface warnings, and key analysis — without leaving your editor.

Built for the **DeveloperWeek New York 2026 Hackathon** 

---

## The Problem

Logic locking is a hardware IP protection technique used across the semiconductor industry. But the tooling to *evaluate* how well a circuit is locked — and where it's vulnerable — lives entirely outside the design environment:

- Academic Python scripts and Jupyter notebooks
- Command-line tools with no IDE integration
- No real-time feedback during design

Engineers at Intel, Qualcomm, Synopsys, and research labs constantly context-switch between their design tools and external analyzers. LockView closes that gap.


## Features

## Real-Time Vulnerability Linting
Flags known logic locking weaknesses as you work, with inline diagnostics and hover explanations:

| Rule | Severity | Description |
|------|----------|-------------|
| LV001 | ⚠ Warning | XOR/XNOR key-gate chain — vulnerable to sensitization attack |
| LV002 | ⚠ Warning | Key bit reuse across multiple gates — reduces effective entropy |
| LV003 | ✗ Error | Output with no locked gates in fanin cone — observable without key |
| LV004 | ℹ Info | Output cone with only 1 locked gate — low SAT attack resistance |
| LV005 | ℹ Info | AND/OR locking — leaks key via stuck-at forcing |

## Coverage Panel (Sidebar)
- Overall locking coverage % with visual bar
- Locked vs total gates
- Key bit count and distribution
- Per-output cone coverage
- Gate type distribution (locked vs total)
- Average key fanin

## Status Bar
Live `LockView: 53% locked · 1E 2W` readout in the bottom bar, updating on every save.

## CLI for CI/CD Pipelines
```bash
# Fail CI if any error-severity vulnerability is found
lockview-cli analyze circuit.bench --sensitivity high
echo $?  # 1 if errors found, 0 if clean
```

---

## Supported Formats

- **Verilog gate-level netlists** (`.v`, `.sv`) — named and positional port styles
- **Bench format** (`.bench`) — ISCAS benchmark standard

Key inputs are detected automatically by naming convention (`keyinput*`, `key*`).

---

## Installation

### VS Code Extension

```bash
git clone https://github.com/your-username/lockview
cd lockview
npm install
npm run compile
# Then: Install from VSIX in VS Code (Extensions → ⋯ → Install from VSIX)
```

Requires Python 3.10+ (no extra packages needed — pure stdlib).

### CLI Only

```bash
cd lockview/cli
python3 lockview-cli.py analyze your_circuit.bench
python3 lockview-cli.py lint your_circuit.v --sensitivity high --format json
```

---

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `lockview.pythonPath` | `python3` | Path to Python 3 interpreter |
| `lockview.enableAutoAnalyze` | `true` | Auto-analyze on file open/save |
| `lockview.attackSensitivity` | `medium` | `low` (errors only) · `medium` · `high` (all rules) |

---

## Example Output

```
━━━ LockView Coverage Report ━━━
  Module       : c17
  Coverage     : 53.33%  ███████████░░░░░░░░░
  Locked Gates : 8 / 15
  Key Bits     : 4  keyinput0, keyinput1, keyinput2, keyinput3
  Output Cone  : 46.15%

  Per-Output Coverage:
    G22gat                  0.0%  ░░░░░░░░░░  ← unprotected output
    G23gat                 50.0%  █████░░░░░
    G16gat                 33.3%  ███░░░░░░░

━━━ LockView Lint — c17_locked.bench ━━━
  1 error(s)  2 warning(s)  2 info(s)

  ✗ [LV003] G22gat — Output has no locked gates in fanin cone
  ⚠ [LV001] G20gat — XOR chain of length 3 (sensitization attack risk)
  ⚠ [LV002] G30gat — keyinput0 reused across 5 gates
```

---

## Attack Rules Reference

## LV001 — XOR/XNOR Chain (Sensitization Attack)
Long consecutive chains of XOR/XNOR locked gates allow attackers to determine key bits one at a time via input sensitization, bypassing the need to solve the full SAT instance. Reference: El Massad et al., 2015.

## LV002 — Key Bit Reuse
When one key bit controls many gates, breaking a single key bit compromises multiple locked gates. Ideal ratio is 1 key bit : 1 locked gate.

## LV003 — Unlocked Output Cone (ATPG Attack)
Any primary output with no locked gates in its transitive fanin cone is fully observable without the key. An attacker can use ATPG to generate distinguishing input patterns on this output. Reference: Subramanyan et al., 2015.

## LV004 — Single Locked Gate Per Output
Low gate count in a locked output cone means the SAT attack resolves in very few iterations. Recommended minimum: 2–3 locked gates per output cone.

## LV005 — AND/OR Locking (Stuck-at Forcing)
AND/OR gates locked with a key bit can be attacked by forcing the controlling input value (0 for AND, 1 for OR), making the output independent of the key. XOR/XNOR locking is strongly preferred.

---

## Architecture

```
lockview/
├── src/
│   └── extension.ts              # VS Code extension (TypeScript)
├── backend/
│   └── lockview/
│       ├── parser.py             # Verilog + Bench netlist parser
│       ├── coverage.py           # Locking coverage metrics
│       ├── corruptibility.py     # Structural corruptibility estimator
│       ├── simulator.py          # Real corruptibility via Monte Carlo
│       ├── linter.py             # Attack surface linting rules
│       └── main.py               # JSON backend entry point
├── cli/
│   └── lockview-cli.py           # Standalone CLI (human-readable + JSON)
├── tools/
│   └── lock.py                   # Random XOR/XNOR locking utility
├── tests/
│   ├── c17_locked.bench          # Synthetic test netlist
│   └── c432_locked.bench         # Real ISCAS-85 benchmark (locked)
├── .vscode/
│   └── launch.json               # Extension debug configuration
├── README.md
├── LICENSE                       # CC BY-NC 4.0
├── NOTICE                        # Authorship + attribution
├── package.json
└── tsconfig.json
```

The extension spawns the Python backend as a subprocess and communicates via JSON stdout — no language server protocol overhead, no pip dependencies.

---

## Roadmap

- [ ] Verilog Verilog structural netlist export (annotated with lock status)
- [ ] SAT attack complexity estimator (theoretical iteration count)
- [ ] Support for encrypted netlist formats (IEEE 1735)
- [ ] SFLL / CAS-Lock pattern recognizer
- [ ] GitHub Actions template for CI/CD locking checks

---

## Built With

- VS Code Extension API
- Python 3 (stdlib only — no pip install required)
- TypeScript

---

## License

Copyright © 2026 [Henry John Grant]

LockView is licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.

**You are free to:**
- Use, share, and adapt this software for personal, academic, or research purposes
- Build on it and redistribute modified versions

**Under these conditions:**
- **Attribution** — You must credit the original author ([YOUR FULL NAME]) and link back to this repository in any use or derivative work
- **NonCommercial** — You may not use this software for commercial purposes without explicit written permission

**Commercial licensing:** If you are a company or individual wishing to use LockView in a commercial product or service, contact [YOUR EMAIL ADDRESS] to discuss a commercial license agreement.

See the [LICENSE](./LICENSE) and [NOTICE](./NOTICE) files for full details.
Full license text: https://creativecommons.org/licenses/by-nc/4.0/legalcode
