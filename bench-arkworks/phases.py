#!/usr/bin/env python3
"""Extract the ark-std print-trace per-phase breakdown for the prover.

print-trace lines look like:
    ····End:     Compute C .......... 12.345s
Indentation is a run of '·' characters, two per nesting level.
"""
import re
import sys

LINE = re.compile(r"^([·]*)End:\s+(.*?)\s*\.+\s*([0-9.]+)(ms|s|µs|ns)\s*$")
MULT = {"ns": 1e-9, "µs": 1e-6, "ms": 1e-3, "s": 1.0}


def parse(path):
    """Return (prover_phases, prover_total). Only the first Prover block is used."""
    phases, total, in_prover, depth0 = [], None, False, None
    for raw in open(path, encoding="utf-8", errors="replace"):
        line = raw.rstrip("\n")
        if "Start:" in line and "Groth16::Prover" in line:
            in_prover = True
            depth0 = line.index("Start:")
            continue
        if not in_prover:
            continue
        m = LINE.match(line)
        if not m:
            continue
        dots, name, val, unit = m.groups()
        secs = float(val) * MULT[unit]
        if name.startswith("Groth16::Prover"):
            total = secs
            break
        phases.append((len(dots), name, secs))
    return phases, total


def main(paths):
    for p in paths:
        phases, total = parse(p)
        if total is None:
            print(f"\n{p}: no complete Prover block found")
            continue
        print(f"\n### {p}\n")
        print("| phase | time (s) | % of prove |")
        print("|---|---|---|")
        mind = min((d for d, _, _ in phases), default=0)
        acc = 0.0
        for d, name, s in phases:
            indent = "&nbsp;" * 4 * ((d - mind) // 2)
            print(f"| {indent}{name} | {s:.3f} | {100*s/total:.1f}% |")
            if d == mind:
                acc += s
        print(f"| **total prove** | **{total:.3f}** | 100% |")
        print(f"\nTop-level phases sum to {acc:.3f}s "
              f"({100*acc/total:.1f}% of the measured prove time).")


if __name__ == "__main__":
    main(sys.argv[1:])
