#!/usr/bin/env python3
"""Render results.jsonl sweeps into markdown tables."""
import json
import sys
from collections import defaultdict


def load(path):
    rows, failed = [], []
    for line in open(path):
        line = line.strip()
        if line.startswith("RESULT_JSON "):
            rows.append(json.loads(line[len("RESULT_JSON "):]))
        elif line.startswith("FAILED_JSON "):
            failed.append(json.loads(line[len("FAILED_JSON "):]))
    return rows, failed


def gb(kb):
    return kb / 1024.0 / 1024.0


def main(paths):
    rows, failed = [], []
    for p in paths:
        r, f = load(p)
        rows += r
        failed += f

    by = defaultdict(dict)
    for r in rows:
        by[(r["label"], r["shape"], r["constraints"])][r["threads"]] = r

    for key in sorted(by, key=lambda k: (k[0], k[1], k[2])):
        label, shape, nc = key
        per = by[key]
        print(f"\n### {label} / shape={shape} / constraints={nc:,}\n")
        print("| threads | prove run1 (s) | prove run2 (s) | best (s) | speedup vs 1t | "
              "par. efficiency | setup (s) | verify (ms) | peak RSS (GB) |")
        print("|---|---|---|---|---|---|---|---|---|")
        base = min(per[1]["prove_s"]) if 1 in per else None
        for t in sorted(per):
            r = per[t]
            b = min(r["prove_s"])
            sp = f"{base/b:.2f}x" if base else "-"
            eff = f"{100*(base/b)/t:.0f}%" if base else "-"
            print(f"| {t} | {r['prove_s'][0]:.2f} | {r['prove_s'][1]:.2f} | {b:.2f} | {sp} | "
                  f"{eff} | {r['setup_s']:.1f} | {r['verify_ms']:.2f} | {gb(r['peak_rss_kb']):.2f} |")
        any_r = next(iter(per.values()))
        print(f"\nProving key: {any_r['pk_compressed_bytes']:,} B compressed / "
              f"{any_r['pk_uncompressed_bytes']:,} B uncompressed. "
              f"Witness vars {any_r['witness']:,}, instance vars {any_r['instance']}. "
              f"Serial synthesis {any_r['synth_only_ms']/1000:.2f}s + "
              f"finalize/inline {any_r['finalize_ms']/1000:.2f}s.")

    if failed:
        print("\n### Failed configurations\n")
        print("| label | shape | target constraints | threads | exit |")
        print("|---|---|---|---|---|")
        for f in failed:
            print(f"| {f['label']} | {f['shape']} | {f['param']:,} | {f['threads']} | {f['exit']} |")


if __name__ == "__main__":
    main(sys.argv[1:] or ["results.jsonl"])
