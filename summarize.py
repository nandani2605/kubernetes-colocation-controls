#!/usr/bin/env python3
"""Pool results.csv across seeds: one row per (nodes, condition, mode)."""
import csv
import math
import sys
from collections import defaultdict


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def f(x):
    return float(x) if x not in ("", None) else float("nan")


def mean(xs):
    xs = [x for x in xs if not math.isnan(x)]
    return sum(xs) / len(xs) if xs else float("nan")


def main(path="results.csv", out="summary.csv"):
    rows = list(csv.DictReader(open(path)))
    g = defaultdict(list)
    for r in rows:
        g[(int(r["nodes"]), r["condition"], r["mode"])].append(r)
    table = []
    for (nodes, cond, mode), rs in sorted(g.items()):
        k = sum(int(r["victims_colocated"]) for r in rs)
        n = sum(int(r["victims_scheduled"]) for r in rs)
        lo, hi = wilson(k, n)
        per_seed = [f(r["colocation_rate"]) for r in rs]
        table.append({
            "nodes": nodes, "condition": cond, "mode": mode, "seeds": len(rs),
            "colocated": k, "victims": n,
            "colocation_rate": round(k / n, 3) if n else "",
            "ci95": f"[{lo:.3f}, {hi:.3f}]",
            "seed_min": round(min(per_seed), 3), "seed_max": round(max(per_seed), 3),
            "legit_rejected": round(mean([f(r["legit_rejected_frac"]) for r in rs]), 3),
            "legit_unschedulable": round(mean([f(r["legit_unschedulable_frac"]) for r in rs]), 3),
            "attacker_rejected": round(mean([f(r["attacker_rejected_frac"]) for r in rs]), 3),
            "attacker_unschedulable": round(mean([f(r["attacker_unschedulable_frac"]) for r in rs]), 3),
            "node_packing_cv": round(mean([f(r["node_packing_cv"]) for r in rs]), 3),
        })
    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(table[0]))
        w.writeheader()
        w.writerows(table)
    cols = ["nodes", "condition", "mode", "colocation_rate", "ci95", "seed_min",
            "seed_max", "legit_rejected", "legit_unschedulable",
            "attacker_rejected", "attacker_unschedulable", "node_packing_cv"]
    width = {c: max(len(c), *(len(str(t[c])) for t in table)) for c in cols}
    print("  ".join(c.ljust(width[c]) for c in cols))
    for t in table:
        print("  ".join(str(t[c]).ljust(width[c]) for c in cols))


if __name__ == "__main__":
    main(*sys.argv[1:])
