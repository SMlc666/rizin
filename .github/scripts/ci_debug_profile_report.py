#!/usr/bin/env python3
"""Validate and aggregate experimental Rizin function-phase timing CSVs.

Durations are inclusive cumulative time. Nested phases overlap.
"""
import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

def audit(directory):
    files = sorted(directory.glob("rzci-prof.*.*.csv"))
    if not files:
        raise ValueError("No profiler CSV files produced")
    totals = defaultdict(lambda: [0, 0])
    pids = set()
    for path in files:
        parts = path.name.split(".")
        if len(parts) < 4 or not parts[-3].isdecimal():
            raise ValueError("Invalid profiler filename: " + path.name)
        pids.add(parts[-3])
        with path.open(newline="") as f:
            rows = list(csv.DictReader(f))
        if not rows:
            raise ValueError("Empty profiler file: " + path.name)
        for row in rows:
            calls, us = int(row["calls"]), int(row["total_us"])
            if calls < 0 or us < 0:
                raise ValueError("Negative profiler metrics")
            value = totals[(row["module"], row["phase"])]
            value[0] += calls
            value[1] += us
    metrics = [
        {"module": module, "phase": phase, "calls": v[0],
         "total_us": v[1], "total_s": round(v[1] / 1e6, 3),
         "mean_us_per_call": round(v[1] / v[0], 2) if v[0] else 0}
        for (module, phase), v in totals.items()
    ]
    metrics.sort(key=lambda x: (-x["total_us"], x["module"], x["phase"]))
    if not any(x["calls"] for x in metrics):
        raise ValueError("Profiler recorded zero actual calls")
    report = {
        "schema": 1, "files": len(files), "observed_pids": len(pids),
        "metrics": metrics,
        "limitations": [
            "Inclusive function totals overlap; do not sum.",
            "Profiling changes runtime and adds overhead.",
            "Abnormally terminated processes may not write files.",
            "Only selected debugger function boundaries are measured."
        ]
    }
    lines = [
        "### Experimental debugger function timings", "",
        f"Captured {len(files)} module files from {len(pids)} PIDs.", "",
        "| Phase | Calls | Inclusive seconds | Mean microseconds/call |",
        "| --- | ---: | ---: | ---: |"
    ]
    for m in metrics:
        if m["calls"]:
            lines.append(
                f"| {m['module']}/{m['phase']} | {m['calls']} | "
                f"{m['total_s']:.3f} | {m['mean_us_per_call']:.1f} |")
    lines.extend(["", "Inclusive totals can overlap. Step duration includes "
                  "trace phases; memory restore includes snapshots. "
                  "This diagnostic is not a performance-speedup claim.", ""])
    return report, "\n".join(lines)

def self_test():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "rzci-prof.123.trace.csv").write_text(
            "module,phase,calls,total_us\ntrace,trace_before,5,1000\n")
        (root / "rzci-prof.123.dsession.csv").write_text(
            "module,phase,calls,total_us\ndsession,restore_memory_total,2,3000\n")
        report, md = audit(root)
        assert report["files"] == 2 and report["observed_pids"] == 1
        assert report["metrics"][0]["total_us"] == 3000
        assert "restore_memory_total" in md
    print("Function-timing audit self-test passed")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--directory", type=Path)
    p.add_argument("--json-output", type=Path)
    p.add_argument("--markdown-output", type=Path)
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.directory or not args.json_output or not args.markdown_output:
        p.error("--directory, --json-output and --markdown-output are required")
    result, md = audit(args.directory)
    args.json_output.write_text(json.dumps(result, indent=2) + "\n")
    args.markdown_output.write_text(md + "\n")
    print(md)

if __name__ == "__main__":
    main()
