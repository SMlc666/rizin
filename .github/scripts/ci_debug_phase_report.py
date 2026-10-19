#!/usr/bin/env python3
"""Audit and summarize opt-in Rizin function-phase profiles from heavy CI tests.

The measured phases are nested: e.g., memory_restore_total includes
snapshot_memory_restore and changed_memory_replay. Never sum all columns as
exclusive CPU time. Elapsed CLOCK_MONOTONIC is wall time within each function.
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import re

ENTRY = re.compile(
    r"^RZ_CI_PROFILE module=(\w+) phase=(\w+) "
    r"calls=(\d+) total_us=(\d+) max_us=(\d+) events=(\d+)$"
)
MANDATORY = {
    ("debug", "step_backend"),
    ("debug", "trace_ins_before"),
    ("debug", "trace_ins_after"),
    ("debug", "goto_cnum_restore"),
    ("session", "registers_restore"),
    ("session", "memory_restore_total"),
    ("session", "snapshot_memory_restore"),
    ("session", "changed_memory_replay"),
}


def aggregate(folder: Path) -> dict:
    sources = sorted(folder.glob("rizin-*-*.txt"))
    if not sources:
        raise ValueError("No per-process Rizin phase files found")
    summary = defaultdict(lambda: {"calls": 0, "total_us": 0, "max_us": 0, "events": 0})
    count = 0
    for path in sources:
        valid = False
        for line in path.read_text().splitlines():
            match = ENTRY.fullmatch(line.strip())
            if not match:
                raise ValueError(f"Unrecognized profile line in {path.name}: {line[:120]}")
            module, phase, calls, total_us, max_us, events = match.groups()
            metrics = summary[(module, phase)]
            metrics["calls"] += int(calls)
            metrics["total_us"] += int(total_us)
            metrics["max_us"] = max(metrics["max_us"], int(max_us))
            metrics["events"] += int(events)
            valid = True
            count += 1
        if not valid:
            raise ValueError(f"Empty per-process profile: {path.name}")
    missing = MANDATORY - set(summary)
    if missing:
        raise ValueError(f"Missing critical profiling phases: {sorted(missing)}")
    if any(summary[x]["calls"] < 1 for x in MANDATORY):
        raise ValueError("At least one critical phase has zero calls")
    rows = [
        {"module": module, "phase": phase, **metrics}
        for (module, phase), metrics in summary.items()
    ]
    rows.sort(key=lambda r: (-r["total_us"], r["module"], r["phase"]))
    return {"schema": 1, "files": len(sources), "metrics": rows, "lines": count}


def markdown(report: dict) -> str:
    rows = [
        "### Rizin debugger phase-level telemetry", "",
        f"Collected **{report['files']} per-process profile files**.", "",
        "| Module | Phase | Calls | Total wall time (s) | Max call (ms) | Events |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for x in report["metrics"]:
        rows.append(
            f"| {x['module']} | {x['phase']} | {x['calls']} | "
            f"{x['total_us'] / 1e6:.3f} | {x['max_us'] / 1000:.3f} | "
            f"{x['events']} |"
        )
    rows.extend([
        "",
        "Phases **overlap**: debugger session restoration includes memory "
        "restoration, which itself includes snapshot writes and replay. "
        "These totals must not be added together as if they were exclusive.",
        "Results are wall-clock time in instrumented functions, not sampled "
        "CPU cycles. CI instrumentation overhead and runner noise must be "
        "considered before changing algorithms.",
        "",
    ])
    return "\n".join(rows)


def self_test() -> None:
    from tempfile import TemporaryDirectory
    with TemporaryDirectory() as root:
        folder = Path(root)
        for module, phase in sorted(MANDATORY):
            target = folder / f"rizin-1000-{module}.txt"
            with target.open("a") as stream:
                stream.write(
                    f"RZ_CI_PROFILE module={module} phase={phase} "
                    "calls=2 total_us=200 max_us=120 events=0\n"
                )
        result = aggregate(folder)
        assert len(result["metrics"]) == len(MANDATORY)
        assert result["files"] == 2
        assert all(r["calls"] == 2 for r in result["metrics"])
        assert "overlap" in markdown(result).lower()
        print("Function phase profile parser self-test passed")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--input", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("--markdown", type=Path)
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.input or not args.json or not args.markdown:
        p.error("--input, --json and --markdown are required")
    report = aggregate(args.input)
    args.json.write_text(json.dumps(report, indent=2) + "\n")
    output = markdown(report)
    args.markdown.write_text(output)
    print(output)


if __name__ == "__main__":
    main()
