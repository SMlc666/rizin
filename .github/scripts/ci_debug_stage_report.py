#!/usr/bin/env python3
"""Summarize opt-in Rizin debugger stage timing JSONL produced by CI.

Cumulative stage totals are not necessarily additive: state restore is nested
in a higher-level goto operation, and concurrent tests share the measurement.
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path

EXPECTED = {
    "trace_before", "step_backend", "trace_after",
    "reverse_breakpoint_scan", "goto_state_restore",
    "restore_registers", "sync_registers",
    "restore_snapshot_memory", "restore_memory_changes",
}


def summarize(path: Path) -> tuple[dict, str]:
    if not path.is_file() or not path.stat().st_size:
        raise ValueError(f"No debugger timing data at {path}")
    stages = defaultdict(lambda: {"calls": 0, "total_ns": 0, "max_ns": 0})
    pid_set = set()
    observations = 0
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        obj = json.loads(line)
        if obj.get("schema") != 1 or obj.get("stage") not in EXPECTED:
            raise ValueError(f"Invalid stage record on line {number}")
        if not isinstance(obj.get("pid"), int) or obj["pid"] < 1:
            raise ValueError(f"Invalid pid on line {number}")
        for key in ("calls", "total_ns", "max_ns"):
            if type(obj.get(key)) is not int or obj[key] < 0:
                raise ValueError(f"Invalid counter {key} on line {number}")
        if obj["calls"] == 0 or obj["total_ns"] < obj["max_ns"]:
            raise ValueError(f"Invalid timer values on line {number}")
        pid_set.add(obj["pid"])
        counter = stages[obj["stage"]]
        counter["calls"] += obj["calls"]
        counter["total_ns"] += obj["total_ns"]
        counter["max_ns"] = max(counter["max_ns"], obj["max_ns"])
        observations += 1
    if not observations:
        raise ValueError("No timing records")
    for label in ("trace_before", "trace_after", "step_backend"):
        if stages[label]["calls"] == 0:
            raise ValueError(f"Mandatory trace-stage counter not observed: {label}")

    ordered = sorted(stages.items(), key=lambda x: x[1]["total_ns"], reverse=True)
    lines = [
        "### Dedicated Rizin reverse-debugger function profiling", "",
        f"**Processes with records:** {len(pid_set)}; **timing records:** {observations}.",
        "",
        "| Stage | Calls | Cumulative time | Mean per call | Max per call |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for name, value in ordered:
        n = value["calls"]
        lines.append(
            f"| {name} | {n:,} | {value['total_ns']/1e9:.3f}s | "
            f"{value['total_ns']/n/1e6:.3f}ms | {value['max_ns']/1e6:.3f}ms |"
        )
    lines += [
        "",
        "**Interpretation:** timings aggregate across subprocesses and measure",
        "nested operations in several stages. Do not sum the rows or compare",
        "their total directly to the Job wall clock. The profiling version itself",
        "may add clock-read overhead; compare with an uninstrumented control.",
        "",
    ]
    data = {
        "schema": 1, "process_count": len(pid_set), "records": observations,
        "stages": stages, "sorted_stages": [key for key, _ in ordered],
    }
    return data, "\n".join(lines)


def self_test():
    import tempfile
    with tempfile.TemporaryDirectory() as temp:
        p = Path(temp) / "profile.jsonl"
        p.write_text("\n".join(json.dumps({
            "schema": 1, "pid": 21, "source": "debug", "stage": label,
            "calls": 2, "total_ns": 2000000, "max_ns": 1000000
        }) for label in ("trace_before", "trace_after", "step_backend")) + "\n")
        data, markdown = summarize(p)
        assert data["stages"]["trace_before"]["calls"] == 2
        assert len(data["sorted_stages"]) == 3
        assert "0.002s" in markdown
        p.write_text("")
        try:
            summarize(p)
        except ValueError:
            pass
        else:
            raise AssertionError("Empty profiles must fail")
    print("Debug stage profile summarizer self-test passed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--markdown", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not (args.input and args.json and args.markdown):
        parser.error("--input, --json, --markdown required")
    result, markdown = summarize(args.input)
    args.json.write_text(json.dumps(result, indent=2) + "\n")
    args.markdown.write_text(markdown)
    print(markdown)
    import os
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(markdown)


if __name__ == "__main__":
    main()
