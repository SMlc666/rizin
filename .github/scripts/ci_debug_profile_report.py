#!/usr/bin/env python3
"""Validate and aggregate opt-in Rizin debugger function-timing records.

Timers in nested call paths deliberately overlap. Do not add phase times
together to infer total CPU consumption or causal performance gains.
"""
import argparse
import json
from collections import defaultdict
from pathlib import Path

EXPECTED = {
    "debug": {"hard_step", "checkpoint_goto", "continue_back"},
    "trace": {"ins_before", "ins_after", "reserved"},
    "session": {"register_restore", "memory_restore", "byte_writes"},
}


def analyze(root: Path) -> tuple[dict, str]:
    inputs = sorted(root.glob("rizin-*.json"))
    if not inputs:
        raise ValueError(f"No debugger function profiles under {root}")
    totals = defaultdict(lambda: {"calls": 0, "total_us": 0})
    units = set()
    paths = []
    for filename in inputs:
        record = json.loads(filename.read_text())
        if record.get("schema") != 1 or record.get("unit") not in EXPECTED:
            raise ValueError(f"Bad profiler schema/category in {filename}")
        unit = record["unit"]
        pid = record.get("pid")
        if type(pid) is not int or pid < 1:
            raise ValueError(f"Invalid PID in {filename}")
        expected_name = f"rizin-{unit}-{pid}.json"
        if filename.name != expected_name:
            raise ValueError(f"Unexpected profile filename {filename.name}")
        metrics = record.get("metrics")
        if not isinstance(metrics, list):
            raise ValueError(f"Invalid metrics in {filename}")
        names = [m.get("name") for m in metrics]
        if set(names) != EXPECTED[unit] or len(names) != len(EXPECTED[unit]):
            raise ValueError(f"Missing/duplicate profile fields in {filename}")
        for metric in metrics:
            name = metric["name"]
            calls, us = metric.get("calls"), metric.get("total_us")
            if type(calls) is not int or type(us) is not int or calls < 0 or us < 0:
                raise ValueError(f"Invalid counters in {filename}: {name}")
            key = (unit, name)
            totals[key]["calls"] += calls
            totals[key]["total_us"] += us
        units.add(unit)
        paths.append(filename.name)
    if units != set(EXPECTED):
        raise ValueError(f"Missing profiler units: {set(EXPECTED) - units}")
    # Refuse to mark zero instrumentation as a successful profile.
    for key in (("debug", "hard_step"), ("trace", "ins_before"),
                ("trace", "ins_after")):
        if totals[key]["calls"] == 0:
            raise ValueError(f"Missing execution observations for {key}")
    metrics = [
        {"unit": unit, "name": name, "calls": values["calls"],
         "total_us": values["total_us"],
         "total_seconds": round(values["total_us"] / 1_000_000, 3)}
        for (unit, name), values in sorted(totals.items())
    ]
    report = {"schema": 1, "unit": "microseconds",
              "input_profiles": paths, "metrics": metrics}
    lines = [
        "### CPU hotspot instrumentation — archos-heavy",
        "",
        f"**Profile files:** {len(paths)}; "
        "**measurement:** wall-clock function time with opt-in overhead.",
        "",
        "| Code phase | Calls | Cumulative seconds |",
        "| --- | ---: | ---: |",
    ]
    for m in sorted(metrics, key=lambda m: m["total_us"], reverse=True):
        lines.append(f"| {m['unit']}.{m['name']} | {m['calls']} | "
                     f"{m['total_seconds']:.3f} |")
    lines.extend([
        "",
        "Important: these phases can **nest** (e.g. hard-step contains "
        "instruction trace), and their totals must **not** be added as "
        "independent CPU costs. They measure elapsed function time, not "
        "per-function CPU cycles. Compare paired instrumented and "
        "uninstrumented runs before attributing timing changes.",
        "",
    ])
    return report, "\n".join(lines)


def self_test() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for unit, labels in EXPECTED.items():
            (root / f"rizin-{unit}-123.json").write_text(json.dumps({
                "schema": 1, "unit": unit, "pid": 123,
                "metrics": [
                    {"name": name, "calls": 2, "total_us": 10}
                    for name in sorted(labels)
                ]}))
        report, summary = analyze(root)
        assert len(report["metrics"]) == 9
        assert "hard_step" in summary
        (root / "rizin-debug-123.json").unlink()
        try:
            analyze(root)
        except ValueError:
            pass
        else:
            raise AssertionError("Missing instrumentation unit must fail")
    print("Function-profile audit self-test passed")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path)
    ap.add_argument("--output", type=Path)
    ap.add_argument("--summary", type=Path)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        self_test()
        return
    if not all((args.root, args.output, args.summary)):
        ap.error("--root, --output and --summary required")
    report, summary = analyze(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    args.summary.write_text(summary)
    print(summary)


if __name__ == "__main__":
    main()
