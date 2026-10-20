#!/usr/bin/env python3
"""Audit and summarize opt-in C debugger profile output for CI artifacts.

A source-level instrument writes one tab-delimited RZCI_PROFILE row per phase
at normal child-process exit. Durations are inclusive: do not sum parent and
child phases or confuse captured wall time with CPU cycles.
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import tempfile


def analyze(raw: str) -> dict:
    totals = defaultdict(lambda: {"calls": 0, "microseconds": 0, "records": 0})
    for line in raw.splitlines():
        if not line:
            continue
        if not line.startswith("RZCI_PROFILE\t"):
            raise ValueError(f"unexpected profile record: {line[:150]}")
        fields = {}
        for item in line.split("\t")[1:]:
            key, sep, val = item.partition("=")
            if not sep or key in fields:
                raise ValueError("invalid profile field")
            fields[key] = val
        if set(fields) != {"unit", "phase", "calls", "us"}:
            raise ValueError("missing or extra profiler data fields")
        if not fields["unit"].isidentifier() or not fields["phase"].isidentifier():
            raise ValueError("unsafe profiler label")
        calls, microseconds = int(fields["calls"]), int(fields["us"])
        if calls <= 0 or microseconds < 0:
            raise ValueError("invalid profiler counts")
        record = totals[(fields["unit"], fields["phase"])]
        record["calls"] += calls
        record["microseconds"] += microseconds
        record["records"] += 1
    if not totals:
        raise ValueError("no C debugger function timing records")
    required = {("debug", "native_step"), ("trace", "instruction_before"),
                ("trace", "instruction_after"), ("dsession", "restore_all"),
                ("dsession", "restore_changed_memory")}
    missing = required - set(totals)
    if missing:
        raise ValueError(f"missing key debugger measurement phases: {sorted(missing)}")
    results = [
        {"unit": unit, "phase": phase, **values,
         "elapsed_seconds": round(values["microseconds"] / 1_000_000, 4)}
        for (unit, phase), values in totals.items()
    ]
    results.sort(key=lambda r: (-r["microseconds"], r["unit"], r["phase"]))
    return {"schema": 1, "measurement": "inclusive monotonic wall microseconds",
            "phase_count": len(results), "phases": results,
            "warning": "Overlapping parent/child phases cannot be summed; "
                       "time spent outside these phases is not categorized."}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        raw = ("RZCI_PROFILE\tunit=debug\tphase=native_step\tcalls=4\tus=10000\n"
               "RZCI_PROFILE\tunit=trace\tphase=instruction_before\tcalls=4\tus=2000\n"
               "RZCI_PROFILE\tunit=trace\tphase=instruction_after\tcalls=4\tus=3000\n"
               "RZCI_PROFILE\tunit=dsession\tphase=restore_all\tcalls=2\tus=5000\n"
               "RZCI_PROFILE\tunit=dsession\tphase=restore_changed_memory\tcalls=2\tus=1200\n")
        a = analyze(raw)
        assert a["phase_count"] == 5
        assert a["phases"][0]["phase"] == "native_step"
        assert a["phases"][0]["elapsed_seconds"] == 0.01
        try:
            analyze("")
        except ValueError:
            pass
        else:
            raise AssertionError("missing data must fail")
        print("C debugger profile audit self-test passed")
        return
    if not args.input or not args.output:
        parser.error("--input and --output are required")
    profile = analyze(args.input.read_text())
    args.output.write_text(json.dumps(profile, indent=2) + "\n")
    print("### Opt-in debugger function timing")
    print("| Unit | Phase | Calls/events | Inclusive seconds |")
    print("| --- | --- | ---: | ---: |")
    for r in profile["phases"]:
        print(f'| {r["unit"]} | {r["phase"]} | {r["calls"]} | '
              f'{r["elapsed_seconds"]:.3f} |')
    print("\nParent-child durations overlap. Compare with the uninstrumented "
          "historical run before attributing absolute performance impact.")


if __name__ == "__main__":
    main()
