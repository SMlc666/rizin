#!/usr/bin/env python3
"""Run one CI test command, sampling its Linux descendant process tree.

Sampling uses ps instead of ptrace/perf so it does not attach to the debugger
under test. Sampling never changes the test exit code. Captures diagnostics
even if a test fails, and propagates SIGTERM/SIGINT to the process group.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def process_tree(root_pid: int) -> list[dict]:
    result = subprocess.run(
        ["ps", "-eo", "pid=,ppid=,stat=,pcpu=,rss=,comm="],
        text=True, capture_output=True, check=True, timeout=8,
    )
    entries = []
    for line in result.stdout.splitlines():
        fields = line.split(None, 5)
        if len(fields) != 6:
            continue
        pid, ppid, status, cpu, rss, command = fields
        try:
            entries.append({
                "pid": int(pid), "ppid": int(ppid), "state": status,
                "cpu_pct": float(cpu), "rss_kib": int(rss),
                "command": command,
            })
        except ValueError:
            continue
    descendants = {root_pid}
    # Repeated fixed-point expansion is deterministic, even if ps ordering
    # changes while subprocesses are being spawned.
    for _ in range(32):
        previous = len(descendants)
        descendants.update(p["pid"] for p in entries if p["ppid"] in descendants)
        if len(descendants) == previous:
            break
    return [p for p in entries if p["pid"] in descendants]


def sample_record(root_pid: int, start: float) -> dict:
    entries = process_tree(root_pid)
    return {
        "elapsed_s": round(time.monotonic() - start, 2),
        "process_count": len(entries),
        "rss_kib_sum": sum(p["rss_kib"] for p in entries),
        "cpu_pct_sum": round(sum(p["cpu_pct"] for p in entries), 2),
        "states": {state: sum(p["state"].startswith(state) for p in entries)
                   for state in ("R", "S", "D", "T", "Z")},
        "processes": entries,
    }


def run(argv: list[str], output: Path, interval: float) -> int:
    start = time.monotonic()
    readings = []
    proc = subprocess.Popen(argv, start_new_session=True)
    interrupted = False
    saved_handlers = {}

    def forward(signum, _frame):
        nonlocal interrupted
        interrupted = True
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signum)
            except ProcessLookupError:
                pass

    for signum in (signal.SIGINT, signal.SIGTERM):
        saved_handlers[signum] = signal.signal(signum, forward)
    try:
        while proc.poll() is None:
            try:
                readings.append(sample_record(proc.pid, start))
            except (OSError, subprocess.SubprocessError, ValueError) as exc:
                readings.append({"elapsed_s": round(time.monotonic() - start, 2),
                                 "sampling_error": str(exc)})
            try:
                proc.wait(timeout=interval)
            except subprocess.TimeoutExpired:
                pass
        returncode = proc.wait()
    finally:
        for signum, handler in saved_handlers.items():
            signal.signal(signum, handler)
        output.parent.mkdir(parents=True, exist_ok=True)
        report = {
            "schema": 1, "command": [Path(argv[0]).name, *argv[1:]],
            "duration_s": round(time.monotonic() - start, 2),
            "exit_code": proc.returncode,
            "sample_interval_s": interval,
            "samples": readings,
            "interrupted": interrupted,
        }
        output.write_text(json.dumps(report, indent=2) + "\n")
        print(
            "Diagnostic process samples:", len(readings),
            "peak aggregate RSS (MiB):",
            round(max((x.get("rss_kib_sum", 0) for x in readings), default=0) / 1024, 1),
            "max observed CPU% sum:",
            max((x.get("cpu_pct_sum", 0) for x in readings), default=0),
            file=sys.stderr,
        )
    return returncode


def self_test() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as temp:
        out = Path(temp) / "profile.json"
        rc = run([sys.executable, "-c", "import time;time.sleep(0.2)"], out, 0.05)
        result = json.loads(out.read_text())
        assert rc == 0 and result["exit_code"] == 0
        assert len(result["samples"]) >= 1
        bad = run([sys.executable, "-c", "raise SystemExit(7)"], out, 0.05)
        assert bad == 7 and json.loads(out.read_text())["exit_code"] == 7
        print("Process sampler self-test passed")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.output or not args.command:
        parser.error("--output and a command following -- are required")
    if not 0.1 <= args.interval <= 60:
        parser.error("--interval outside [0.1,60] seconds")
    command = args.command[1:] if args.command[0] == "--" else args.command
    if not command:
        parser.error("empty command")
    raise SystemExit(run(command, args.output, args.interval))


if __name__ == "__main__":
    main()
