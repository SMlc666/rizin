#!/usr/bin/env python3
"""Read actual GitHub Actions job timestamps and emit a blocking-chain report.

Needs edges come from the checked-out workflow YAML; observed timestamps are
not a prediction of CPU time saved by parallelism.
"""
import argparse
from datetime import datetime, timezone, timedelta
import json
import os
from pathlib import Path
import urllib.request
import yaml


def logical_key(name):
    if name.startswith("00 / Validate graph"): return "validate-dag"
    if name.startswith("05 / Plan historical"): return "plan-regressions"
    if name.startswith("10 / Package regression"): return "prepare-fixtures"
    if name.startswith("10 / GCC build"): return "build-gcc"
    if name.startswith("10 / Coverage"): return "coverage"
    if name.startswith("10 / Build compatibility"): return "compatibility"
    if name.startswith("10 / ") and " ASan+UBSan /" in name: return "sanitizer"
    if name.startswith("20 / Validate staged CLI"): return "cli-smoke"
    if name.startswith("20 / rz-test /"): return "regression-shards"
    if name.startswith("90 / Regression inventory"): return "regression-report"
    if name.startswith("99 / Aggregate all DAG"): return "quality-gate"
    return None


def seconds(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def dependencies_from_workflow(path):
    jobs = yaml.safe_load(path.read_text())["jobs"]
    edges = {}
    for key, options in jobs.items():
        if key == "performance-report":
            continue
        req = options.get("needs", [])
        edges[key] = [req] if isinstance(req, str) else list(req)
    if "quality-gate" not in edges:
        raise ValueError("Missing final quality gate")
    visited = {}
    def visit(key):
        if visited.get(key) == 2: return
        if visited.get(key) == 1: raise ValueError("DAG cycle involving " + key)
        if key not in edges: raise ValueError("Missing dependency: " + key)
        visited[key] = 1
        for predecessor in edges[key]: visit(predecessor)
        visited[key] = 2
    for key in edges: visit(key)
    return edges


def analyze(jobs, edges):
    stages = {key: [] for key in edges}
    for job in jobs:
        stage = logical_key(job.get("name", ""))
        if stage not in stages:
            continue
        if not job.get("started_at") or not job.get("completed_at"):
            raise ValueError("Incomplete job: " + job["name"])
        entry = {
            "name": job["name"], "stage": stage, "id": job.get("id"),
            "result": job.get("conclusion"), "start": seconds(job["started_at"]),
            "end": seconds(job["completed_at"]),
        }
        entry["duration_s"] = round(entry["end"] - entry["start"], 2)
        if entry["duration_s"] < 0: raise ValueError("Job ended before start")
        stages[stage].append(entry)
    missing = [s for s, items in stages.items() if not items]
    if missing: raise ValueError("No job observations for " + ", ".join(missing))
    if len(stages["quality-gate"]) != 1:
        raise ValueError("Expected one final quality gate")
    representatives = {k: max(v, key=lambda x: x["end"]) for k, v in stages.items()}
    gate = stages["quality-gate"][0]
    chain = []
    key = "quality-gate"
    while True:
        chain.append(representatives[key])
        parents = edges[key]
        if not parents: break
        key = max(parents, key=lambda p: representatives[p]["end"])
    chain.reverse()
    gaps = [round(max(0, b["start"] - a["end"]), 2)
            for a, b in zip(chain, chain[1:])]
    observed = round(gate["end"] - min(j["start"] for v in stages.values() for j in v), 2)
    all_jobs = sorted([j for items in stages.values() for j in items],
                      key=lambda j: j["duration_s"], reverse=True)
    report = {
        "schema": 1,
        "gate_result": gate["result"],
        "gate_observed_wall_s": observed,
        "observed_job_count": len(all_jobs),
        "stages": {k: {"jobs": len(v), "latest_finisher": representatives[k]["name"],
                       "max_job_seconds": max(j["duration_s"] for j in v)}
                   for k, v in stages.items()},
        "chain": [{"name": j["name"], "stage": j["stage"],
                   "duration_s": j["duration_s"]} for j in chain],
        "chain_wait_gaps_s": gaps,
        "top_slowest": [{"name": j["name"], "duration_s": j["duration_s"],
                         "result": j["result"]} for j in all_jobs[:12]],
    }
    lines = ["### Mega DAG: observed gate-blocking chain", "",
             f"Gate: **{gate['result']}**; observed job window: **{observed:.1f}s**; "
             f"observed Jobs: **{len(all_jobs)}**.", "",
             "Chain below follows the latest-finishing predecessor at each "
             "declared needs edge (not intrinsic CPU criticality):", ""]
    for index, j in enumerate(chain):
        delay = f" (+ {gaps[index-1]:.1f}s scheduling gap)" if index else ""
        lines.append(f"{index + 1}. {j['name']}: **{j['duration_s']:.1f}s**{delay}")
    lines.extend(["", "**Longest Jobs**", "", "| Job | Seconds | Result |",
                  "| --- | ---: | --- |"])
    for j in all_jobs[:10]:
        lines.append(f"| {j['name']} | {j['duration_s']:.1f} | {j['result']} |")
    lines.extend(["", "Note: this is a retrospective dependency and timestamp "
                  "analysis; changes in runner queueing, cache temperature and "
                  "parallel load may change the observed chain.", ""])
    return report, "\n".join(lines)


def fetch_jobs(repo, run_id, token):
    rows = []
    for page in range(1, 21):
        url = (f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/jobs"
               f"?per_page=100&page={page}&filter=latest")
        req = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "rizin-mega-dag-diagnostics"})
        with urllib.request.urlopen(req, timeout=30) as response:
            batch = json.load(response)["jobs"]
        rows.extend(batch)
        if len(batch) < 100: return rows
    raise ValueError("Job listing pagination exceeded 2,000 jobs")


def self_test():
    edges = {
        "validate-dag": [], "build-gcc": ["validate-dag"],
        "prepare-fixtures": ["validate-dag"],
        "regression-shards": ["build-gcc", "prepare-fixtures"],
        "quality-gate": ["regression-shards", "build-gcc"],
    }
    origin = datetime(2026, 10, 19, tzinfo=timezone.utc)
    fmt = lambda x: (origin + timedelta(seconds=x)).isoformat()
    source = [("00 / Validate graph and test inventory", 0, 5),
              ("10 / GCC build + Meson suites + runtime artifact", 6, 50),
              ("10 / Package regression fixtures", 6, 20),
              ("20 / rz-test / asm-0", 51, 71),
              ("20 / rz-test / archos-heavy", 55, 92),
              ("99 / Aggregate all DAG results", 93, 99)]
    jobs = [{"name": name, "started_at": fmt(a),
             "completed_at": fmt(b), "conclusion": "success"}
            for name, a, b in source]
    report, markdown = analyze(jobs, edges)
    assert report["gate_observed_wall_s"] == 99
    assert [v["stage"] for v in report["chain"]] == [
        "validate-dag", "build-gcc", "regression-shards", "quality-gate"]
    assert report["chain"][-2]["name"].endswith("archos-heavy")
    assert "99.0s" in markdown
    print("Critical-path reporter self-test passed")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--workflow", type=Path)
    p.add_argument("--report", type=Path)
    p.add_argument("--markdown", type=Path)
    p.add_argument("--jobs-json", type=Path)
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.workflow or not args.report or not args.markdown:
        p.error("--workflow, --report and --markdown are required")
    deps = dependencies_from_workflow(args.workflow)
    if args.jobs_json:
        jobs = json.loads(args.jobs_json.read_text())
    else:
        jobs = fetch_jobs(os.environ["GITHUB_REPOSITORY"],
                          int(os.environ["GITHUB_RUN_ID"]), os.environ["GITHUB_TOKEN"])
    report, md = analyze(jobs, deps)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    args.markdown.write_text(md)
    print(md)
    if "GITHUB_STEP_SUMMARY" in os.environ:
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as out:
            out.write(md)


if __name__ == "__main__":
    main()
