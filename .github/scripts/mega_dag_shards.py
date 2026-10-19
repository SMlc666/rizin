#!/usr/bin/env python3
"""Produce an auditable, deterministic dynamic GitHub Actions regression matrix.

ASM is split by historical per-file execution cost (LPT); other rz-test
directories remain independent. Any newly added ASM test file is included
automatically with a fallback weight rather than silently omitted.
"""
import argparse
import json
import os
from pathlib import Path
import re
import statistics
import tempfile

CATEGORIES = (
    "abi", "analysis", "archos", "asm", "cmd", "esil",
    "formats", "inquiry", "io", "json", "rzil", "tools",
)
SAFE_NAME = re.compile(r"^[A-Za-z0-9_.+-]+$")


def build_plan(db_root: Path, history: dict, asm_groups: int = 4) -> tuple[dict, dict]:
    if history.get("schema") != 1 or history.get("unit") != "microseconds":
        raise ValueError("Unknown historical duration format")
    weights = history.get("files")
    if not isinstance(weights, dict) or not weights:
        raise ValueError("Empty ASM timing history")
    if any(not SAFE_NAME.fullmatch(name) or not isinstance(info, list)
           or len(info) != 2 or type(info[0]) is not int or info[0] < 0
           or type(info[1]) is not int or info[1] < 1
           for name, info in weights.items()):
        raise ValueError("Invalid ASM historical file weights")
    for category in CATEGORIES:
        if not (db_root / category).is_dir():
            raise ValueError(f"Missing required regression category: {category}")

    asm_root = db_root / "asm"
    # All ASM tests are flat files in the current Rizin test tree.
    if any(p.is_dir() for p in asm_root.iterdir() if not p.name.startswith(".")):
        raise ValueError("Nested ASM tests require an explicit planner update")
    asm_names = sorted(p.name for p in asm_root.iterdir()
                       if p.is_file() and not p.name.startswith("."))
    if not asm_names or len(asm_names) < asm_groups:
        raise ValueError("Not enough ASM files for nonempty shard allocation")
    if any(not SAFE_NAME.fullmatch(n) for n in asm_names):
        raise ValueError("Unsafe file name in ASM test directory")
    if any((asm_root / n).is_symlink() for n in asm_names):
        raise ValueError("ASM test files must not be symlinks")

    median_us = int(statistics.median(info[0] for info in weights.values()))
    unknown = sorted(set(asm_names) - set(weights))
    known = sorted(set(asm_names) & set(weights))
    # LPT: pack the next longest file onto the lowest-cost shard.
    ranked = sorted(asm_names, key=lambda n: (-weights.get(n, (median_us, 1))[0], n))
    groups = [[] for _ in range(asm_groups)]
    loads = [0] * asm_groups
    for name in ranked:
        i = min(range(asm_groups), key=lambda slot: (loads[slot], slot))
        groups[i].append(name)
        loads[i] += weights.get(name, (median_us, 1))[0]
    if sorted(name for group in groups for name in group) != asm_names:
        raise ValueError("ASM shards omit or duplicate tests")

    include = [
        {"name": f"asm-{i}", "category": "asm",
         "paths": [f"db/asm/{name}" for name in group], "exclude": []}
        for i, group in enumerate(groups)
    ]
    # Linux x86_64 debugger reverse-execution tests are very slow.
    # rz-test -e PATH excludes every test in that exact source file,
    # while the dedicated node runs that same file without exclusions.
    # The normal archos loader still filters irrelevant OS/architecture
    # subtrees automatically (unlike enumerating their files directly).
    heavy = "db/archos/linux-x64/dbg_cont_back"
    if not (db_root / "archos" / "linux-x64" / "dbg_cont_back").is_file():
        raise ValueError(f"Missing required heavy archos test: {heavy}")
    include += [
        {"name": name, "category": name, "paths": [f"db/{name}"],
         "exclude": [heavy] if name == "archos" else []}
        for name in CATEGORIES if name != "asm"
    ]
    # Keep this slow debugger regression outside the matrix concurrency cap.
    # Its standalone job uses the same source path and exports the same
    # result artifact that the regression audit previously expected.
    dedicated = {"name": "archos-heavy", "category": "archos",
                 "paths": [heavy], "exclude": []}
    names = [entry["name"] for entry in include] + [dedicated["name"]]
    if len(set(names)) != len(names) or len(include) != (asm_groups + len(CATEGORIES) - 1):
        raise ValueError("Invalid expanded matrix")
    matrix = {"include": include}
    manifest = {
        "schema": 1, "source_run": history.get("source_run"),
        "history_file_count": len(weights),
        "discovered_asm_file_count": len(asm_names),
        "historical_test_count": sum(weights[n][1] for n in known),
        "unknown_asm_files": unknown,
        "stale_historical_files": sorted(set(weights) - set(asm_names)),
        "predicted_asm_shard_seconds": [round(v / 1_000_000, 3) for v in loads],
        "isolated_archos_file": heavy,
        "standalone": dedicated,
        "matrix": matrix,
    }
    return matrix, manifest


def self_test() -> None:
    with tempfile.TemporaryDirectory() as root:
        db = Path(root)
        for category in CATEGORIES:
            (db / category).mkdir()
        (db / "archos" / "linux-x64").mkdir()
        (db / "archos" / "linux-x64" / "dbg_cont_back").write_text("test\n")
        names = ["a", "b", "c", "d", "e"]
        for name in names:
            (db / "asm" / name).write_text("test\n")
        history = {"schema": 1, "unit": "microseconds",
                   "files": {"a": [500, 1], "b": [400, 1],
                             "c": [300, 1], "d": [200, 1]}}
        matrix, manifest = build_plan(db, history, 4)
        flattened = sorted(p for item in matrix["include"] if item["category"] == "asm"
                           for p in item["paths"])
        assert flattened == [f"db/asm/{n}" for n in names]
        assert manifest["unknown_asm_files"] == ["e"]
        assert all(x["paths"] for x in matrix["include"])
        assert next(x for x in matrix["include"] if x["name"] == "archos")["exclude"] == [
            "db/archos/linux-x64/dbg_cont_back"]
        assert all(x["name"] != "archos-heavy" for x in matrix["include"])
        assert manifest["standalone"]["paths"] == [
            "db/archos/linux-x64/dbg_cont_back"]
        assert manifest["standalone"]["exclude"] == []
        assert build_plan(db, history, 4)[0] == matrix
        # A newly added file must be included automatically.
        (db / "asm" / "f").write_text("test\n")
        new_matrix, _ = build_plan(db, history, 4)
        assert "db/asm/f" in [p for x in new_matrix["include"] for p in x["paths"]]
        # Detect nested test directories instead of quietly losing cases.
        (db / "asm" / "nested").mkdir()
        try:
            build_plan(db, history, 4)
        except ValueError:
            pass
        else:
            raise AssertionError("Nested ASM files should fail closed")
    print("Shard planner tests passed")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path)
    p.add_argument("--history", type=Path)
    p.add_argument("--output", type=Path)
    p.add_argument("--manifest", type=Path)
    p.add_argument("--asm-groups", type=int, default=4)
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.root or not args.history or not args.manifest:
        p.error("--root, --history and --manifest are required")
    if args.asm_groups < 2 or args.asm_groups > 12:
        p.error("--asm-groups must be between 2 and 12")
    history = json.loads(args.history.read_text())
    matrix, manifest = build_plan(args.root, history, args.asm_groups)
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    if args.output:
        with args.output.open("a") as f:
            print("matrix=" + json.dumps(matrix, separators=(",", ":")), file=f)
    if manifest["unknown_asm_files"]:
        print("::warning title=New ASM tests::Missing historical weights for: " +
              ", ".join(manifest["unknown_asm_files"]))
    if manifest["stale_historical_files"]:
        print("::notice title=Removed ASM tests::Stale history entries: " +
              ", ".join(manifest["stale_historical_files"]))
    print("ASM shards (historic summed test CPU-seconds):",
          manifest["predicted_asm_shard_seconds"])
    print("Isolated slow debugger test file:", manifest["isolated_archos_file"])
    print("Matrix jobs:", len(matrix["include"]),
          "+1 dedicated archos-heavy job outside matrix capacity")


if __name__ == "__main__":
    main()
