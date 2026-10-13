#!/usr/bin/env python3
"""Rebuild and evaluate Sprint 6 Issue #149 labelled usage fixtures."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LABEL_ROOT = ROOT / "testdata/fixtures/usage-ground-truth"
SOURCE_ROOT = ROOT / "testdata/fixtures"
OUT = ROOT / "docs/evidence/s6-04"
METRICS = ("importEvaluation", "callEvaluation", "unresolvedCallEvaluation")


def command(*args, env=None):
    result = subprocess.run(
        args, cwd=ROOT, env=env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {' '.join(map(str, args))}\n{result.stdout}")
    return result.stdout.strip()


def git(*args):
    return command("git", *args)


def tree_digest(directory):
    h = hashlib.sha256()
    for file in sorted(p for p in directory.rglob("*") if p.is_file()):
        h.update(file.relative_to(directory).as_posix().encode())
        h.update(b"\0")
        h.update(file.read_bytes())
        h.update(b"\0")
    return h.hexdigest()


def display(value):
    return "N/A" if value is None else f"{value:.0%}"


def main():
    # Evidence may already be generated, but production/test source must be clean.
    dirty = [line for line in git("status", "--porcelain", "--untracked-files=all").splitlines()
             if not line[3:].startswith("docs/evidence/s6-04/")]
    if dirty:
        raise RuntimeError("Commit or remove other working-tree changes first:\n" + "\n".join(dirty))

    commit = git("rev-parse", "HEAD")
    label_paths = sorted(LABEL_ROOT.glob("component2-s6-*/expected.json"))
    if len(label_paths) != 13:
        raise RuntimeError(f"Expected 13 labelled fixtures, found {len(label_paths)}")

    (OUT / "graphs").mkdir(parents=True, exist_ok=True)
    (OUT / "metrics").mkdir(parents=True, exist_ok=True)
    rows = []

    for index, labels_path in enumerate(label_paths, 1):
        labels = json.loads(labels_path.read_text())
        name = labels["fixture"]
        source_dir = SOURCE_ROOT / name
        if not source_dir.is_dir() or labels_path.parent.name != name:
            raise RuntimeError(f"Source/label directory mismatch: {name}")
        graph_file = OUT / "graphs" / f"{name}.json"
        metrics_file = OUT / "metrics" / f"{name}.json"

        print(f"[{index:02d}/13] {name}", flush=True)
        env = os.environ.copy()
        env.pop("GITHUB_TOKEN", None)
        env.pop("GH_TOKEN", None)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["S6_FIXTURE"] = name
        env["S6_GRAPH_OUT"] = str(graph_file)

        command("go", "test", "-count=1", "-run", "^TestS6ExportUsageGraph$",
                "./internal/usagegraph", env=env)
        command(sys.executable, "-B", "scripts/evaluate_usage_constructs.py",
                "--labels", str(labels_path), "--graph", str(graph_file),
                "--out", str(metrics_file), "--commit", commit, env=env)
        command(sys.executable, "-B", "scripts/check_s6_usage_safety.py",
                "--labels", str(labels_path), "--graph", str(graph_file), env=env)

        metrics = json.loads(metrics_file.read_text())
        for key in METRICS:
            result = metrics[key]
            if result["fp"] or result["fn"]:
                raise RuntimeError(f"{name}: {key} has FP/FN: {result}")
        if metrics["excludedCallViolations"]:
            raise RuntimeError(f"{name}: excluded calls were attributed")

        path_in_git = labels_path.relative_to(ROOT).as_posix()
        label_added = git("log", "--reverse", "--diff-filter=A", "--format=%H", "--", path_in_git).splitlines()
        label_last = git("log", "-1", "--format=%H", "--", path_in_git)
        if not label_added or not label_last:
            raise RuntimeError(f"No committed label history for {name}")

        rows.append({
            "fixture": name,
            "construct": labels["construct"],
            "variant": labels.get("variant"),
            "sourceFixtureSha256": tree_digest(source_dir),
            "labelSha256": metrics["labelSha256"],
            "labelFirstCommit": label_added[0],
            "labelLatestCommit": label_last,
            "labelCorrection": labels.get("labelCorrection"),
            "importEvaluation": metrics["importEvaluation"],
            "callEvaluation": metrics["callEvaluation"],
            "unresolvedCallEvaluation": metrics["unresolvedCallEvaluation"],
            "excludedCallViolations": metrics["excludedCallViolations"],
            "safetyChecks": "PASS",
            "graphSha256": metrics["graphSha256"],
        })
        print("  PASS: import, resolved calls, unresolved calls and safety", flush=True)

    categories = {row["construct"] for row in rows}
    if len(categories) != 11:
        raise RuntimeError(f"Expected 11 construct categories; got {len(categories)}: {sorted(categories)}")

    manifest = {
        "issue": 149,
        "analyserGitCommit": commit,
        "method": "Go test exporter (production source analyser and usagegraph producer); TypeScript aliases supplied from root tsconfig.json",
        "fixtureCount": len(rows),
        "constructCategoryCount": len(categories),
        "results": rows,
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    md = [
        "# Sprint 6 Issue #149 — per-construct usage evaluation",
        "",
        f"Analyser Git commit: `{commit}`. Fixtures: **{len(rows)}**; construct categories: **{len(categories)}**.",
        "",
        "All metrics are based on controlled, independently source-reviewed fixtures, not overall real-world scanner accuracy.",
        "A call metric of N/A means no measurable resolved/unresolved calls were present, not 100% accuracy.",
        "", "| Fixture | Import TP/FP/FN | Import P/R | Call TP/FP/FN | Call P/R | Unknown TP/FP/FN | Unknown P/R | Safety |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        imp, call, unknown = (row[key] for key in METRICS)
        counts = lambda m: f"{m['tp']}/{m['fp']}/{m['fn']}"
        rates = lambda m: f"{display(m['precision'])}/{display(m['recall'])}"
        name = row["fixture"]
        md.append(
            f"| [{name}](metrics/{name}.json) | {counts(imp)} | {rates(imp)} | "
            f"{counts(call)} | {rates(call)} | {counts(unknown)} | {rates(unknown)} | PASS |"
        )
    md += [
        "", "## Evidence and limitations", "",
        "- Each fixture has a graph in `graphs/`, a per-fixture metrics file in `metrics/`, and provenance in `manifest.json`.",
        "- Import evidence, resolved calls and unresolved calls are scored independently. False positives and false negatives are not blended.",
        "- Computed imports, re-exports, type-only imports, side-effect imports and TS aliases receive additional conservative-evidence checks.",
        "- The original `component2-s6-import-type` label was corrected after evaluation; its initial and correction commits are preserved in `manifest.json`. The independent alias type-only fixture was prelabelled and evaluated separately.",
        "- This uses the production source analyser and usagegraph producer via a Go test exporter, not a complete end-to-end CLI scan. Reachability accuracy belongs to Issue #152.",
        "", "## Reproduction", "",
        "Run `python3 -B scripts/run_s6_usage_evaluation.py` from a clean committed worktree. The runner removes inherited GitHub tokens from the Go test environment.",
    ]
    (OUT / "report.md").write_text("\n".join(md) + "\n")
    print(f"\nPASS: {len(rows)} fixtures across {len(categories)} categories")
    print(f"Evidence: {OUT.relative_to(ROOT)}")
    print(f"Analyser commit: {commit}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, KeyError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
