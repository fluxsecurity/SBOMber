#!/usr/bin/env python3
"""Issue #152: production scan -> usage, with separate reachability evidence."""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
STATES = ("reachable", "unknown", "not_analysed")


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rate(resolved, unknown):
    return resolved / (resolved + unknown) if resolved + unknown else None


def summarise(graph):
    """Count public contract records, not unique expressions or runtime calls."""
    entries = {e["entryPointId"]: e for e in graph["entryPoints"]}
    if len(entries) != len(graph["entryPoints"]):
        raise ValueError("duplicate entry-point identity")
    counts, resolved_calls, causes = Counter(), Counter(), Counter()
    records = []
    for observation in graph["observations"]:
        for index, call in enumerate(observation["callSites"]):
            state = call["reachability"]
            if state not in STATES:
                raise ValueError(f"invalid reachability: {state}")
            counts[state] += 1
            if call["resolution"] == "resolved":
                resolved_calls[state] += 1
            if state == "reachable":
                entry = entries.get(call.get("entryPointId"))
                path = call.get("callPath", [])
                if (not entry or not path or call["resolution"] != "resolved"
                        or observation["resolution"] != "resolved"):
                    raise ValueError("reachable record lacks resolved import/call/path/entry")
                if path[0]["function"] != entry["function"] or path[0]["file"] != entry["file"]:
                    raise ValueError("call path does not begin at its entry point")
                cause = None
            else:
                if call.get("callPath") or call.get("entryPointId"):
                    raise ValueError("unknown/not_analysed record carries a proven path")
                if state == "not_analysed":
                    cause = "reachability_pass_not_run"
                elif observation["resolution"] != "resolved":
                    cause = "import_resolution:" + observation.get("unresolvedReason", "unspecified")
                elif call["resolution"] != "resolved":
                    cause = "call_resolution:" + call.get("unresolvedReason", "unspecified")
                elif not call.get("enclosingFunction"):
                    cause = "no_recorded_enclosing_function"
                else:
                    cause = "no_resolved_entry_point_path"
                if state == "unknown":
                    causes[cause] += 1
            # The public contract lacks a synthetic-marker flag. This is only
            # a review candidate; it must not be presented as an exact split.
            marker_candidate = (
                call["resolution"] == "unresolved" and not call.get("calledSymbol")
                and call["file"] == observation["location"]["file"]
                and call["line"] == observation["location"]["line"]
                and call.get("column", 0) == observation["location"].get("column", 0)
            )
            records.append({
                "observationId": observation["observationId"], "callIndex": index,
                "specifier": observation["importedSpecifier"],
                "importResolution": observation["resolution"],
                "call": call, "causeCategory": cause,
                "possibleSyntheticMarker": marker_candidate,
            })
    coverage = graph["coverage"]
    expected = {
        "entryPointsDetected": len(entries),
        "callPathsResolved": counts["reachable"],
        "callPathsUnresolved": counts["unknown"],
        "thirdPartyCallSitesResolved": sum(resolved_calls.values()),
        "thirdPartyCallSitesUnresolved": len(records) - sum(resolved_calls.values()),
    }
    for field, measured in expected.items():
        if coverage[field] != measured:
            raise ValueError(f"{field}: coverage={coverage[field]}, records={measured}")
    if not graph["analyser"]["reachabilityAnalysed"] and (counts["reachable"] or counts["unknown"]):
        raise ValueError("reachability states contradict pass metadata")
    metrics = {
        "entryPointsDetected": len(entries), "contractCallRecords": len(records),
        "reachable": counts["reachable"], "unknown": counts["unknown"],
        "notAnalysed": counts["not_analysed"],
        "resolutionDenominator": counts["reachable"] + counts["unknown"],
        "resolutionRate": rate(counts["reachable"], counts["unknown"]),
        "resolvedSymbolCallRecords": sum(resolved_calls.values()),
        "resolvedSymbolCallsUnknown": resolved_calls["unknown"],
        "resolvedSymbolCallsNotAnalysed": resolved_calls["not_analysed"],
        "resolvedSymbolResolutionDenominator": resolved_calls["reachable"] + resolved_calls["unknown"],
        "resolvedSymbolResolutionRate": rate(resolved_calls["reachable"], resolved_calls["unknown"]),
        "unresolvedCallRecords": len(records) - sum(resolved_calls.values()),
        "possibleSyntheticMarkers": sum(r["possibleSyntheticMarker"] for r in records),
        "unknownByCause": dict(sorted(causes.items())),
        "analysis": graph["analysis"], "analyser": graph["analyser"],
        "coverage": coverage, "parseFailures": graph["parseFailures"],
        "unanalysedOccurrenceReasons": dict(sorted(Counter(
            o["reason"] for o in graph["unanalysedOccurrences"]).items())),
        "unresolvedImportsWithoutCallRecords": sum(
            o["resolution"] == "unresolved" and not o["callSites"]
            for o in graph["observations"]),
    }
    return metrics, records


def run(args, log, env=None, allowed=(0,), cwd=ROOT, timeout=900):
    result = subprocess.run([str(a) for a in args], cwd=cwd, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=timeout, check=False)
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(result.stdout)
    if result.returncode not in allowed:
        raise RuntimeError(f"exit {result.returncode}: {args[0]} (see {log})")
    return result


def git(*args, cwd=ROOT):
    return subprocess.check_output(["git", *args], cwd=cwd, text=True).strip()


def validate(canonical, graph):
    spec = importlib.util.spec_from_file_location("contract_validator", ROOT / "contracts/validate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not module.HAVE_JSONSCHEMA:
        raise RuntimeError("jsonschema is required; install contracts/requirements.txt in a venv")
    for name, doc in (("canonical-scan", canonical), ("usage-graph", graph)):
        schema = json.loads((ROOT / "contracts" / f"{name}.schema.json").read_text())
        module.Draft202012Validator(schema).validate(doc)
    canon = module.validate_canonical(canonical)
    module.validate_usage_graph(graph, canon)
    if module.errors:
        raise ValueError("contract invariants: " + "; ".join(module.errors))
    return {"schemaValidation": "PASS", "invariantChecks": module.checks}


def report(manifest):
    lines = ["# Issue #152 — reachability evaluation", "",
             f"Analyser checkout: `{manifest['analyserGitCommit']}`.", "",
             "Production `scan` (inventory only) → `usage`; no package install or execution, Grype, localisation or risk decision is performed.",
             "This measures statically resolved paths to third-party calls, not exploitability or paths inside dependency source.", "",
             "## Denominators", "",
             "Primary rate = reachable / (reachable + unknown) over emitted contract call records. These records include conservative unresolved-use markers and may duplicate a source expression across observations. They are not a census of runtime calls.",
             "Secondary rate uses only records with resolved call symbols. It excludes unresolved calls/markers and therefore describes a narrower subset. Neither rate includes not_analysed; zero denominator is N/A.",
             "Unseen calls in parse failures, skipped source, unsupported syntax or dependency internals cannot be counted in either denominator. Read coverage alongside every rate. Import-only unresolved observations are reported separately.", "",
             "## Repository results", "",
             "| Repository | Commit | Status | Entries | Resolved | Unknown | Not analysed | Denominator | Rate | Resolved-symbol subset rate |",
             "|---|---|---|---:|---:|---:|---:|---:|---:|---:|"]
    def pct(value):
        return "N/A" if value is None else f"{value:.2%}"
    for row in manifest["results"]:
        m = row["metrics"]
        lines.append(f"| {row['id']} | `{row['commit']}` | {m['analysis']['status']} | {m['entryPointsDetected']} | {m['reachable']} | {m['unknown']} | {m['notAnalysed']} | {m['resolutionDenominator']} | {pct(m['resolutionRate'])} | {pct(m['resolvedSymbolResolutionRate'])} |")
    for row in manifest["results"]:
        m = row["metrics"]
        lines += ["", f"## {row['id']}", "", f"Roles: {', '.join(row['roles'])}.",
                  f"Unknown categories: `{json.dumps(m['unknownByCause'], sort_keys=True)}`.",
                  f"Files: {m['coverage']['filesDiscovered']} discovered, {m['coverage']['filesParsed']} parsed, {m['coverage']['filesParsedWithErrors']} with syntax errors, {m['coverage']['filesFailed']} failed, {m['coverage']['filesSkipped']} skipped.",
                  f"Limits hit: `{m['coverage']['limitsHit']}`. Unresolved imports without call records: {m['unresolvedImportsWithoutCallRecords']}.",
                  f"Possible synthetic-marker records: {m['possibleSyntheticMarkers']}. This is a location-based review aid, not an exact identification.",
                  f"See `{row['id']}/call-records.json` for every path, location and classification; `{row['id']}/metrics.json` for counters, grammar versions and coverage."]
    lines += ["", "## Ground truth and limitations", "",
              "The existing four frozen reachability fixtures are checked separately in `fixture-tests.jsonl`: cross-file direct path, disconnected function, callback indirection and route handler. These are controlled correctness checks, not independently labelled real-repository accuracy estimates.",
              "Unknown categories describe the first blocking condition observable in public output; they are not mutually exhaustive root causes. `no_resolved_entry_point_path` does not prove callback, dynamic dispatch or unreachability. Specific construct explanations require source review at saved locations before final submission.",
              "The pinned demonstration repository and one audit repository are the same source and commit: one run covers both roles. No aggregate rate double-counts it.",
              "Issue #172 remains a safety dependency: application-only analysis cannot exclude dependency-internal use of direct-but-unimported packages. These measurements do not validate downstream downgrades. No unsafe negative result is ruled out by this evaluation.",
              "Issue #151 scope decisions are unchanged. Any subsequent change affecting analysis requires rerunning affected measurements.", "",
              "## Reproduction", "",
              "Use the exact saved config and analyser commit. Run `python3 -B scripts/evaluate_reachability.py --config CONFIG --work-dir CACHE --out NEW_OUTPUT`. The output directory must be new. Each source checkout must match its full SHA and be clean. The runner saves commands, exit codes, schema/invariant validation and SHA-256 hashes. It repeats usage with the identical canonical input and requires byte-identical graphs.",
              "Saved canonical inventory is unmodified production output. A missing lockfile leaves range-only installed versions unknown; these must not be represented as resolved installed versions.",
              "Evaluation evidence is provisional until construct-level source review, required full checks and paired-owner review are complete. This report alone does not close #152."]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    repos = config["repositories"]
    expected_ids = {"kirill89-prototype-pollution-explained", "juice-shop", "appsecco-dvna", "gitaalekhyapaul-vuln-app"}
    if {r["id"] for r in repos} != expected_ids or len(repos) != 4:
        raise ValueError("config must contain exactly the four unique evaluation repositories")
    for repo in repos:
        if not re.fullmatch(r"[0-9a-f]{40}", repo["commit"]):
            raise ValueError(f"full pinned SHA required: {repo['id']}")
    args.out = args.out.resolve()
    args.work_dir = args.work_dir.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    args.work_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        env.pop(name, None)
    env["CGO_ENABLED"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    manifest = {"issue": 152, "analyserGitCommit": git("rev-parse", "HEAD"),
                "analyserWorkingTreeStatus": git("status", "--porcelain", "--untracked-files=all"),
                "platform": platform.platform(), "config": config, "results": [],
                "runnerSha256": digest(Path(__file__)), "status": "running"}
    save(args.out / "manifest.json", manifest)
    source_paths = [p for p in git("ls-files", "cmd", "internal", "go.mod", "go.sum").splitlines() if (ROOT / p).is_file()]
    save(args.out / "analyser-source-hashes.json", {p: digest(ROOT / p) for p in source_paths})
    save(args.out / "config.json", config)
    binary = args.out / "sbomber"
    try:
        run(["go", "version"], args.out / "go-version.txt", env)
        run(["go", "build", "-o", binary, "./cmd/sbomber"], args.out / "build.log", env)
        manifest["binarySha256"] = digest(binary)
        run(["go", "test", "-json", "-count=1", "-run", "^TestFrozenUsageGroundTruth$", "./internal/usagegraph"], args.out / "fixture-tests.jsonl", env)
        fixture_events = [json.loads(line) for line in (args.out / "fixture-tests.jsonl").read_text().splitlines() if line.startswith("{")]
        fixture_passes = [e.get("Test", "") for e in fixture_events if e.get("Action") == "pass" and e.get("Test", "").startswith("TestFrozenUsageGroundTruth/")]
        if len(fixture_passes) != 4:
            raise RuntimeError(f"expected four frozen fixture passes, got {fixture_passes}")
        manifest["frozenFixturePasses"] = fixture_passes
        for repo in repos:
            print(f"Evaluating {repo['id']} at {repo['commit']}", flush=True)
            folder = args.out / repo["id"]
            folder.mkdir()
            checkout = args.work_dir / repo["id"]
            if not checkout.exists():
                run(["git", "clone", "--quiet", "--no-checkout", repo["url"], checkout], folder / "clone.log", env)
                run(["git", "-C", checkout, "checkout", "--quiet", "--detach", repo["commit"]], folder / "checkout.log", env)
            if git("rev-parse", "HEAD", cwd=checkout) != repo["commit"]:
                raise ValueError(f"existing checkout has wrong commit: {checkout}")
            if git("status", "--porcelain", "--untracked-files=all", "--ignored", cwd=checkout):
                raise ValueError(f"existing checkout has changed, untracked or ignored files: {checkout}")
            repoenv = env.copy()
            repoenv["SOURCE_DATE_EPOCH"] = git("log", "-1", "--format=%ct", cwd=checkout)
            canonical_file, graph_file = folder / "canonical-scan.json", folder / "usage-graph.json"
            scan_cmd = [str(binary), "scan", "--no-color", "--canonical-scan", str(canonical_file), "--", str(checkout)]
            scan = run(scan_cmd, folder / "scan.log", repoenv, allowed=(0, 2))
            if not canonical_file.exists():
                raise RuntimeError(f"scan produced no canonical output: {repo['id']}")
            usage_cmd = [str(binary), "usage", "--canonical-scan", str(canonical_file), "--out", str(graph_file), "--max-files", "10000", "--max-file-bytes", "1000000"]
            usage = run(usage_cmd, folder / "usage.log", repoenv, allowed=(0, 2))
            canonical = json.loads(canonical_file.read_text())
            graph = json.loads(graph_file.read_text())
            if len(canonical["scan"]["repositories"]) != 1:
                raise ValueError("expected one source repository per evaluation")
            if usage.returncode != (0 if graph["analysis"]["status"] == "complete" else 2):
                raise ValueError("usage exit code contradicts analysis status")
            validation = validate(canonical, graph)
            metrics, records = summarise(graph)
            repeat_file = folder / "usage-graph-repeat.json"
            repeat_cmd = usage_cmd.copy()
            repeat_cmd[repeat_cmd.index("--out") + 1] = str(repeat_file)
            run(repeat_cmd, folder / "usage-repeat.log", repoenv, allowed=(usage.returncode,))
            if graph_file.read_bytes() != repeat_file.read_bytes():
                raise ValueError(f"non-deterministic usage output: {repo['id']}")
            repeat_file.unlink()
            save(folder / "metrics.json", metrics)
            save(folder / "call-records.json", records)
            provenance = {**repo, "metrics": metrics, "validation": validation,
                          "commands": [scan_cmd, usage_cmd, repeat_cmd],
                          "scanExitCode": scan.returncode, "usageExitCode": usage.returncode,
                          "sourceDateEpoch": repoenv["SOURCE_DATE_EPOCH"],
                          "canonicalSha256": digest(canonical_file), "graphSha256": digest(graph_file),
                          "deterministicRepeat": "PASS"}
            save(folder / "provenance.json", provenance)
            manifest["results"].append(provenance)
            save(args.out / "manifest.json", manifest)
        manifest["status"] = "measured_pending_source_review_and_full_checks"
        save(args.out / "manifest.json", manifest)
        (args.out / "report.md").write_text(report(manifest))
        print(f"Saved evidence: {args.out}", flush=True)
    except Exception as exc:
        manifest["status"] = "failed"
        manifest["error"] = str(exc)
        save(args.out / "manifest.json", manifest)
        raise
    finally:
        # Binaries are reproducible intermediates, never committed evidence.
        if binary.exists():
            binary.unlink()


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
