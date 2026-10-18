#!/usr/bin/env python3
"""S6-07: check the provenance of the ten frozen cases, offline.

    python3 spikes/localisation/verify_provenance.py           # verify, exit 1 on a broken trace
    python3 spikes/localisation/verify_provenance.py --write   # also write results/provenance/VERIFICATION.md

Reads results/provenance/localisation.json (produced by `sbomber localise`,
schema 1.1.0) and cases/FROZEN.json (tag localisation-set-v1). For every
frozen case it checks that:

  1. every candidate cites at least one artefact in its result's provenance,
     and each cited artefact is verified, has a SHA-256, and (for a source
     file) a full commit SHA and git blob SHA;
  2. the commits the candidates were read from include at least one of the
     commits the frozen ground truth was read from;
  3. there is a tag check for the fixed and the vulnerable release, and the
     npm gitHead each one used is the gitHead pinned in FROZEN.json.

Re-downloading the artefacts is the online half and lives in the tool:
`sbomber localise --verify <file> --online`. Tag checks that are not
`verified` are reported as findings, not failures: they are honest records
about the advisory (for example a vulnerable release that already contains
a linked commit), not a broken trace.
"""

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FROZEN = HERE / "cases" / "FROZEN.json"
RESULTS = HERE / "results" / "provenance" / "localisation.json"
REPORT = HERE / "results" / "provenance" / "VERIFICATION.md"

SHA256 = re.compile(r"[0-9a-f]{64}")
SHA1 = re.compile(r"[0-9a-f]{40}")


def same_commit(a, b):
    return bool(a) and bool(b) and (a.startswith(b) or b.startswith(a))


def check_case(case, result):
    """Return (row, errors, findings) for one frozen case."""
    errors, findings = [], []
    cid = case["id"]
    if result is None:
        return None, [f"{cid}: no result in localisation.json"], []
    if result["purl"] != case["purl"] or result["vulnerabilityId"] != case["vulnerabilityId"]:
        errors.append(f"{cid}: result is for {result['vulnerabilityId']} {result['purl']}, "
                      f"frozen case is {case['vulnerabilityId']} {case['purl']}")

    prov = result.get("provenance") or {}
    arts = prov.get("artefacts", [])
    by_id = {a["id"]: a for a in arts if a.get("id")}
    if len(by_id) != len(arts):
        errors.append(f"{cid}: an artefact has no id or repeats one")

    cands = result.get("candidateSymbols", [])
    traced = 0
    read_from = set()
    for c in cands:
        ok = bool(c.get("evidence"))
        if not ok:
            errors.append(f"{cid}: candidate {c['symbol']} cites no artefact")
        for ref in c.get("evidence", []):
            a = by_id.get(ref)
            problem = None
            if a is None:
                problem = "is not in provenance.artefacts"
            elif not a.get("verified"):
                problem = f"is not verified ({a.get('note', 'no reason')})"
            elif not SHA256.fullmatch(a.get("sha256", "")):
                problem = "has no SHA-256"
            elif a.get("executed") is not False:
                problem = "does not record executed: false"
            elif a.get("kind") == "source_file" and not (
                    SHA1.fullmatch(a.get("commit", "")) and SHA1.fullmatch(a.get("gitBlobSha", ""))):
                problem = "lacks a full commit SHA or git blob SHA"
            if problem:
                errors.append(f"{cid}: candidate {c['symbol']} cites {ref}, which {problem}")
                ok = False
            elif a.get("kind") == "source_file":
                read_from.add(a["commit"])
        traced += ok

    answer = [s["sha"] for s in case["answerSource"]]
    tool_fixes = set()
    for tc in prov.get("tagChecks", []):
        tool_fixes.update(tc.get("fixCommits", []))
    shared = [s for s in answer if any(same_commit(s, f) for f in tool_fixes | read_from)]
    if not shared:
        errors.append(f"{cid}: candidates were read from none of the ground-truth commits {', '.join(s[:10] for s in answer)}")

    pinned = {a["version"]: a.get("gitHead") for a in case["artefacts"]}
    checks = {}
    for tc in prov.get("tagChecks", []):
        checks[tc["role"]] = tc
        want = pinned.get(tc["version"])
        got = tc.get("registryGitHead")
        if want and got and want != got:
            errors.append(f"{cid}: npm gitHead for {tc['version']} is {got[:10]}, FROZEN.json pinned {want[:10]}")
        if want and not got:
            errors.append(f"{cid}: tag check for {tc['version']} did not use the pinned gitHead {want[:10]}")
        if tc["result"] != "verified":
            findings.append(f"{cid} {tc['role']} {tc['version']}: {tc['result']}. {tc.get('note', '')}")
    for role in ("fixed", "vulnerable"):
        if role not in checks:
            errors.append(f"{cid}: no tag check for the {role} release")

    def tag(role):
        tc = checks.get(role)
        if not tc:
            return "missing"
        basis = f" ({tc['basis']})" if tc.get("basis") and tc["result"] == "verified" else ""
        return tc["result"] + basis

    row = {
        "id": cid,
        "case": f"{case['vulnerabilityId']} `{case['purl']}`",
        "traced": f"{traced}/{len(cands)}",
        "artefacts": len(arts),
        "answer": f"{len(shared)}/{len(answer)}",
        "fixed": tag("fixed"),
        "vulnerable": tag("vulnerable"),
    }
    return row, errors, findings


def render(rows, findings, doc):
    out = [
        "# Localisation provenance: the ten frozen cases (S6-07)",
        "",
        "Generated by `spikes/localisation/verify_provenance.py --write` from",
        "`results/provenance/localisation.json` (schema " + doc["schemaVersion"] + ") and",
        "`cases/FROZEN.json` (tag `localisation-set-v1`). The candidate sets are the",
        "same as the Sprint 4 run in `results/localisation.json`; this run adds the",
        "provenance. Localisation accuracy is not re-measured here.",
        "",
        "| Case | Advisory and package | Candidates traced | Artefacts | Ground-truth commits read | Fixed release | Vulnerable release |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        out.append(f"| {r['id']} | {r['case']} | {r['traced']} | {r['artefacts']} | {r['answer']} | {r['fixed']} | {r['vulnerable']} |")
    total = sum(int(r["traced"].split("/")[1]) for r in rows)
    ok = sum(int(r["traced"].split("/")[0]) for r in rows)
    out += [
        "",
        f"**{ok}/{total} candidates trace to a verified, checksummed artefact.**",
        "",
        "- *Candidates traced*: the candidate cites an artefact that is verified and has a",
        "  SHA-256 (and, for a source file, a full commit SHA and git blob SHA).",
        "- *Ground-truth commits read*: how many of the commits the frozen answer was",
        "  read from are among the commits the candidates were read from. An advisory",
        "  often links commits from other release lines too, so 1/3 can be complete.",
        "- *Fixed / vulnerable release*: the tag checks. `ancestry` means a linked",
        "  commit is an ancestor of the release commit; `content` means it is not (a",
        "  backport or squash merge) but every line it adds is in the release.",
        "",
        "The online half, re-downloading every artefact and comparing checksums, is",
        "`sbomber localise --verify results/provenance/localisation.json --online`;",
        "its output is `results/provenance/verification.json`.",
        "",
        "## Tag checks that did not verify",
        "",
    ]
    out += [f"- {f}" for f in findings] or ["None."]
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="write results/provenance/VERIFICATION.md")
    ap.add_argument("--results", default=str(RESULTS))
    args = ap.parse_args()

    frozen = json.loads(FROZEN.read_text())
    doc = json.loads(Path(args.results).read_text())
    errors, findings, rows = [], [], []
    if doc.get("schemaVersion") != "1.1.0":
        errors.append(f"localisation.json is {doc.get('schemaVersion')}; provenance needs 1.1.0")
    results = {r["findingId"]: r for r in doc.get("results", [])}
    for case in frozen["cases"]:
        row, errs, finds = check_case(case, results.get(case["id"]))
        errors += errs
        findings += finds
        if row:
            rows.append(row)
    if len(results) != len(frozen["cases"]):
        errors.append(f"{len(results)} results for {len(frozen['cases'])} frozen cases")

    report = render(rows, findings, doc)
    if args.write:
        REPORT.write_text(report)
        print(f"wrote {REPORT.relative_to(HERE.parent.parent)}")
    elif Path(args.results) == RESULTS and (not REPORT.exists() or REPORT.read_text() != report):
        errors.append("results/provenance/VERIFICATION.md is stale; re-run with --write")
    for f in findings:
        print("finding: " + f)
    if errors:
        print(f"FAIL - {len(errors)} problem(s)")
        for e in errors:
            print("  " + e)
        sys.exit(1)
    print(f"OK - provenance verifies for all {len(rows)} frozen cases")


if __name__ == "__main__":
    main()
