#!/usr/bin/env python3
"""S5-13: freeze the labelled localisation set.

    python3 spikes/localisation/freeze.py --write    # create cases/FROZEN.json
    python3 spikes/localisation/freeze.py            # verify offline
    python3 spikes/localisation/freeze.py --online   # also re-check the registry

The ground truth in cases/cases.json is not edited by freezing. FROZEN.json
records the SHA-256 of that file plus, for every case, the fix commits the
expected answer was read from and the npm tarballs of both versions with the
integrity hash the registry publishes. Verification fails if cases.json has
changed by a single byte, if a case was added or dropped, or (with --online)
if the registry no longer serves the pinned artefact.

Only registry metadata is fetched. No tarball is downloaded or executed.
"""

import argparse
import hashlib
import json
import sys
import urllib.parse
import urllib.request
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES = HERE / "cases" / "cases.json"
FROZEN = HERE / "cases" / "FROZEN.json"
REGISTRY = "https://registry.npmjs.org"
TAG = "localisation-set-v1"
FROZEN_CASES_SHA256 = "461ebc12548ee5babe01470a6e9c3ea5a4146eab7c65d342b7512fc2de728123"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def registry_version(package, version):
    url = f"{REGISTRY}/{urllib.parse.quote(package, safe='@')}/{version}"
    with urllib.request.urlopen(url, timeout=30) as resp:
        meta = json.load(resp)
    dist = meta.get("dist", {})
    pinned = {
        "version": version,
        "tarball": dist["tarball"],
        "integrity": dist.get("integrity"),
        "shasum": dist.get("shasum"),
    }
    if meta.get("gitHead"):
        pinned["gitHead"] = meta["gitHead"]
    return pinned


def build(cases):
    frozen_cases = []
    for c in cases["cases"]:
        frozen_cases.append({
            "id": c["id"],
            "vulnerabilityId": c["vulnerabilityId"],
            "purl": c["purl"],
            "expectedChangedFunctions": c["expectedChangedFunctions"],
            "expectedPublicSymbols": c["expectedPublicSymbols"],
            "answerSource": [
                {"repo": f["repo"], "sha": f["sha"], "source": f["source"]}
                for f in c["fixCommits"]
            ],
            "artefacts": [
                registry_version(c["package"], c["vulnerableVersion"]),
                registry_version(c["package"], c["fixedVersion"]),
            ],
        })
    return {
        "set": "S4-18 localisation evaluation cases",
        "tag": TAG,
        "frozenAt": date.today().isoformat(),
        "groundTruthFixedAt": cases["groundTruthFixedAt"],
        "casesFile": "cases/cases.json",
        "casesSha256": sha256(CASES),
        "caseCount": len(frozen_cases),
        "rule": "cases.json is frozen. Any change to an expected answer is a new set "
                "with a new tag, never an edit to this one.",
        "cases": frozen_cases,
    }


def verify(frozen, cases, online):
    problems = []

    case_list = cases.get("cases", [])
    frozen_cases = frozen.get("cases", [])

    # Top-level identity must remain consistent with the frozen set.
    if frozen.get("tag") != TAG:
        problems.append(f"tag changed: {frozen.get('tag')!r}")
    if frozen.get("casesFile") != "cases/cases.json":
        problems.append(f"casesFile changed: {frozen.get('casesFile')!r}")
    if frozen.get("groundTruthFixedAt") != cases.get("groundTruthFixedAt"):
        problems.append("groundTruthFixedAt does not match cases.json")
    if frozen.get("caseCount") != len(frozen_cases):
        problems.append(
            f"caseCount is {frozen.get('caseCount')}, but FROZEN.json contains {len(frozen_cases)} cases"
        )
    if len(case_list) != len(frozen_cases):
        problems.append(
            f"cases.json contains {len(case_list)} cases but FROZEN.json contains {len(frozen_cases)}"
        )

    actual_cases_sha = sha256(CASES)
    if actual_cases_sha != FROZEN_CASES_SHA256:
        problems.append(
            "cases.json does not match localisation-set-v1 "
            f"(got {actual_cases_sha[:12]}, want {FROZEN_CASES_SHA256[:12]})"
        )
    if frozen.get("casesSha256") != FROZEN_CASES_SHA256:
        problems.append(
            "FROZEN.json casesSha256 does not match localisation-set-v1"
        )

    ids = [c.get("id") for c in case_list]
    frozen_ids = [c.get("id") for c in frozen_cases]
    if ids != frozen_ids:
        problems.append(f"case list changed: {ids}")

    by_id = {c.get("id"): c for c in case_list}

    for want in frozen_cases:
        case_id = want.get("id")
        c = by_id.get(case_id, {})

        recorded = (
            c.get("vulnerabilityId"),
            c.get("purl"),
            c.get("expectedChangedFunctions"),
            c.get("expectedPublicSymbols"),
            [
                (f.get("repo"), f.get("sha"), f.get("source"))
                for f in c.get("fixCommits", [])
            ],
            [c.get("vulnerableVersion"), c.get("fixedVersion")],
        )

        pinned = (
            want.get("vulnerabilityId"),
            want.get("purl"),
            want.get("expectedChangedFunctions"),
            want.get("expectedPublicSymbols"),
            [
                (src.get("repo"), src.get("sha"), src.get("source"))
                for src in want.get("answerSource", [])
            ],
            [art.get("version") for art in want.get("artefacts", [])],
        )

        if recorded != pinned:
            problems.append(
                f"{case_id}: FROZEN.json identity, answer, source or versions do not match cases.json"
            )

        if not want.get("answerSource"):
            problems.append(f"{case_id}: no source recorded for the expected answer")

        if not want.get("expectedChangedFunctions") or not want.get("expectedPublicSymbols"):
            problems.append(f"{case_id}: expected answer missing")

        for src in want.get("answerSource", []):
            sha = src.get("sha", "")
            if len(sha) != 40 or any(ch not in "0123456789abcdefABCDEF" for ch in sha):
                problems.append(f"{case_id}: answer source does not use a full commit SHA: {sha!r}")

        artefacts = want.get("artefacts", [])
        if len(artefacts) != 2:
            problems.append(
                f"{case_id}: expected exactly two pinned artefacts, found {len(artefacts)}"
            )

        for art in artefacts:
            if not art.get("integrity"):
                problems.append(
                    f"{case_id}: {art.get('tarball', '<unknown tarball>')} has no integrity hash"
                )

        if online:
            purl = want.get("purl", "")
            try:
                package = purl.split("/", 1)[1].rsplit("@", 1)[0]
            except (IndexError, AttributeError):
                problems.append(f"{case_id}: invalid purl {purl!r}")
                continue

            for art in artefacts:
                try:
                    live = registry_version(
                        urllib.parse.unquote(package), art["version"]
                    )
                except (OSError, KeyError, ValueError) as e:
                    problems.append(
                        f"{case_id}: registry lookup failed for "
                        f"{art.get('tarball', '<unknown tarball>')}: {e}"
                    )
                    continue

                for field in ("tarball", "integrity", "shasum", "gitHead"):
                    if live.get(field) != art.get(field):
                        problems.append(
                            f"{case_id}: registry {field} changed for "
                            f"{art.get('tarball', '<unknown tarball>')}"
                        )

    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true", help="create FROZEN.json (refuses to overwrite)")
    ap.add_argument("--online", action="store_true", help="re-check pinned integrity against the registry")
    args = ap.parse_args()

    cases = json.loads(CASES.read_text())
    if args.write:
        if FROZEN.exists():
            sys.exit("FROZEN.json exists; a frozen set is not rewritten. Start a new set instead.")
        FROZEN.write_text(json.dumps(build(cases), indent=2) + "\n")
        print(f"wrote {FROZEN.relative_to(HERE.parent.parent)}")

    if not FROZEN.exists():
        sys.exit("FROZEN.json missing; run with --write to create it")
    frozen = json.loads(FROZEN.read_text())
    problems = verify(frozen, cases, args.online)
    for p in problems:
        print("FAIL", p)
    if problems:
        sys.exit(1)
    pinned = sum(len(c["artefacts"]) for c in frozen["cases"])
    print(f"OK {frozen['caseCount']} cases frozen at {frozen['frozenAt']}, "
          f"cases.json sha256 {frozen['casesSha256'][:12]}, {pinned} tarballs pinned"
          + (", registry re-checked" if args.online else ""))


if __name__ == "__main__":
    main()
