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
    if sha256(CASES) != frozen["casesSha256"]:
        problems.append("cases.json changed since the freeze (SHA-256 mismatch)")
    ids = [c["id"] for c in cases["cases"]]
    if ids != [c["id"] for c in frozen["cases"]]:
        problems.append(f"case list changed: {ids}")
    for want in frozen["cases"]:
        if not want["answerSource"]:
            problems.append(f"{want['id']}: no source recorded for the expected answer")
        if not want["expectedChangedFunctions"] or not want["expectedPublicSymbols"]:
            problems.append(f"{want['id']}: expected answer missing")
        for art in want["artefacts"]:
            if not art.get("integrity"):
                problems.append(f"{want['id']}: {art['tarball']} has no integrity hash")
        if online:
            package = want["purl"].split("/", 1)[1].rsplit("@", 1)[0]
            for art in want["artefacts"]:
                live = registry_version(urllib.parse.unquote(package), art["version"])
                if live["integrity"] != art["integrity"]:
                    problems.append(f"{want['id']}: registry integrity changed for {art['tarball']}")
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
