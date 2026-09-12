#!/usr/bin/env python3
"""Build a schema-valid canonical-scan.json from cases/cases.json.

The ten evaluation cases are expressed as one synthetic scan of an
application that directly depends on each vulnerable package, so that
`sbomber localise` reads exactly the contract Component 1 produces and the
output can be validated against contracts/localisation.schema.json.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
cases = json.load(open(HERE / "cases" / "cases.json"))["cases"]
schema = json.load(open(ROOT / "contracts" / "canonical-scan.schema.json"))
sample = json.load(open(ROOT / "contracts" / "fixtures" / "canonical-scan.sample.json"))

scan_id = "scan-2026-09-06-localisation-eval"
doc = {
    "schemaVersion": sample["schemaVersion"],
    "scan": dict(sample["scan"]),
    "components": [],
    "occurrences": [],
    "findings": [],
    "supplyChainWarnings": [],
}
doc["scan"]["scanId"] = scan_id
doc["scan"]["repositories"] = [dict(sample["scan"]["repositories"][0])]
doc["scan"]["repositories"][0]["repositoryId"] = "repo-eval"
doc["scan"]["repositories"][0].pop("name", None)
for k in ("root", "path"):
    if k in doc["scan"]["repositories"][0]:
        doc["scan"]["repositories"][0][k] = "spikes/localisation/cases"
doc["scan"]["repositories"][0]["commit"] = "0" * 40

comp_t = sample["components"][0]
occ_t = sample["occurrences"][0]
find_t = sample["findings"][0]

for i, c in enumerate(cases, 1):
    comp = {k: v for k, v in comp_t.items()}
    comp.update({"purl": c["purl"], "name": c["package"], "version": c["vulnerableVersion"], "ecosystem": "npm"})
    for k in list(comp):
        if k not in schema["properties"]["components"]["items"]["properties"]:
            del comp[k]
    doc["components"].append(comp)

    occ = {k: v for k, v in occ_t.items()}
    occ.update({"occurrenceId": f"occ-{i:03d}", "purl": c["purl"], "repositoryId": "repo-eval",
                "installPath": f"node_modules/{c['package']}", "relationship": "direct",
                "dependencyPath": [c["purl"]]})
    for k in list(occ):
        if k not in schema["properties"]["occurrences"]["items"]["properties"]:
            del occ[k]
    doc["occurrences"].append(occ)

    f = {k: v for k, v in find_t.items()}
    f.update({"findingId": c["id"], "vulnerabilityId": c["vulnerabilityId"], "aliases": c["aliases"],
              "purl": c["purl"], "occurrenceIds": [f"occ-{i:03d}"], "severity": "high",
              "fixedVersion": c["fixedVersion"]})
    for k in list(f):
        if k not in schema["properties"]["findings"]["items"]["properties"]:
            del f[k]
    for k in ("cvssScore", "epss", "cisaKev", "provenance"):
        f.pop(k, None)
    doc["findings"].append(f)

out = HERE / "cases" / "canonical-scan.json"
json.dump(doc, open(out, "w"), indent=2)
print("wrote", out)

try:
    from jsonschema import Draft202012Validator
    errs = list(Draft202012Validator(schema).iter_errors(doc))
    for e in errs:
        print("SCHEMA:", "/".join(map(str, e.path)), e.message)
    print("schema:", "VALID" if not errs else f"{len(errs)} error(s)")
    sys.exit(1 if errs else 0)
except ImportError:
    print("jsonschema not installed; schema check skipped")
