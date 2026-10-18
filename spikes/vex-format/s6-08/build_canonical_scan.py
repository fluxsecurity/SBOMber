#!/usr/bin/env python3
"""S6-08 bridge: canonical-scan.json for the demo app from its lockfile and a
real Grype run.

    python3 build_canonical_scan.py <app-dir> <grype.json> <out.json>

This stands in for Component 1's canonical-scan writer, which is not on main
yet (#121, #146). It is deliberately small: npm lockfile v2/v3 only, one
repository, every package a direct or transitive occurrence at its install
path. Everything after it in run.sh is the real tool. Replace it with
Component 1's output when it lands, then rerun the consistency checks. Finding
counts and identities may change.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def purl(name, version):
    return f"pkg:npm/{name.replace('@', '%40', 1) if name.startswith('@') else name}@{version}"


def main(app_dir, grype_path, out_path):
    app = Path(app_dir)
    manifest = json.loads((app / "package.json").read_text())
    lock = json.loads((app / "package-lock.json").read_text())
    if lock.get("lockfileVersion", 0) < 2:
        sys.exit("lockfile v2 or v3 needed")
    direct = {**manifest.get("dependencies", {}), **manifest.get("devDependencies", {})}
    dev = set(manifest.get("devDependencies", {}))

    components, occurrences, occ_by_purl = [], [], {}
    for install_path, pkg in sorted(lock["packages"].items()):
        if not install_path.startswith("node_modules/"):
            continue
        name = pkg.get("name") or install_path.rsplit("node_modules/", 1)[1]
        version = pkg["version"]
        p = purl(name, version)
        if p not in occ_by_purl:
            comp = {"purl": p, "ecosystem": "npm", "name": name, "version": version, "versionKnown": True}
            # An exact pin is not a constraint (R0: never store the
            # constraint as the version), so only a real range is recorded.
            if name in direct and direct[name] != version:
                comp["declaredConstraint"] = direct[name]
            components.append(comp)
        is_direct = install_path == f"node_modules/{name}" and name in direct
        occ = {
            "occurrenceId": f"occ-{len(occurrences) + 1:03d}",
            "purl": p,
            "repositoryId": "repo-demo-app",
            "manifest": "package.json",
            "relationship": "direct" if is_direct else "transitive",
            "dependencyPath": [],
            "installPath": install_path,
            "scope": "development" if pkg.get("dev") or name in dev else "runtime",
        }
        occurrences.append(occ)
        occ_by_purl.setdefault(p, []).append(occ["occurrenceId"])

    grype = json.loads(Path(grype_path).read_text())
    grype_version = grype["descriptor"]["version"]
    findings, seen = [], set()
    for m in sorted(grype["matches"], key=lambda m: (m["artifact"]["purl"], m["vulnerability"]["id"])):
        v, a = m["vulnerability"], m["artifact"]
        cves = [r["id"] for r in m.get("relatedVulnerabilities", []) if r["id"].startswith("CVE-")]
        vuln_id = cves[0] if cves else v["id"]
        key = (vuln_id, a["purl"])
        if key in seen:
            continue
        seen.add(key)
        aliases = sorted({v["id"], *[r["id"] for r in m.get("relatedVulnerabilities", [])]} - {vuln_id})
        f = {
            "findingId": f"find-{len(findings) + 1:03d}",
            "vulnerabilityId": vuln_id,
            "aliases": aliases,
            "purl": a["purl"],
            "occurrenceIds": occ_by_purl.get(a["purl"], []),
            "severity": v.get("severity", "unknown").lower(),
            "provenance": {"scanner": "grype", "scannerVersion": grype_version},
        }
        fixes = v.get("fix", {}).get("versions") or []
        if fixes:
            f["fixedVersion"] = fixes[0]
        findings.append(f)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc = {
        "schemaVersion": "1.0.0",
        "scan": {
            "scanId": "scan-s6-08-demo-app",
            "startedAt": now,
            "completedAt": now,
            "toolVersions": {"grype": grype_version, "bridge": "spikes/vex-format/s6-08/build_canonical_scan.py"},
            "status": "complete",
            "statusDetail": {"skippedFiles": [], "failedFiles": [], "truncatedTree": False, "limitsHit": []},
            "repositories": [{"repositoryId": "repo-demo-app", "path": "demo-app", "source": "local"}],
            "enrichment": [{"source": s, "status": "skipped", "detail": "not run by the S6-08 bridge; Component 1 enriches"}
                           for s in ("epss", "cisa_kev", "registry", "malware")],
        },
        "components": components,
        "occurrences": occurrences,
        "findings": findings,
        "supplyChainWarnings": [],
    }
    Path(out_path).write_text(json.dumps(doc, indent=2) + "\n")
    print(f"canonical-scan.json: {len(components)} components, {len(occurrences)} occurrences, {len(findings)} findings")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
