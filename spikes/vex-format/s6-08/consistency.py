#!/usr/bin/env python3
"""S6-08 (#154): do the outputs of one real run agree, and does the pinned
consumer act on the VEX statements?

    python3 consistency.py <results-dir>            # print CONSISTENCY.md, exit 1 on a problem
    python3 consistency.py <results-dir> --check    # also fail if CONSISTENCY.md is stale

Offline: it reads the files run.sh wrote. Checks:

  1. Identity: every canonical-scan finding has exactly one decision, one row
     in the HTML report, one entry in the text report and one statement in
     each VEX document, with the same vulnerability and package, and nothing
     appears that the scan did not report.
  2. State: the HTML and text reports show the decision's state, and each VEX
     statement has the status the decision's vexMapping names (usage_detected
     -> affected, everything else -> under_investigation; never not_affected).
  3. Every VEX document validates against OpenVEX 0.2.0.
  4. No finding is silently missing from the human report, whatever its
     state (unknown and unsupported included).
  5. contracts/validate.py passes on the run's four contract files.
  6. The pinned consumer (Grype 0.112.0, every finding ignored by rule,
     vex-add: [under_investigation]) re-adds exactly the findings whose
     statement is under_investigation, and nothing else. The package-subject
     document must do this. The application-subject document is reported
     either way: at these pinned versions Grype does not match it (#128).
"""

import html
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
OPENVEX_SCHEMA = ROOT / "spikes" / "vex-format" / "samples" / "openvex_json_schema_0.2.0.json"
SUBJECTS = ("application", "package")
EXPECTED_STATUS = {"usage_detected": "affected", "no_usage_detected": "under_investigation",
                   "unknown": "under_investigation", "unsupported": "under_investigation"}

ROW = re.compile(r'<tr data-finding-id="([^"]+)">\s*<td class="id">([^<]+)</td>\s*<td>([a-z_]+),', re.S)
TEXT_PKG = re.compile(r"^(pkg:\S+) \(installed ")
TEXT_FINDING = re.compile(r"^\s+- (\S+) \[([a-z_]+),")


def load(out, name):
    return json.loads((out / name).read_text())


def statement_key(st, subject):
    names = {st["vulnerability"]["name"], *st["vulnerability"].get("aliases", [])}
    purls = []
    for p in st.get("products", []):
        if subject == "package":
            purls.append(p["@id"])
        else:
            purls += [s["@id"] for s in p.get("subcomponents", [])]
    return names, purls


def check(out):
    errors, notes = [], []
    canon = load(out, "canonical-scan.json")
    decisions = {d["findingId"]: d for d in load(out, "decision-results.json")["decisions"]}
    findings = {f["findingId"]: f for f in canon["findings"]}

    # 1/4. decisions and both reports cover every finding exactly once.
    if set(decisions) != set(findings):
        errors.append(f"decisions {sorted(set(decisions) ^ set(findings))} do not match the scan's findings")
    rows = {}
    for fid, vuln, state in ROW.findall((out / "report.html").read_text()):
        if fid in rows:
            errors.append(f"{fid} appears twice in report.html")
        rows[fid] = (html.unescape(vuln).strip(), state)
    text = {}
    pkg = None
    for line in (out / "report.txt").read_text().splitlines():
        if m := TEXT_PKG.match(line):
            pkg = m.group(1)
        elif (m := TEXT_FINDING.match(line)) and pkg:
            key = (m.group(1), pkg)
            if key in text:
                errors.append(f"{key[0]} on {pkg} appears twice in report.txt")
            text[key] = m.group(2)

    table = []
    for fid, f in sorted(findings.items()):
        d = decisions.get(fid)
        if d is None:
            continue
        state, vuln, purl = d["state"], f["vulnerabilityId"], f["purl"]
        if (d.get("vulnerabilityId", vuln), d.get("purl", purl)) != (vuln, purl):
            errors.append(f"{fid}: decision is for {d.get('vulnerabilityId')} {d.get('purl')}, scan says {vuln} {purl}")
        h = rows.get(fid)
        if h is None:
            errors.append(f"{fid} ({vuln}, {state}) is missing from report.html")
        elif h != (vuln, state):
            errors.append(f"{fid}: report.html shows {h[0]} {h[1]}, decision is {vuln} {state}")
        t = text.get((vuln, purl))
        if t is None:
            errors.append(f"{fid} ({vuln} on {purl}, {state}) is missing from report.txt")
        elif t != state:
            errors.append(f"{fid}: report.txt shows {t}, decision is {state}")
        want = (d.get("vexMapping") or {}).get("statement") or EXPECTED_STATUS.get(state)
        if want != EXPECTED_STATUS.get(state):
            errors.append(f"{fid}: decision maps {state} to {want}, policy says {EXPECTED_STATUS.get(state)}")
        table.append({"fid": fid, "vuln": vuln, "purl": purl, "state": state, "want": want,
                      "aliases": set(f.get("aliases", [])) | {vuln}})
    for fid in sorted(set(rows) - set(findings)):
        errors.append(f"report.html has a row for {fid}, which the scan did not report")
    known = {(r["vuln"], r["purl"]) for r in table}
    for key in sorted(set(text) - known):
        errors.append(f"report.txt lists {key[0]} on {key[1]}, which the scan did not report")

    # 1/2/3. VEX documents.
    try:
        from jsonschema import validators
        schema = json.loads(OPENVEX_SCHEMA.read_text())
        validator = validators.validator_for(schema)(schema)
    except ImportError:
        validator = None
        errors.append("jsonschema is not installed, so the OpenVEX documents were not validated")
    vex_status = {}
    for subject in SUBJECTS:
        doc = load(out, f"demo-app.{subject}.openvex.json")
        if validator:
            for e in validator.iter_errors(doc):
                errors.append(f"{subject} VEX is not valid OpenVEX 0.2.0: {'/'.join(map(str, e.path))}: {e.message}")
        seen = {}
        for st in doc.get("statements", []):
            names, purls = statement_key(st, subject)
            if st.get("status") == "not_affected":
                errors.append(f"{subject} VEX asserts not_affected for {st['vulnerability']['name']}")
            matched = [r for r in table if r["vuln"] in names and r["purl"] in purls]
            if len(matched) != 1:
                errors.append(f"{subject} VEX statement {st['vulnerability']['name']} on {purls} matches "
                              f"{len(matched)} findings")
                continue
            r = matched[0]
            if r["fid"] in seen:
                errors.append(f"{subject} VEX has two statements for {r['fid']}")
            seen[r["fid"]] = st["status"]
            if st["status"] != r["want"]:
                errors.append(f"{subject} VEX says {st['status']} for {r['fid']}, decision maps to {r['want']}")
        for r in table:
            if r["fid"] not in seen:
                errors.append(f"{subject} VEX has no statement for {r['fid']} ({r['vuln']})")
        vex_status[subject] = seen

    # 5. contract invariants on the real files.
    v = subprocess.run([sys.executable, str(ROOT / "contracts" / "validate.py"), "--dir", str(out),
                        "--vex-decision", str(ROOT / "contracts" / "fixtures" / "vex-decision.json")],
                       capture_output=True, text=True)
    contract = (v.stdout.strip().splitlines() or ["no output"])[-1] if v.returncode == 0 else v.stdout.strip()
    if v.returncode != 0:
        errors.append("contracts/validate.py failed on the run: " + contract.replace("\n", " | ")[:600])

    # 6. the pinned consumer.
    def grype_ids(name):
        return sorted({m["vulnerability"]["id"] for m in load(out, name)["matches"]})
    baseline = grype_ids("grype-consumer-baseline.json")
    if baseline:
        errors.append(f"the ignore-all baseline still reports {baseline}")
    under = {r["fid"] for r in table if r["want"] == "under_investigation"}
    ghsa = {}
    for m in load(out, "grype.json")["matches"]:
        ids = {m["vulnerability"]["id"], *[x["id"] for x in m.get("relatedVulnerabilities", [])]}
        for r in table:
            if r["aliases"] & ids and r["purl"] == m["artifact"]["purl"]:
                ghsa[m["vulnerability"]["id"]] = r["fid"]
    want_readded = sorted(g for g, fid in ghsa.items() if fid in under)
    consumer = {}
    for subject in SUBJECTS:
        got = grype_ids(f"grype-consumer-{subject}.json")
        consumer[subject] = got
        if subject == "package" and got != want_readded:
            errors.append(f"package VEX: Grype re-added {got}, expected exactly the under_investigation findings {want_readded}")
    if consumer["application"] != want_readded:
        notes.append(f"application-subject VEX: Grype re-added {consumer['application'] or 'nothing'}; it does not act on "
                     "the R5 rule-1 shape at the pinned version (recorded limitation of the #128 decision)")

    return {"table": table, "vex": vex_status, "consumer": consumer, "want_readded": want_readded,
            "baseline": baseline, "contract": contract, "errors": errors, "notes": notes,
            "grype": load(out, "grype.json")["descriptor"]["version"]}


def render(r):
    t = r["table"]
    counts = {}
    for row in t:
        counts[row["state"]] = counts.get(row["state"], 0) + 1
    out = [
        "# S6-08: VEX consistency on real decide output (#154)",
        "",
        "Generated by `spikes/vex-format/s6-08/consistency.py` from the files `run.sh` wrote for the",
        "demo app (`demo-app/`). The scan step is a bridge (`build_canonical_scan.py`) until",
        "Component 1's canonical-scan writer lands (#121, #146); everything after it is the real",
        "tool: `usage`, `localise`, `decide`, `report`, `vex`.",
        "",
        f"**{len(t)} findings** from Grype {r['grype']}: " +
        ", ".join(f"{n} {s}" for s, n in sorted(counts.items())) + ".",
        "",
        "| Finding | Vulnerability | Package | Decision | HTML / text report | VEX (application, package) |",
        "|---|---|---|---|---|---|",
    ]
    for row in t:
        out.append(f"| {row['fid']} | {row['vuln']} | `{row['purl']}` | {row['state']} | same | "
                   f"{r['vex']['application'].get(row['fid'], 'missing')}, {r['vex']['package'].get(row['fid'], 'missing')} |")
    out += [
        "",
        "## Checks",
        "",
        "- Identity: every finding has one decision, one HTML row, one text entry and one statement per",
        "  VEX document, for the same vulnerability and package; nothing extra appears.",
        "- State: both reports show the decision's state; every statement has the status the decision maps",
        "  to (`usage_detected` -> `affected`, otherwise `under_investigation`; never `not_affected`).",
        "- Both VEX documents validate against OpenVEX 0.2.0.",
        "- No finding is missing from the human report, including `unknown` ones.",
        f"- `contracts/validate.py` on the run: {r['contract']}",
        "",
        "## Does the pinned consumer act on the statements?",
        "",
        "Grype with every finding ignored by rule and `vex-add: [under_investigation]`: a finding comes",
        "back only if a statement matches it.",
        "",
        f"- Baseline, no VEX: {', '.join(r['baseline']) or 'nothing'} reported.",
        f"- Package-subject VEX: re-adds {', '.join(r['consumer']['package']) or 'nothing'}, exactly the",
        f"  `under_investigation` findings ({', '.join(r['want_readded'])}); the `affected` ones stay ignored.",
        f"- Application-subject VEX (R5 rule 1): re-adds {', '.join(r['consumer']['application']) or 'nothing'}.",
        "",
    ]
    if r["notes"]:
        out += ["**Finding:** " + n for n in r["notes"]] + [""]
    if r["errors"]:
        out += ["## Problems", ""] + [f"- {e}" for e in r["errors"]] + [""]
    else:
        out += ["No problems.", ""]
    return "\n".join(out)


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    out = Path(sys.argv[1]).resolve()
    r = check(out)
    report = render(r)
    print(report, end="")
    stale = False
    if "--check" in sys.argv[2:]:
        md = out / "CONSISTENCY.md"
        stale = not md.exists() or md.read_text() != report
        if stale:
            print("CONSISTENCY.md is stale; re-run run.sh or regenerate it", file=sys.stderr)
    sys.exit(1 if r["errors"] or stale else 0)


if __name__ == "__main__":
    main()
