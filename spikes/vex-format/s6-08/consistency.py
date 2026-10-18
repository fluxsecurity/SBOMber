#!/usr/bin/env python3
"""S6-08 (#154): do the outputs of one real run agree, and does the pinned
consumer act on the VEX statements?

    python3 consistency.py <results-dir>            # print CONSISTENCY.md, exit 1 on a problem
    python3 consistency.py <results-dir> --check    # also fail if CONSISTENCY.md is stale

Offline: it reads the files run.sh wrote. Checks:

  1. Identity: every canonical-scan finding has exactly one decision, one row
     in the HTML report, one entry in the text report and, for supported
     findings, one statement in each VEX document, with the same vulnerability and package, and nothing
     appears that the scan did not report.
  2. State: the HTML and text reports show the decision's state, and each VEX
     statement has the status the decision's vexMapping names (usage_detected
     -> affected only when the decision guards allow it; uncertainty ->
     under_investigation; unsupported -> omitted; never not_affected).
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

from collections import Counter
from html.parser import HTMLParser
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
OPENVEX_SCHEMA = (
    ROOT / "spikes" / "vex-format" / "samples" / "openvex_json_schema_0.2.0.json"
)
SUBJECTS = ("application", "package")
EXPECTED_STATUS = {
    "usage_detected": "under_investigation",
    "no_usage_detected": "under_investigation",
    "unknown": "under_investigation",
    "unsupported": "omit",
}

TEXT_PKG = re.compile(r"^(pkg:\S+) \(installed ")
TEXT_FINDING = re.compile(r"^\s+- (\S+) \[([a-z_]+),")


class HTMLRows(HTMLParser):
    """Read finding cells together with their enclosing package heading."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.rows = []
        self.pkg = None
        self.heading = None
        self.fid = None
        self.cells = []
        self.cell = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "article":
            self.pkg = None
        if tag == "h3":
            self.heading = []
        if tag == "tr":
            self.fid = attrs.get("data-finding-id")
            self.cells = []
        if tag == "td":
            self.cell = []

    def handle_data(self, data):
        if self.heading is not None:
            self.heading.append(data)
        if self.cell is not None:
            self.cell.append(data)

    def handle_endtag(self, tag):
        if tag == "h3" and self.heading is not None:
            text = "".join(self.heading).strip().split()
            self.pkg = text[0] if text and text[0].startswith("pkg:") else None
            self.heading = None
        if tag == "td" and self.cell is not None:
            self.cells.append("".join(self.cell).strip())
            self.cell = None
        if tag == "tr" and (self.fid is not None or self.cells):
            vuln = self.cells[0] if self.cells else ""
            state = self.cells[1].split(",", 1)[0] if len(self.cells) > 1 else ""
            self.rows.append((self.fid or "", vuln, state, self.pkg))
        if tag == "article":
            self.pkg = None


def unique_index(records, label, errors):
    result = {}
    for record in records:
        key = record["findingId"]
        if key in result:
            errors.append(f"{label} has duplicate findingId {key}")
        result[key] = record
    return result


def expected_status(d, errors):
    state = d["state"]
    statement = (d.get("vexMapping") or {}).get("statement")
    if state == "usage_detected":
        # Mirrors vex.Map: positive usage alone does not prove affected.
        if statement in (None, "", "affected", "under_investigation"):
            return statement or "under_investigation"
    elif state in EXPECTED_STATUS:
        want = EXPECTED_STATUS[state]
        if statement in (None, "", want):
            return want
    errors.append(
        f"{d['findingId']}: decision maps {state} to {statement}, inconsistent with export policy"
    )
    return EXPECTED_STATUS.get(state, "invalid")


def grype_key(match):
    return match["vulnerability"]["id"], match["artifact"]["purl"]


def key_text(key):
    return f"{key[0]} on {key[1]}"


def check_consumers(out, table, errors, notes):
    original = load(out, "grype.json")
    original_keys = Counter(grype_key(m) for m in original["matches"])
    mapping = {}
    covered = set()
    for m in original["matches"]:
        ids = {
            m["vulnerability"]["id"],
            *[x["id"] for x in m.get("relatedVulnerabilities", [])],
        }
        matches = [
            r
            for r in table
            if r["aliases"] & ids and r["purl"] == m["artifact"]["purl"]
        ]
        if len(matches) != 1:
            errors.append(
                f"original Grype match {key_text(grype_key(m))} maps to {len(matches)} canonical findings"
            )
        else:
            fid = matches[0]["fid"]
            key = grype_key(m)
            if key in mapping and mapping[key] != fid:
                errors.append(f"ambiguous Grype identity {key_text(key)}")
            mapping[key] = fid
            covered.add(fid)
    for row in table:
        if row["fid"] not in covered:
            errors.append(
                f"{row['fid']}: no original Grype match for canonical finding"
            )
    under = {r["fid"] for r in table if r["want"] == "under_investigation"}
    expected = Counter(
        {k: n for k, n in original_keys.items() if mapping.get(k) in under}
    )
    docs = {"scan": original, "baseline": load(out, "grype-consumer-baseline.json")}
    docs.update({s: load(out, f"grype-consumer-{s}.json") for s in SUBJECTS})
    db = original["descriptor"].get("db", {})
    status = db.get("status", {})
    if status.get("valid") is not True or not all(
        status.get(k) for k in ["schemaVersion", "from", "built"]
    ):
        errors.append("original scan has incomplete or invalid database provenance")
    if original.get("source", {}).get("type") != "directory" or not original.get(
        "source", {}
    ).get("target"):
        errors.append("original scan has no directory source identity")

    def database_identity(value):
        status = value.get("status", {})
        return {
            k: status.get(k) for k in ["schemaVersion", "from", "built", "valid"]
        }, value.get("providers")

    base_config = docs["baseline"]["descriptor"].get("configuration", {})

    ignored_ids = {
        r.get("vulnerability")
        for r in base_config.get("ignore", [])
        if r.get("vulnerability")
    }
    if not {key[0] for key in original_keys} <= ignored_ids:
        errors.append(
            "baseline does not configure ignore rules for every original finding"
        )

    def fixed_config(config):
        result = {
            k: v for k, v in config.items() if k not in ["vex-documents", "ignore"]
        }
        result["ignore"] = [
            r for r in config.get("ignore", []) if not r.get("vex-status")
        ]
        return result

    consumer = {}
    for subject, doc in docs.items():
        desc = doc["descriptor"]
        if desc.get("name") != "grype" or desc.get("version") != "0.112.0":
            errors.append(f"{subject}: expected pinned Grype 0.112.0")
        if database_identity(desc.get("db", {})) != database_identity(db):
            errors.append(
                f"{subject}: Grype database identity differs from the original scan"
            )
        if doc.get("source") != original.get("source"):
            errors.append(f"{subject}: Grype source differs from the original scan")
        if subject == "scan":
            continue
        config = desc.get("configuration", {})
        documents = config.get("vex-documents", [])
        if subject == "baseline":
            if documents:
                errors.append("baseline unexpectedly loaded a VEX document")
        elif (
            len(documents) != 1
            or Path(documents[0]).name != f"demo-app.{subject}.openvex.json"
        ):
            errors.append(f"{subject}: consumer did not load the expected VEX document")
        if config.get("vex-add") != ["under_investigation"] or fixed_config(
            config
        ) != fixed_config(base_config):
            errors.append(
                f"{subject}: consumer configuration differs from the ignore-all baseline"
            )
        live = Counter(grype_key(m) for m in doc["matches"])
        ignored = Counter(grype_key(m) for m in doc.get("ignoredMatches", []))
        if live + ignored != original_keys:
            errors.append(
                f"{subject}: consumer match/ignored inventory differs from original vulnerability/package identities"
            )
        if any(not m.get("appliedIgnoreRules") for m in doc.get("ignoredMatches", [])):
            errors.append(f"{subject}: ignored finding has no recorded ignore rule")
        consumer[subject] = sorted(key_text(k) for k in live.elements())
        if subject == "baseline" and live:
            errors.append("the ignore-all baseline still reports findings")
        if subject == "package" and live != expected:
            errors.append(
                "package VEX: Grype re-added vulnerability/package identities that differ from the under_investigation findings"
            )
        if subject == "application":
            if live - expected:
                errors.append(
                    "application VEX re-added unexpected vulnerability/package identities"
                )
            if live != expected:
                notes.append(
                    f"application-subject VEX re-added {consumer[subject] or 'nothing'}; expected for full matching: {sorted(key_text(k) for k in expected.elements())}. This is the recorded #128 consumer limitation."
                )
    return (
        consumer["baseline"],
        {k: consumer[k] for k in SUBJECTS},
        sorted(key_text(k) for k in expected.elements()),
    )


ARTIFACTS = (
    "canonical-scan.json",
    "usage-graph.json",
    "localisation.json",
    "decision-results.json",
    "report.html",
    "report.txt",
    "demo-app.application.openvex.json",
    "demo-app.package.openvex.json",
    "grype.json",
    "grype-consumer-baseline.json",
    "grype-consumer-application.json",
    "grype-consumer-package.json",
    "grype-ignore-all.yaml",
    "localisation-trace.json",
    "localisation-verify.txt",
    "localisation-verify.json",
)


def check_manifest(out, errors, notes):
    path = out / "run-metadata.json"
    if not path.exists():
        notes.append(
            "Historical evidence has no source/artefact hash manifest; a fresh run.sh replay records one. These checks validate recorded outputs, not a new live run."
        )
        return
    import hashlib

    meta = json.loads(path.read_text())
    if (
        meta.get("mode") != "live"
        or meta.get("sourceDirty") is not False
        or not re.fullmatch(r"[0-9a-f]{40}", meta.get("sbomberRevision", ""))
    ):
        errors.append("run-metadata.json does not identify a clean committed live run")
    inputs = {
        str(f.relative_to(HERE)): hashlib.sha256(f.read_bytes()).hexdigest()
        for f in sorted((HERE / "demo-app").rglob("*"))
        if f.is_file()
    }
    if meta.get("inputSha256") != inputs:
        errors.append(
            "run-metadata.json demo input hashes differ from the checked fixture"
        )
    if not re.fullmatch(r"[0-9a-f]{64}", meta.get("binarySha256", "")):
        errors.append("run-metadata.json has no binary checksum")
    hashes = meta.get("sha256", {})
    if set(hashes) != set(ARTIFACTS):
        errors.append(
            "run-metadata.json has an incomplete or unexpected artefact inventory"
        )
    for name in set(hashes) & set(ARTIFACTS):
        target = out / name
        if (
            not target.is_file()
            or hashlib.sha256(target.read_bytes()).hexdigest() != hashes[name]
        ):
            errors.append(f"{name}: bytes differ from the live run manifest")
    verification = out / "localisation-verify.json"
    if verification.is_file():
        result = json.loads(verification.read_text())
        if (
            result.get("online") is not True
            or result.get("unreachable", 0)
            or result.get("candidates", 0) == 0
            or result.get("candidatesTraced") != result.get("candidates")
            or result.get("tagChecks", {}).get("unavailable", 0)
            or any(i.get("severity") == "error" for i in (result.get("issues") or []))
        ):
            errors.append("live provenance verification is incomplete or failed")


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
    check_manifest(out, errors, notes)
    canon = load(out, "canonical-scan.json")
    decision_doc = load(out, "decision-results.json")
    decisions = unique_index(decision_doc["decisions"], "decisions", errors)
    findings = unique_index(canon["findings"], "canonical scan", errors)
    scan_id = canon["scan"]["scanId"]
    for name in ["usage-graph.json", "localisation.json", "decision-results.json"]:
        if load(out, name).get("scanId") != scan_id:
            errors.append(f"{name}: scanId does not match canonical scan")
    identities = [(f["vulnerabilityId"], f["purl"]) for f in canon["findings"]]
    if len(set(identities)) != len(identities):
        errors.append("canonical scan repeats a vulnerability/package identity")

    # 1/4. decisions and both reports cover every finding exactly once.
    if set(decisions) != set(findings):
        errors.append(
            f"decisions {sorted(set(decisions) ^ set(findings))} do not match the scan's findings"
        )
    rows = {}
    parser = HTMLRows()
    parser.feed((out / "report.html").read_text())
    for fid, vuln, state, purl in parser.rows:
        if fid in rows:
            errors.append(f"{fid} appears twice in report.html")
        rows[fid] = (vuln, state, purl)
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
        if (d.get("vulnerabilityId"), d.get("purl")) != (vuln, purl):
            errors.append(
                f"{fid}: decision is for {d.get('vulnerabilityId')} {d.get('purl')}, scan says {vuln} {purl}"
            )
        h = rows.get(fid)
        if h is None:
            errors.append(f"{fid} ({vuln}, {state}) is missing from report.html")
        elif h != (vuln, state, purl):
            errors.append(
                f"{fid}: report.html shows {h}, decision is {(vuln,state,purl)}"
            )
        t = text.get((vuln, purl))
        if t is None:
            errors.append(
                f"{fid} ({vuln} on {purl}, {state}) is missing from report.txt"
            )
        elif t != state:
            errors.append(f"{fid}: report.txt shows {t}, decision is {state}")
        want = expected_status(d, errors)
        table.append(
            {
                "fid": fid,
                "vuln": vuln,
                "purl": purl,
                "state": state,
                "want": want,
                "aliases": set(f.get("aliases", [])) | {vuln},
            }
        )
    for fid in sorted(set(rows) - set(findings)):
        errors.append(f"report.html has a row for {fid}, which the scan did not report")
    known = {(r["vuln"], r["purl"]) for r in table}
    for key in sorted(set(text) - known):
        errors.append(
            f"report.txt lists {key[0]} on {key[1]}, which the scan did not report"
        )

    # 1/2/3. VEX documents.
    try:
        from jsonschema import validators, FormatChecker

        schema = json.loads(OPENVEX_SCHEMA.read_text())
        validator = validators.validator_for(schema)(
            schema, format_checker=FormatChecker()
        )
    except ImportError:
        validator = None
        errors.append(
            "jsonschema is not installed, so the OpenVEX documents were not validated"
        )
    vex_status = {}
    for subject in SUBJECTS:
        doc = load(out, f"demo-app.{subject}.openvex.json")
        if validator:
            for e in validator.iter_errors(doc):
                errors.append(
                    f"{subject} VEX is not valid OpenVEX 0.2.0: {'/'.join(map(str, e.path))}: {e.message}"
                )
        seen = {}
        for st in doc.get("statements", []):
            names, purls = statement_key(st, subject)
            if st.get("status") == "not_affected":
                errors.append(
                    f"{subject} VEX asserts not_affected for {st['vulnerability']['name']}"
                )
            matched = [r for r in table if r["vuln"] in names and r["purl"] in purls]
            if len(matched) != 1:
                errors.append(
                    f"{subject} VEX statement {st['vulnerability']['name']} on {purls} matches "
                    f"{len(matched)} findings"
                )
                continue
            r = matched[0]
            if r["fid"] in seen:
                errors.append(f"{subject} VEX has two statements for {r['fid']}")
            products = st.get("products", [])
            if subject == "package":
                valid = (
                    len(products) == 1
                    and products[0].get("@id") == r["purl"]
                    and not products[0].get("subcomponents")
                )
            else:
                manifest = json.loads((HERE / "demo-app/package.json").read_text())
                app = f"pkg:npm/{manifest['name']}@{manifest['version']}"
                valid = (
                    len(products) == 1
                    and products[0].get("@id") == app
                    and products[0].get("subcomponents") == [{"@id": r["purl"]}]
                )
            if not valid or names != r["aliases"]:
                errors.append(
                    f"{subject} VEX has extra or mismatched product/vulnerability identities for {r['fid']}"
                )
            if r["want"] == "omit":
                errors.append(f"{subject} VEX must omit unsupported finding {r['fid']}")
            seen[r["fid"]] = st["status"]
            if st["status"] != r["want"]:
                errors.append(
                    f"{subject} VEX says {st['status']} for {r['fid']}, decision maps to {r['want']}"
                )
        for r in table:
            if r["want"] != "omit" and r["fid"] not in seen:
                errors.append(
                    f"{subject} VEX has no statement for {r['fid']} ({r['vuln']})"
                )
        vex_status[subject] = seen

    # 5. contract invariants on the real files.
    v = subprocess.run(
        [
            sys.executable,
            str(ROOT / "contracts" / "validate.py"),
            "--dir",
            str(out),
            "--vex-decision",
            str(ROOT / "contracts" / "fixtures" / "vex-decision.json"),
        ],
        capture_output=True,
        text=True,
    )
    contract = (
        (v.stdout.strip().splitlines() or ["no output"])[-1]
        if v.returncode == 0
        else v.stdout.strip()
    )
    if v.returncode != 0:
        errors.append(
            "contracts/validate.py failed on the run: "
            + contract.replace("\n", " | ")[:600]
        )

    # 6. Keep full package identities, counts, database and source provenance.
    baseline, consumer, want_readded = check_consumers(out, table, errors, notes)

    return {
        "table": table,
        "vex": vex_status,
        "consumer": consumer,
        "want_readded": want_readded,
        "baseline": baseline,
        "contract": contract,
        "errors": errors,
        "notes": notes,
        "grype": load(out, "grype.json")["descriptor"]["version"],
    }


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
        f"**{len(t)} findings** from Grype {r['grype']}: "
        + ", ".join(f"{n} {s}" for s, n in sorted(counts.items()))
        + ".",
        "",
        "| Finding | Vulnerability | Package | Decision | HTML / text report | VEX (application, package) |",
        "|---|---|---|---|---|---|",
    ]
    for row in t:
        out.append(
            f"| {row['fid']} | {row['vuln']} | `{row['purl']}` | {row['state']} | same | "
            f"{r['vex']['application'].get(row['fid'], 'omitted' if row['want']=='omit' else 'missing')}, {r['vex']['package'].get(row['fid'], 'omitted' if row['want']=='omit' else 'missing')} |"
        )
    out += [
        "",
        "## Checks",
        "",
        "- Identity: every finding has one decision, one HTML row, one text entry and one statement per supported finding per",
        "  VEX document, for the same vulnerability and package; unsupported findings are omitted from VEX only.",
        "- State: both reports show the decision's state; every statement has the status the decision maps",
        "  to (guarded positives may remain `under_investigation`; unsupported -> omit; never `not_affected`).",
        "- Both VEX documents validate against OpenVEX 0.2.0, including format checks.",
        "- Duplicate finding IDs, cross-scan inputs, wrong HTML package headings and extra VEX identities are rejected.",
        "- Consumer checks retain vulnerability/package identities and multiplicities, and compare pinned tool, source, database and configuration.",
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
    try:
        r = check(out)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        sys.exit(f"Invalid or incomplete consistency input: {exc}")
    report = render(r)
    print(report, end="")
    stale = False
    if "--check" in sys.argv[2:]:
        md = out / "CONSISTENCY.md"
        stale = not md.exists() or md.read_text() != report
        if stale:
            print(
                "CONSISTENCY.md is stale; re-run run.sh or regenerate it",
                file=sys.stderr,
            )
    sys.exit(1 if r["errors"] or stale else 0)


if __name__ == "__main__":
    main()
