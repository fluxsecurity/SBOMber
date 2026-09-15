#!/usr/bin/env python3
"""Validate the four SBOMber contracts.

Schema conformance is the easy half. The rules below are the ones a JSON Schema
cannot express, and they are where the project's safety actually lives.

Usage:
    python3 contracts/validate.py                 # validate the committed fixtures
    python3 contracts/validate.py --dir ./out     # validate real tool output
"""

import argparse
import json
import sys
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
    HAVE_JSONSCHEMA = True
except ImportError:
    HAVE_JSONSCHEMA = False

HERE = Path(__file__).resolve().parent

CONTRACTS = [
    ("canonical-scan", "canonical-scan.schema.json"),
    ("usage-graph", "usage-graph.schema.json"),
    ("localisation", "localisation.schema.json"),
    ("decision-results", "decision-results.schema.json"),
]

errors = []
checks = 0


def fail(contract, rule, detail):
    errors.append(f"[{contract}] {rule}: {detail}")


def check(contract, rule, condition, detail):
    global checks
    checks += 1
    if not condition:
        fail(contract, rule, detail)


# ---------------------------------------------------------------- canonical-scan

def validate_canonical(d):
    c = "canonical-scan"
    purls = {x["purl"] for x in d["components"]}
    occ_ids = set()

    for comp in d["components"]:
        v = comp.get("version", "")
        check(c, "R0 resolved version", not any(ch in v for ch in "^~*><= "),
              f"{comp['purl']} version '{v}' looks like a range or operator")
        check(c, "R0 constraint not version",
              comp.get("declaredConstraint") != comp.get("version"),
              f"{comp['purl']} stores its constraint as the version")

    seen_identity = {}
    for occ in d["occurrences"]:
        check(c, "occurrence id unique", occ["occurrenceId"] not in occ_ids,
              f"duplicate occurrenceId {occ['occurrenceId']}")
        occ_ids.add(occ["occurrenceId"])
        check(c, "occurrence purl known", occ["purl"] in purls,
              f"{occ['occurrenceId']} references unknown component {occ['purl']}")
        for step in occ.get("dependencyPath", []):
            check(c, "dependency path resolves", step in purls,
                  f"{occ['occurrenceId']} dependencyPath references {step}, absent from components")
        ident = (occ["purl"], occ.get("workspace", ""), occ.get("installPath", ""))
        prior = seen_identity.get(ident)
        check(c, "occurrence identity unique", prior is None,
              f"{occ['occurrenceId']} shares identity with {prior}")
        if prior is None:
            seen_identity[ident] = occ["occurrenceId"]

    by_path = {}
    for occ in d["occurrences"]:
        key = (occ["purl"], occ.get("installPath", ""))
        by_path.setdefault(key, set()).add(occ["relationship"])
    for key, rels in by_path.items():
        check(c, "no direct/transitive duplication", len(rels) == 1,
              f"{key[0]} at {key[1]} is both direct and transitive - the reconciliation bug")

    for f in d["findings"]:
        check(c, "finding purl known", f["purl"] in purls,
              f"{f['findingId']} references unknown component {f['purl']}")
        for oid in f.get("occurrenceIds", []):
            check(c, "finding occurrence known", oid in occ_ids,
                  f"{f['findingId']} references unknown occurrence {oid}")

    status = d["scan"]["status"]
    detail = d["scan"].get("statusDetail", {})
    if status == "complete":
        check(c, "honesty: complete means complete",
              not detail.get("skippedFiles") and not detail.get("failedFiles")
              and not detail.get("truncatedTree") and not detail.get("limitsHit"),
              "status is complete but files were skipped/failed, the tree was truncated, or a limit was hit")
    for e in d["scan"].get("enrichment", []):
        if e["status"] != "success":
            check(c, "non-success enrichment explains itself", bool(e.get("detail")),
                  f"enrichment source {e['source']} is {e['status']} with no detail")

    return {"occurrenceIds": occ_ids, "findingIds": {f["findingId"] for f in d["findings"]},
            "purls": purls, "scanId": d["scan"]["scanId"]}


# ------------------------------------------------------------------ usage-graph

def validate_usage_graph(d, canon):
    c = "usage-graph"
    entry_ids = {e["entryPointId"] for e in d.get("entryPoints", [])}
    cov = d["coverage"]
    analysis = d["analysis"]
    analysis_status = analysis["status"]

    check(c, "complete or partial analysis names analyzer",
          analysis_status not in ("complete", "partial")
          or bool(analysis.get("analyzerId")),
          f"analysis status {analysis_status} has no analyzerId")

    check(c, "unsupported or failed analysis states reason",
          analysis_status not in ("unsupported", "failed")
          or bool(analysis.get("reasonCode")),
          f"analysis status {analysis_status} has no reasonCode")

    check(c, "file counts sum",
          cov["filesDiscovered"] == cov["filesParsed"] + cov["filesParsedWithErrors"]
          + cov["filesFailed"] + cov["filesSkipped"],
          f"{cov['filesDiscovered']} discovered != parsed+withErrors+failed+skipped")
    check(c, "parse failures match counter",
          len(d.get("parseFailures", [])) == cov["filesFailed"],
          f"{len(d.get('parseFailures', []))} parseFailures vs filesFailed {cov['filesFailed']}")

    n_resolved = n_typeonly = n_unresolved = 0
    cs_resolved = cs_unresolved = 0
    reachable = unknown_reach = 0
    obs_ids = set()
    observed_occurrences = set()

    for o in d["observations"]:
        oid = o["observationId"]
        check(c, "observation id unique", oid not in obs_ids, f"duplicate observationId {oid}")
        obs_ids.add(oid)

        res = o["resolution"]
        n_resolved += res == "resolved"
        n_typeonly += res == "type_only"
        n_unresolved += res == "unresolved"

        if res == "unresolved":
            check(c, "unresolved states its reason", bool(o.get("unresolvedReason")),
                  f"{oid} is unresolved with no unresolvedReason - nothing is dropped silently")
        else:
            check(c, "occurrence linked", bool(o.get("occurrenceId")),
                  f"{oid} is {res} but carries no occurrenceId")
            if o.get("occurrenceId"):
                check(c, "occurrence known to canonical-scan",
                      o["occurrenceId"] in canon["occurrenceIds"],
                      f"{oid} references unknown occurrence {o['occurrenceId']}")
                observed_occurrences.add(o["occurrenceId"])

        check(c, "application source only",
              "node_modules/" not in o["location"]["file"],
              f"{oid} has an import location inside node_modules - only application source is parsed")

        if res == "type_only":
            check(c, "type_only carries no call sites", not o["callSites"],
                  f"{oid} is type_only but has call sites - import type is erased at compile time")

        max_level = 1
        for cs in o["callSites"]:
            if cs["resolution"] == "resolved":
                cs_resolved += 1
                max_level = max(max_level, 2)
                check(c, "resolved call site names a symbol", bool(cs.get("calledSymbol")),
                      f"{oid} has a resolved call site at {cs['file']}:{cs['line']} with no calledSymbol")
            else:
                cs_unresolved += 1
                check(c, "unresolved call site states its reason", bool(cs.get("unresolvedReason")),
                      f"{oid} call site {cs['file']}:{cs['line']} is unresolved with no reason")

            r = cs["reachability"]
            if r == "reachable":
                reachable += 1
                max_level = max(max_level, 3)
                check(c, "reachable requires a call path", bool(cs.get("callPath")),
                      f"{oid} call site {cs['file']}:{cs['line']} is reachable with no callPath")
                check(c, "reachable requires an entry point",
                      cs.get("entryPointId") in entry_ids,
                      f"{oid} call site {cs['file']}:{cs['line']} entryPointId not in entryPoints")
                if cs.get("callPath") and cs.get("entryPointId"):
                    ep = next(e for e in d["entryPoints"] if e["entryPointId"] == cs["entryPointId"])
                    check(c, "call path starts at its entry point",
                          cs["callPath"][0]["function"] == ep["function"],
                          f"{oid} callPath starts at {cs['callPath'][0]['function']}, entry point is {ep['function']}")
                    if cs.get("enclosingFunction"):
                        check(c, "call path ends at the calling function",
                              cs["callPath"][-1]["function"] == cs["enclosingFunction"],
                              f"{oid} callPath ends at {cs['callPath'][-1]['function']}, call is in {cs['enclosingFunction']}")
                check(c, "reachable requires a resolved call", cs["resolution"] == "resolved",
                      f"{oid} call site {cs['file']}:{cs['line']} is reachable but unresolved")
            else:
                if r == "unknown":
                    unknown_reach += 1
                check(c, "no path without reachable", not cs.get("callPath"),
                      f"{oid} call site {cs['file']}:{cs['line']} reports {r} but carries a callPath")
                check(c, "no entry point without reachable", not cs.get("entryPointId"),
                      f"{oid} call site {cs['file']}:{cs['line']} reports {r} but carries an entryPointId")

        check(c, "evidenceLevel is derived", o["evidenceLevel"] == max_level,
              f"{oid} declares level {o['evidenceLevel']}, call sites support {max_level}")

    check(c, "import counters match observations",
          (cov["thirdPartyImportsResolved"], cov["thirdPartyImportsTypeOnly"],
           cov["thirdPartyImportsUnresolved"]) == (n_resolved, n_typeonly, n_unresolved),
          f"coverage says {cov['thirdPartyImportsResolved']}/{cov['thirdPartyImportsTypeOnly']}/"
          f"{cov['thirdPartyImportsUnresolved']}, observations give {n_resolved}/{n_typeonly}/{n_unresolved}")
    check(c, "call site counters match observations",
          (cov["thirdPartyCallSitesResolved"], cov["thirdPartyCallSitesUnresolved"]) == (cs_resolved, cs_unresolved),
          f"coverage says {cov['thirdPartyCallSitesResolved']}/{cov['thirdPartyCallSitesUnresolved']}, "
          f"observations give {cs_resolved}/{cs_unresolved}")
    check(c, "callPathsResolved counts reachable call sites",
          cov["callPathsResolved"] == reachable,
          f"coverage says {cov['callPathsResolved']}, {reachable} call sites are reachable")
    check(c, "callPathsUnresolved counts unknown call sites",
          cov["callPathsUnresolved"] == unknown_reach,
          f"coverage says {cov['callPathsUnresolved']}, {unknown_reach} call sites report unknown")
    check(c, "entry point counter matches", cov["entryPointsDetected"] == len(entry_ids),
          f"coverage says {cov['entryPointsDetected']}, {len(entry_ids)} entry points listed")
    if cov["entryPointsDetected"] == 0:
        check(c, "no reachable without entry points", reachable == 0,
              "call sites are reachable but no entry point was detected")

    # The safety-critical one: every occurrence is either observed or declared unanalysed.
    unan = {u["occurrenceId"]: u for u in d["unanalysedOccurrences"]}
    for uid in unan:
        check(c, "unanalysed occurrence known", uid in canon["occurrenceIds"],
              f"unanalysedOccurrences references unknown occurrence {uid}")
        check(c, "unanalysed is not also observed", uid not in observed_occurrences,
              f"{uid} appears in both observations and unanalysedOccurrences")
    missing = canon["occurrenceIds"] - observed_occurrences - set(unan)
    check(c, "every occurrence is accounted for", not missing,
          f"occurrences neither observed nor declared unanalysed: {sorted(missing)} - "
          "component 4 cannot tell 'analysed, found nothing' from 'never analysed'")

    check(c, "scanId matches", d["scanId"] == canon["scanId"],
          f"usage-graph scanId {d['scanId']} != canonical-scan {canon['scanId']}")

    return {"observationIds": obs_ids,
            "negativeEligible": {uid for uid, u in unan.items()
                                 if u["reason"] == "not_imported_by_analysed_source"} | observed_occurrences,
            "unanalysed": unan,
            "analysisStatus": analysis_status}


# ------------------------------------------------------------------ localisation

def validate_localisation(d, canon):
    c = "localisation"
    check(c, "scanId matches", d["scanId"] == canon["scanId"],
          f"localisation scanId {d['scanId']} != canonical-scan {canon['scanId']}")
    methods = {}
    for r in d["results"]:
        check(c, "finding known", r["findingId"] in canon["findingIds"],
              f"{r['findingId']} not in canonical-scan")
        if r["method"] == "unknown":
            check(c, "unknown carries no candidates", not r.get("candidateSymbols"),
                  f"{r['findingId']} has method unknown but lists candidate symbols")
            check(c, "unknown carries no confidence", r["confidence"] == "none",
                  f"{r['findingId']} has method unknown with confidence {r['confidence']}")
        for a in r.get("provenance", {}).get("artefacts", []):
            check(c, "downloaded code never executed", a.get("executed") is False,
                  f"{r['findingId']} artefact {a['url']} does not record executed: false")
        llm = r.get("provenance", {}).get("llm")
        if llm and llm.get("corroboratedBy", "none") == "none":
            check(c, "uncorroborated LLM stays low", r["confidence"] == "low",
                  f"{r['findingId']} is an uncorroborated LLM result claiming {r['confidence']} confidence")
        methods[r["method"]] = methods.get(r["method"], 0) + 1
    s = d.get("summary", {})
    if s:
        check(c, "summary counts match results", s.get("findingsProcessed") == len(d["results"]),
              f"summary says {s.get('findingsProcessed')}, {len(d['results'])} results present")
        check(c, "byMethod matches results", s.get("byMethod") == methods,
              f"summary byMethod {s.get('byMethod')} != actual {methods}")
    return {r["findingId"]: r for r in d["results"]}


# -------------------------------------------------------------- decision-results

BANNED = ["not affected", "is safe", "no risk", "false positive"]

VEX_INVESTIGATION_STATES = {
    "openvex": "under_investigation",
    "cyclonedx": "in_triage",
}


def load_vex_policy(path):
    with open(path) as f:
        policy = json.load(f)

    fmt = policy.get("format")
    state = policy.get("investigationState")
    expected = VEX_INVESTIGATION_STATES.get(fmt)

    if expected is None:
        raise ValueError(
            f"unsupported VEX format {fmt!r}; expected one of "
            f"{sorted(VEX_INVESTIGATION_STATES)}"
        )

    if state != expected:
        raise ValueError(
            f"VEX decision record says format {fmt!r} but investigationState "
            f"is {state!r}; expected {expected!r}"
        )

    return policy


def validate_decisions(d, canon, usage, loc, vex_policy):
    c = "decision-results"
    check(c, "scanId matches", d["scanId"] == canon["scanId"],
          f"decision-results scanId {d['scanId']} != canonical-scan {canon['scanId']}")
    counts = {"usage_detected": 0, "no_usage_detected": 0, "unknown": 0, "unsupported": 0}

    expected_investigation_state = vex_policy["investigationState"]
    investigation_tokens = {
        dec.get("vexMapping", {}).get("statement")
        for dec in d["decisions"]
        if dec.get("vexMapping", {}).get("statement")
        in set(VEX_INVESTIGATION_STATES.values())
    }

    check(c, "VEX vocabularies are not mixed",
          len(investigation_tokens) <= 1,
          f"decision-results mixes investigation vocabularies: "
          f"{sorted(investigation_tokens)}")

    wrong_tokens = investigation_tokens - {expected_investigation_state}
    check(c, "VEX vocabulary matches selected format",
          not wrong_tokens,
          f"selected format {vex_policy['format']} requires "
          f"{expected_investigation_state}, found {sorted(wrong_tokens)}")

    occ_by_finding = {}
    for f_id in canon["findingIds"]:
        occ_by_finding[f_id] = set()

    usage_status = usage["analysisStatus"]

    for dec in d["decisions"]:
        fid = dec["findingId"]
        check(c, "finding known", fid in canon["findingIds"], f"{fid} not in canonical-scan")
        counts[dec["state"]] = counts.get(dec["state"], 0) + 1

        if usage_status == "unsupported":
            check(c, "analysis-level unsupported maps to finding-level unsupported",
                  dec["state"] == "unsupported",
                  f"{fid} has state {dec['state']} while Component 2 analysis is unsupported")

        if usage_status in ("partial", "failed"):
            check(c, "incomplete analysis cannot produce negative evidence",
                  dec["state"] != "no_usage_detected",
                  f"{fid} is no_usage_detected while Component 2 analysis is {usage_status}")

        for oid in dec["basedOn"].get("usageObservationIds", []):
            check(c, "observation known", oid in usage["observationIds"],
                  f"{fid} cites unknown observation {oid}")

        j = dec["justification"].lower()
        for phrase in BANNED:
            check(c, "justification language", phrase not in j,
                  f"{fid} justification contains '{phrase}'")

        lm = dec["basedOn"].get("localisationMethod")
        if lm == "unknown":
            check(c, "localisation unknown produces unknown", dec["state"] == "unknown",
                  f"{fid} has localisation unknown but state {dec['state']}")

        if dec["state"] == "no_usage_detected":
            check(c, "negative needs a completed analysis",
                  dec["basedOn"]["coverageSummary"].get("scanStatus") == "complete",
                  f"{fid} is no_usage_detected on a {dec['basedOn']['coverageSummary'].get('scanStatus')} scan")

        vex = dec.get("vexMapping", {})
        st = vex.get("statement")
        if st == "not_affected":
            check(c, "no automated not_affected", bool(vex.get("manuallyReviewedBy")),
                  f"{fid} asserts not_affected with no named manual reviewer")
        if dec["state"] == "no_usage_detected":
            check(c, "no_usage_detected maps to selected investigation state",
                  st == expected_investigation_state,
                  f"{fid} is no_usage_detected but maps to {st}; "
                  f"selected {vex_policy['format']} requires "
                  f"{expected_investigation_state}")
        if dec["state"] == "unknown":
            check(c, "unknown cannot assert", st not in ("affected", "not_affected"),
                  f"{fid} is unknown but asserts {st}")
        if st == "affected":
            check(c, "affected needs matched symbols", bool(dec["basedOn"].get("matchedSymbols")),
                  f"{fid} asserts affected with no matched symbols")
            check(c, "affected needs reliable localisation",
                  dec["basedOn"].get("localisationConfidence") in ("high", "medium"),
                  f"{fid} asserts affected on {dec['basedOn'].get('localisationConfidence')} localisation")
            check(c, "affected needs an action statement", bool(vex.get("actionStatement")),
                  f"{fid} asserts affected with no action statement")

    dist = d.get("distribution")
    if dist:
        check(c, "distribution matches decisions",
              all(dist.get(k2) == counts[k1] for k1, k2 in
                  [("usage_detected", "usageDetected"), ("no_usage_detected", "noUsageDetected"),
                   ("unknown", "unknown"), ("unsupported", "unsupported")]),
              f"distribution {dist} != actual {counts}")
        check(c, "distribution total matches",
              dist.get("totalFindings") == len(d["decisions"]),
              f"totalFindings {dist.get('totalFindings')} != {len(d['decisions'])} decisions")

    # Cross-contract: a negative verdict requires that component 2 actually looked.
    findings = {f["findingId"]: f for f in canon["_findings"]}
    for dec in d["decisions"]:
        if dec["state"] != "no_usage_detected":
            continue
        occs = set(findings[dec["findingId"]].get("occurrenceIds", []))
        blocked = [o for o in occs if o in usage["unanalysed"]
                   and usage["unanalysed"][o]["reason"] != "not_imported_by_analysed_source"]
        check(c, "no negative on an unanalysed occurrence", not blocked,
              f"{dec['findingId']} is no_usage_detected but occurrence(s) {blocked} were reported "
              f"unanalysed by component 2 - this must be unknown")


# ------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=str(HERE / "fixtures"),
                    help="directory holding the four JSON files")
    ap.add_argument("--vex-decision",
                    help="path to the machine-readable VEX decision record")
    args = ap.parse_args()
    base = Path(args.dir)

    if args.vex_decision:
        vex_decision_path = Path(args.vex_decision)
    else:
        vex_decision_path = base / "vex-decision.json"
        if not vex_decision_path.exists():
            vex_decision_path = base / "vex-decision.sample.json"

    if not vex_decision_path.exists():
        print(f"missing VEX decision record: {vex_decision_path}", file=sys.stderr)
        sys.exit(2)

    try:
        vex_policy = load_vex_policy(vex_decision_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"invalid VEX decision record: {exc}", file=sys.stderr)
        sys.exit(2)

    docs = {}
    for name, schema_file in CONTRACTS:
        path = base / f"{name}.sample.json"
        if not path.exists():
            path = base / f"{name}.json"
        if not path.exists():
            print(f"missing: {name}", file=sys.stderr)
            sys.exit(2)
        docs[name] = json.load(open(path))

        if HAVE_JSONSCHEMA:
            schema = json.load(open(HERE / schema_file))
            v = Draft202012Validator(schema)
            for e in sorted(v.iter_errors(docs[name]), key=lambda e: e.path):
                fail(name, "schema", f"{'/'.join(str(p) for p in e.path)}: {e.message}")

    canon = validate_canonical(docs["canonical-scan"])
    canon["_findings"] = docs["canonical-scan"]["findings"]
    usage = validate_usage_graph(docs["usage-graph"], canon)
    loc = validate_localisation(docs["localisation"], canon)
    validate_decisions(
        docs["decision-results"], canon, usage, loc, vex_policy
    )

    if not HAVE_JSONSCHEMA:
        print("note: jsonschema not installed - invariant checks only, no schema conformance\n")

    if errors:
        print(f"FAIL - {len(errors)} problem(s) across {checks} invariant checks\n")
        for e in errors:
            print("  " + e)
        sys.exit(1)
    print(f"OK - {checks} invariant checks passed across four contracts")


if __name__ == "__main__":
    main()
