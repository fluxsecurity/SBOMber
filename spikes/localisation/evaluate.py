#!/usr/bin/env python3
"""Grade the localisation trace against the pre-committed ground truth.

Reads cases/cases.json (fixed before measurement) and results/trace.json
(what `sbomber localise --all-methods` recorded) and writes
results/evaluation.json and results/evaluation.md.

Two questions are asked of every method attempt, per case:

  changed-hit   does the candidate set contain a function the fix changed?
  public-hit    does it contain the public symbol an application would call?

The unknown rate is a result, not a failure.
"""
import json
import sys
from collections import OrderedDict
from pathlib import Path

HERE = Path(__file__).resolve().parent
cases = {c["id"]: c for c in json.load(open(HERE / "cases" / "cases.json"))["cases"]}
traces = {t["findingId"]: t for t in json.load(open(HERE / "results" / "trace.json"))}
localisation = {r["findingId"]: r for r in json.load(open(HERE / "results" / "localisation.json"))["results"]}

METHODS = ["advisory_metadata", "patch_reference", "advisory_text", "version_diff"]


def symbols(attempt):
    return {c["symbol"] for c in attempt.get("candidates") or []}


rows = []
per_method = {m: {"attempted": 0, "hit": 0, "changed_hit": 0, "public_hit": 0, "empty": 0, "error": 0,
                  "non_code": 0, "skipped": 0, "unbounded": 0, "candidates": []} for m in METHODS}
client = {"searched": 0, "matched": 0}

for cid, case in cases.items():
    t = traces.get(cid)
    r = localisation.get(cid)
    if not t or not r:
        rows.append({"id": cid, "error": "no trace or result"})
        continue
    row = OrderedDict(id=cid, vulnerabilityId=case["vulnerabilityId"], package=case["package"],
                      advisoryNamesFunction=case["advisoryNamesFunction"],
                      expectedChanged=case["expectedChangedFunctions"], expectedPublic=case["expectedPublicSymbols"],
                      selected=t["selected"], confidence=r["confidence"],
                      selectedSymbols=[c["symbol"] for c in r.get("candidateSymbols", [])], methods={})
    changed = set(case["expectedChangedFunctions"])
    public = set(case["expectedPublicSymbols"])
    for a in t["attempts"]:
        m = a["method"]
        if m not in per_method:
            continue
        pm = per_method[m]
        pm["attempted"] += 1
        pm[a["outcome"]] = pm.get(a["outcome"], 0) + 1
        syms = symbols(a)
        ch = bool(syms & changed)
        pu = bool(syms & public)
        if a["outcome"] == "hit":
            pm["candidates"].append(len(syms))
            pm["changed_hit"] += ch
            pm["public_hit"] += pu
        row["methods"][m] = {"outcome": a["outcome"], "candidates": sorted(syms), "changedHit": ch, "publicHit": pu,
                             "nonFunctionChanges": a.get("nonFunctionChanges") or [], "notes": a.get("notes") or []}
        if a.get("clientMethod"):
            client["searched"] += 1
            if a["clientMethod"].get("commitsMatched", 0) > 0:
                client["matched"] += 1
            row["clientMethod"] = a["clientMethod"]
    sel = set(row["selectedSymbols"])
    row["selectedChangedHit"] = bool(sel & changed)
    row["selectedPublicHit"] = bool(sel & public)
    rows.append(row)

n = len(rows)
unknown = sum(1 for r in rows if r.get("selected") == "unknown")
summary = OrderedDict(
    cases=n,
    unknownCount=unknown,
    unknownRate=round(unknown / n, 2) if n else None,
    selectedChangedHit=sum(1 for r in rows if r.get("selectedChangedHit")),
    selectedPublicHit=sum(1 for r in rows if r.get("selectedPublicHit")),
    clientMethod=client,
    perMethod={m: {k: (v if k != "candidates" else (round(sum(v) / len(v), 1) if v else None))
                   for k, v in pm.items()} for m, pm in per_method.items()},
)
for m, pm in summary["perMethod"].items():
    pm["medianCandidates"] = (sorted(per_method[m]["candidates"])[len(per_method[m]["candidates"]) // 2]
                              if per_method[m]["candidates"] else None)

json.dump({"summary": summary, "cases": rows}, open(HERE / "results" / "evaluation.json", "w"), indent=2)

# ---------------------------------------------------------------- markdown
def yn(b):
    return "yes" if b else "no"

md = []
md.append("# Localisation Spike Results (S4-08)\n")
md.append(f"Ten cases, ground truth fixed before measurement (`cases/cases.json`). "
          f"Tool: `sbomber localise --all-methods --client-search`, trace in `results/trace.json`.\n")
md.append("## Headline numbers\n")
md.append("| Measure | Value |\n|---|---|")
md.append(f"| Cases | {n} |")
md.append(f"| Selected method produced a candidate | {n - unknown}/{n} |")
md.append(f"| **Unknown rate** (no method produced a candidate) | **{unknown}/{n}** |")
md.append(f"| Selected candidate set contains a function the fix changed | {summary['selectedChangedHit']}/{n} |")
md.append(f"| Selected candidate set contains the public symbol an app would call | {summary['selectedPublicHit']}/{n} |")
md.append(f"| Client's method: vulnerability ID found in a commit message | {client['matched']}/{client['searched']} repositories searched |\n")

md.append("## Per method\n")
md.append("| Method | Attempted | Hit | Empty | Error / non-code / skipped | Contains a changed function | Contains the public symbol | Median candidates |")
md.append("|---|---|---|---|---|---|---|---|")
for m in METHODS:
    pm = per_method[m]
    other = pm.get("error", 0) + pm.get("non_code", 0) + pm.get("skipped", 0) + pm.get("unbounded", 0)
    med = summary["perMethod"][m]["medianCandidates"]
    md.append(f"| `{m}` | {pm['attempted']} | {pm['hit']} | {pm.get('empty', 0)} | {other} | {pm['changed_hit']}/{pm['hit']} | {pm['public_hit']}/{pm['hit']} | {med if med is not None else '-'} |")
md.append("")
md.append("Hit = at least one candidate. A hit that names the wrong function is still a hit; the two right-hand columns say whether it was useful.\n")

md.append("## Per case\n")
md.append("| Case | Advisory | Names a fn? | Selected | Conf. | Selected candidates | Changed fn found | Public symbol found | metadata | patch | text | version_diff |")
md.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
for r in rows:
    if "error" in r:
        md.append(f"| {r['id']} | | | | | {r['error']} | | | | | | |")
        continue
    def cell(m):
        a = r["methods"].get(m)
        if not a:
            return "-"
        if a["outcome"] != "hit":
            return a["outcome"]
        return f"{len(a['candidates'])} ({'C' if a['changedHit'] else ''}{'P' if a['publicHit'] else ''}{'' if a['changedHit'] or a['publicHit'] else 'miss'})"
    sel = ", ".join(r["selectedSymbols"][:5]) + (f" +{len(r['selectedSymbols']) - 5}" if len(r["selectedSymbols"]) > 5 else "")
    md.append(f"| {r['id']} | {r['vulnerabilityId']} {r['package']} | {yn(r['advisoryNamesFunction'])} | `{r['selected']}` | {r['confidence']} | {sel or '-'} | {yn(r['selectedChangedHit'])} | {yn(r['selectedPublicHit'])} | {cell('advisory_metadata')} | {cell('patch_reference')} | {cell('advisory_text')} | {cell('version_diff')} |")
md.append("")
md.append("Method cells: candidate count, then C = contains a changed function, P = contains the public symbol.\n")

md.append("## Notes recorded per case\n")
for r in rows:
    if "error" in r:
        continue
    md.append(f"### {r['id']} {r['vulnerabilityId']} ({r['package']})\n")
    md.append(f"Expected changed: {', '.join('`'+s+'`' for s in r['expectedChanged'])}. Expected public: {', '.join('`'+s+'`' for s in r['expectedPublic'])}.\n")
    for m in METHODS:
        a = r["methods"].get(m)
        if not a:
            continue
        line = f"- `{m}`: {a['outcome']}"
        if a["candidates"]:
            line += " -> " + ", ".join(f"`{s}`" for s in a["candidates"][:12]) + (f" (+{len(a['candidates']) - 12})" if len(a["candidates"]) > 12 else "")
        if a["nonFunctionChanges"]:
            line += f"; non-function changes: {', '.join(a['nonFunctionChanges'][:6])}"
        md.append(line)
        for note in a["notes"][:6]:
            md.append(f"  - {note}")
    if r.get("clientMethod"):
        cm = r["clientMethod"]
        md.append(f"- client method: searched `{cm.get('repository')}` for `{cm.get('query')}` -> {cm.get('commitsMatched', 0)} commit(s)" + (f"; error: {cm['error']}" if cm.get("error") else ""))
    md.append("")

open(HERE / "results" / "evaluation.md", "w").write("\n".join(md) + "\n")
print(json.dumps(summary, indent=1))
