#!/usr/bin/env python3
"""Check evaluated/provisional audit scopes and report disclosed label timing."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read(path):
    return json.loads(path.read_text())


def is_retrospective(case_id, label):
    # These rules encode the author's saved CASE.md disclosures, not an
    # independently established claim that labels were blinded.
    return ((case_id == 'appsecco-dvna' and label['reasoning'].startswith('Labelled at the package.json range floor')) or
            (case_id == 'gitaalekhyapaul-vuln-app' and label['vulnerabilityId'] == 'GHSA-jqcg-44mw-7w3h'))


def outcome(label, state):
    if state in ('unknown', 'unsupported'):
        return 'abstained'
    if state == 'usage_detected':
        return 'agree_usage' if label == 'genuine_usage' else 'over_reported_usage'
    if state == 'no_usage_detected':
        return 'missed_usage' if label == 'genuine_usage' else 'agree_no_usage'
    raise ValueError('Unrecognised decision state: '+state)


def summarise(root):
    audit_root = root / 'testdata/audit'
    original = read(root / 'docs/evidence/s5-14/audit-results.original-93.json')
    current = read(root / 'docs/evidence/s5-14/audit-results.json')
    original_cases = {c['caseId']:c for c in original['cases']}
    current_cases = {c['caseId']:c for c in current['cases']}
    discovered = {p.parent.name for p in audit_root.glob('*/labels.json')}
    if set(current_cases) != discovered or len(current_cases) != len(current['cases']):
        raise ValueError('Current report does not match active case discovery')
    if 'appsecco-dvna' in discovered:
        raise ValueError('DVNA conditional labels must remain provisional')
    totals = Counter()
    strata = {'worksheet_origin':Counter(), 'retrospective':Counter()}
    details = []
    provisional_rows = []
    prior_strata = {'worksheet_origin':Counter(), 'retrospective':Counter()}
    for case_id, saved in sorted(original_cases.items()):
        folder = audit_root / case_id
        active = (folder / 'labels.json').is_file()
        label_path = folder / ('labels.json' if active else 'labels.provisional.json')
        labels = read(label_path)
        scan = read(folder / 'canonical-scan.json')
        by_id = {v['findingId']:v for v in labels['labels']}
        findings = {v['findingId']:v for v in scan['findings']}
        if len(by_id) != len(labels['labels']) or set(by_id) != set(findings):
            raise ValueError(case_id+': labels do not cover scan exactly')
        components = {c['purl']:c for c in scan['components']}
        if labels['repository']['commit'] != saved['repository']['commit']:
            raise ValueError(case_id+': repository pin changed')
        rows = current_cases[case_id]['rows'] if active else saved['rows']
        if len(rows) != len(by_id) or {v['findingId'] for v in rows} != set(by_id):
            raise ValueError(case_id+': report row identities differ')
        for row in rows:
            label = by_id[row['findingId']]
            finding = findings[row['findingId']]
            if (label['vulnerabilityId'],label['purl']) != (finding['vulnerabilityId'],finding['purl']):
                raise ValueError(case_id+': label identity mismatch')
            if label['label'] != row['label'] or label['reasoning'] != row['labelReasoning']:
                raise ValueError(case_id+': report label data differs')
            result = outcome(label['label'],row['state'])
            if row['outcome'] != result:
                raise ValueError(case_id+': report outcome differs')
            timing = 'retrospective' if is_retrospective(case_id,label) else 'worksheet_origin'
            component = components[label['purl']]
            version_unknown = component.get('versionKnown') is False or not component.get('version')
            item = {'caseId':case_id,'findingId':label['findingId'],'vulnerabilityId':label['vulnerabilityId'],'purl':label['purl'],'labelTiming':timing,'state':row['state'],'label':label['label'],'outcome':result,'exactVersionUnavailable':version_unknown,'rangeFloorAssumption':label['reasoning'].startswith('Labelled at the package.json range floor'),'evaluationStatus':'included' if active else 'provisional_excluded'}
            prior_strata[timing][result] += 1
            if active:
                totals[result] += 1
                strata[timing][result] += 1
                details.append(item)
            else:
                provisional_rows.append(item)
    for key,json_key in [('agree_usage','agreeUsage'),('over_reported_usage','overReportedUsage'),('abstained','abstained'),('missed_usage','missedUsage'),('agree_no_usage','agreeNoUsage')]:
        if totals[key] != current['totals'][json_key]:
            raise ValueError('Current report totals mismatch: '+key)
    if len(details) != current['totals']['findings']:
        raise ValueError('Current findings count mismatch')
    return {'method':'Counts on existing source labels; label timing follows author disclosures, not an independent blinding claim','evaluationScope':'Two active cases; all 47 DVNA proposals excluded together under labelling rule 6','activeCaseCount':len(discovered),'activeFindingCount':len(details),'activeOutcomes':dict(totals),'activeTimingStrata':{k:dict(v) for k,v in strata.items()},'provisionalCaseCount':1,'provisionalFindingCount':len(provisional_rows),'provisionalUnknownVersionFindings':sum(v['exactVersionUnavailable'] for v in provisional_rows),'provisionalRangeFloorLabels':sum(v['rangeFloorAssumption'] for v in provisional_rows),'originalTimingStrata':{k:dict(v) for k,v in prior_strata.items()},'readyToClose124':False,'remainingAcceptance':'At least one more evaluable real repository case is required; conditional DVNA trigger/version claims remain unresolved','rows':details+provisional_rows,'sourceLabelSha256':{str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(audit_root.glob('*/labels*.json'))}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',required=True,help='New output file, never overwritten')
    args = parser.parse_args()
    result = summarise(ROOT)
    target = Path(args.out)
    with target.open('x') as f:
        json.dump(result,f,indent=2)
        f.write('\n')
    print(f'{result["activeCaseCount"]} active cases / {result["activeFindingCount"]} findings; {result["provisionalFindingCount"]} provisional findings excluded; #124 remains open')


if __name__ == '__main__':
    main()
