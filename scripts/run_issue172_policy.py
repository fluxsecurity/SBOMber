#!/usr/bin/env python3
"""Run labelled synthetic #172 cases through the production CLI; no network."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / 'testdata/fixtures/indirect-usage-172'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--out', required=True, help='New output directory; never overwritten')
    parser.add_argument('--source-commit', help='Commit of a source archive without Git metadata')
    parser.add_argument('--expect-original', action='store_true', help='Reproduce original verdicts before applying the policy')
    args = parser.parse_args()
    import jsonschema  # mandatory preflight; validate.py can otherwise skip schema checks
    del jsonschema
    binary = Path(args.binary).resolve()
    if not binary.is_file():
        raise RuntimeError('Build the requested binary first')
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    for key in ('GITHUB_TOKEN', 'GH_TOKEN'):
        env.pop(key, None)
    rows = []
    commands = []

    def run(argv, log):
        commands.append([str(v) for v in argv])
        result = subprocess.run(argv, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        log.write_text(result.stdout)
        if result.returncode:
            raise RuntimeError(f'{log}: exit {result.returncode}; inspect saved log')

    for fixture in sorted(p for p in FIXTURES.iterdir() if p.is_dir()):
        label = json.loads((fixture / 'expected.json').read_text())
        dest = out / fixture.name
        dest.mkdir()
        for name in ('canonical-scan.json', 'localisation.json', 'expected.json'):
            shutil.copyfile(fixture / name, dest / name)
        shutil.copyfile(ROOT / 'contracts/fixtures/vex-decision.json', dest / 'vex-decision.json')
        run([str(binary), 'usage', '--canonical-scan', str(dest / 'canonical-scan.json'), '--repo', 'repo-172='+str(fixture / 'app'), '--out', str(dest / 'usage-graph.json')], dest / 'usage.log')
        run([str(binary), 'decide', '--canonical-scan', str(dest / 'canonical-scan.json'), '--usage-graph', str(dest / 'usage-graph.json'), '--localisation', str(dest / 'localisation.json'), '--out', str(dest / 'decision-results.json')], dest / 'decide.log')
        graph = json.loads((dest / 'usage-graph.json').read_text())
        decisions = json.loads((dest / 'decision-results.json').read_text())['decisions']
        expected = label['expectedOriginalState' if args.expect_original else 'expectedState']
        if len(decisions) != 1 or decisions[0]['state'] != expected:
            raise RuntimeError(f'{fixture.name}: expected {expected}; inspect saved decision')
        if graph['analysis']['status'] != 'complete' or graph['coverage']['filesDiscovered'] != 1:
            raise RuntimeError(f'{fixture.name}: application analysis scope changed')
        if label['expectedUnanalysedReason'] is not None:
            reasons = {v['occurrenceId']: v['reason'] for v in graph['unanalysedOccurrences']}
            if reasons.get('occ-dep-b') != label['expectedUnanalysedReason']:
                raise RuntimeError(f'{fixture.name}: absence evidence changed')
        if label['requiresUnresolvedUse']:
            calls = [c for o in graph['observations'] if o.get('occurrenceId') == 'occ-dep-b' for c in o['callSites']]
            if not any(c.get('unresolvedReason') == 'outside_supported_syntax' and c['reachability'] == 'unknown' and not c.get('callPath') and not c.get('entryPointId') for c in calls):
                raise RuntimeError(f'{fixture.name}: copied function lost conservative evidence')
        decision = decisions[0]
        if decision['state'] == 'unknown' and decision['riskPriority']['band'] != 'insufficient_information':
            raise RuntimeError(f'{fixture.name}: uncertainty lowered priority')
        if decision['state'] != 'usage_detected' and decision['vexMapping']['statement'] != 'under_investigation':
            raise RuntimeError(f'{fixture.name}: unexpected VEX mapping')
        # Localisation is author-supplied synthetic policy input, not a
        # production localisation claim. Validate its shape, but do not invent
        # verified upstream artefacts to pass the provenance gate.
        from jsonschema import Draft202012Validator
        spec = importlib.util.spec_from_file_location('policy_validator', ROOT / 'contracts/validate.py')
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        docs = {}
        for name in ('canonical-scan', 'usage-graph', 'localisation', 'decision-results'):
            docs[name] = json.loads((dest / (name+'.json')).read_text())
            Draft202012Validator(json.loads((ROOT / 'contracts' / (name+'.schema.json')).read_text())).validate(docs[name])
        canon = validator.validate_canonical(docs['canonical-scan'])
        canon['_findings'] = docs['canonical-scan']['findings']
        usage = validator.validate_usage_graph(docs['usage-graph'], canon)
        loc = {v['findingId']:v for v in docs['localisation']['results']}
        validator.validate_decisions(docs['decision-results'], canon, usage, loc, validator.load_vex_policy(dest / 'vex-decision.json'))
        if validator.errors:
            raise RuntimeError('Invariant validation failed: '+str(validator.errors))
        (dest / 'contracts.log').write_text(f'PASS: four JSON schemas and {validator.checks} canonical/usage/decision invariant checks. Localisation provenance NOT validated: synthetic policy input, not production localisation evidence.\n')
        rows.append({'fixture':fixture.name, 'state':decision['state'], 'band':decision['riskPriority']['band'], 'coverage':graph['coverage'], 'hashes':{p.name:digest(p) for p in sorted(dest.glob('*.json'))}})
        print(f'{fixture.name}: {decision["state"]}; schemas/policy invariants PASS', flush=True)
    files = [p for base in ('cmd', 'internal', 'contracts', 'testdata/fixtures/indirect-usage-172') for p in (ROOT / base).rglob('*') if p.is_file() and '__pycache__' not in p.parts]
    files += [ROOT / 'go.mod', ROOT / 'go.sum', Path(__file__).resolve()]
    manifest = {'issue':172, 'syntheticPolicyCases':True, 'realVulnerabilityAccuracyClaim':False, 'mode':'original' if args.expect_original else 'proposed-policy', 'gitHead':args.source_commit or subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(), 'gitStatus':('Archive export augmented with the labelled policy harness' if args.source_commit else subprocess.check_output(['git','status','--porcelain','--untracked-files=all'],cwd=ROOT,text=True)), 'binarySha256':digest(binary), 'sourceSha256':{p.relative_to(ROOT).as_posix():digest(p) for p in sorted(set(files))}, 'commands':commands, 'results':rows}
    (out / 'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(f'Saved {len(rows)} labelled policy cases: {out}')


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError) as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        sys.exit(1)
