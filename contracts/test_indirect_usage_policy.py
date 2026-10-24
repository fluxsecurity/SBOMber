"""Policy regression: absence of application imports cannot support a negative."""
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent


class IndirectUsagePolicyTests(unittest.TestCase):
    def test_absent_import_blocks_negative_but_preserves_positive(self):
        for identity in ('occurrence-id', 'purl-fallback'):
            for state, blocked in [('no_usage_detected', True), ('unknown', False), ('usage_detected', False)]:
                with self.subTest(identity=identity, state=state):
                    spec = importlib.util.spec_from_file_location('policy_validator', HERE / 'validate.py')
                    validator = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(validator)
                    def load(name):
                        return json.loads((HERE / 'fixtures' / name).read_text())
                    canon = load('canonical-scan.sample.json')
                    usage = load('usage-graph.sample.json')
                    decisions = load('decision-results.sample.json')
                    # Consumer-view unit test for the decision cross-check.
                    view = {'scanId':canon['scan']['scanId'], 'findingIds':{v['findingId'] for v in canon['findings']}, '_findings':canon['findings']}
                    target_occurrence = 'occ-003' if identity == 'occurrence-id' else 'different-occurrence-id'
                    usage_view = {'analysisStatus':'complete', 'filesDiscovered':142, 'observationIds':{v['observationId'] for v in usage['observations']}, 'unanalysed':{target_occurrence:{'reason':'not_imported_by_analysed_source', 'purl':'pkg:npm/axios@0.21.0'}}}
                    target = next(v for v in decisions['decisions'] if v['findingId']=='find-002')
                    target['state'] = state
                    if state == 'usage_detected':
                        target['vexMapping']['statement'] = 'affected'
                        target['vexMapping']['actionStatement'] = 'Review the matched call.'
                        target['basedOn']['matchedSymbols'] = ['merge']
                    decisions.pop('distribution', None)
                    validator.validate_decisions(decisions, view, usage_view, {}, load('vex-decision.json'))
                    errors = [e for e in validator.errors if 'no negative on an unanalysed occurrence' in e]
                    self.assertEqual(bool(errors), blocked, validator.errors)
                    self.assertEqual(validator.errors, errors)


if __name__ == '__main__':
    unittest.main()
