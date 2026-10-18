import unittest
from unittest.mock import patch
import subprocess
from collections import Counter
try:
    from .evaluate_usage_constructs import evaluate, score, aggregate
except ImportError:
    from evaluate_usage_constructs import evaluate, score, aggregate


class EvaluationTests(unittest.TestCase):
    def make_case(self, imports, calls, observed, unknown=None, excluded=None):
        labels = {'expected': {'thirdPartyImports': imports,
                               'thirdPartyCalls': calls,
                               'unresolvedCalls': unknown or [],
                               'excludedCalls': excluded or []}}
        graph = {'analysis': {'status': 'complete'}, 'observations': observed}
        return evaluate(labels, graph)

    def test_duplicate_observation_counts_false_positive(self):
        self.assertEqual(score(Counter({('x',): 1}), Counter({('x',): 2}))['fp'], 1)

    def test_empty_call_metrics_are_undefined(self):
        self.assertIsNone(score(Counter(), Counter())['precision'])
        self.assertIsNone(score(Counter(), Counter())['recall'])

    def test_misattribution_to_other_import_is_false_positive(self):
        label = {'file': 'src/index.js', 'line': 1, 'specifier': 'lodash',
                 'imported': 'merge', 'local': 'merge', 'kind': 'esm_named'}
        other = {**label, 'specifier': 'other', 'line': 2}
        call = {'file': 'src/index.js', 'line': 5, 'symbol': 'merge',
                'importSpecifier': 'lodash'}
        obs = [{'location': {'file': other['file'], 'line': other['line']},
                'importedSpecifier': other['specifier'],
                'importedSymbol': other['imported'], 'localAlias': other['local'],
                'importKind': other['kind'], 'resolution': 'resolved',
                'callSites': [{'file': 'src/index.js', 'line': 5,
                               'calledSymbol': 'merge', 'resolution': 'resolved'}]}]
        result = self.make_case([label, other], [call], obs)
        self.assertEqual(result['callEvaluation']['tp'], 0)
        self.assertEqual(result['callEvaluation']['fp'], 1)
        self.assertEqual(result['callEvaluation']['fn'], 1)

    def test_type_only_import_and_no_calls(self):
        label = {'file': 'src/index.ts', 'line': 1, 'specifier': 'pkg',
                 'imported': 'Thing', 'local': 'Thing', 'kind': 'esm_type_only',
                 'resolution': 'type_only'}
        obs = [{'location': {'file': label['file'], 'line': 1},
                'importedSpecifier': 'pkg', 'importedSymbol': 'Thing',
                'localAlias': 'Thing', 'importKind': 'esm_type_only',
                'resolution': 'type_only', 'callSites': []}]
        result = self.make_case([label], [], obs)
        self.assertEqual(result['importEvaluation']['tp'], 1)
        self.assertIsNone(result['callEvaluation']['precision'])

    def test_excluded_shadow_detected(self):
        label = {'file': 'src/index.js', 'line': 1, 'specifier': 'lodash',
                 'imported': 'merge', 'local': 'merge', 'kind': 'esm_named'}
        obs = [{'location': {'file': 'src/index.js', 'line': 1},
                'importedSpecifier': 'lodash', 'importedSymbol': 'merge',
                'localAlias': 'merge', 'importKind': 'esm_named',
                'resolution': 'resolved',
                'callSites': [{'file': 'src/index.js', 'line': 8,
                               'calledSymbol': 'merge', 'resolution': 'resolved'}]}]
        result = self.make_case([label], [], obs, excluded=[
            {'file': 'src/index.js', 'line': 8, 'symbol': 'merge'}])
        self.assertEqual(result['callEvaluation']['fp'], 1)
        self.assertEqual(result['excludedCallViolations'][0]['count'], 1)

    def test_unresolved_import_is_separate_from_resolved_call(self):
        label = {'file': 'src/index.js', 'line': 1, 'specifier': '<computed>',
                 'imported': '', 'local': '', 'kind': 'dynamic_computed',
                 'resolution': 'unresolved'}
        obs = [{'location': {'file': 'src/index.js', 'line': 1},
                'importedSpecifier': '<computed>', 'importedSymbol': '',
                'localAlias': '', 'importKind': 'dynamic_computed',
                'resolution': 'unresolved', 'callSites': []}]
        result = self.make_case([label], [], obs)
        self.assertEqual(result['importEvaluation']['tp'], 1)
        self.assertEqual(result['observedImportOutcomes']['unresolved'], 1)
        self.assertIsNone(result['callEvaluation']['precision'])

    def test_missing_expected_call_counts_false_negative(self):
        label = {'file': 'src/index.js', 'line': 1, 'specifier': 'lodash',
                 'imported': 'merge', 'local': 'merge', 'kind': 'esm_named'}
        observed = [{'location': {'file': 'src/index.js', 'line': 1},
                    'importedSpecifier': 'lodash', 'importedSymbol': 'merge',
                    'localAlias': 'merge', 'importKind': 'esm_named',
                    'resolution': 'resolved', 'callSites': []}]
        result = self.make_case([label], [{'file': 'src/index.js',
                                           'line': 4, 'symbol': 'merge'}],
                                observed)
        self.assertEqual(result['callEvaluation']['fn'], 1)

    def test_wrong_purl_is_misattribution(self):
        label = {'file': 'x.js', 'line': 1, 'specifier': 'lodash',
                 'kind': 'esm_named', 'purl': 'pkg:npm/lodash@4.17.21'}
        obs = {'location': {'file': 'x.js', 'line': 1},
               'importedSpecifier': 'lodash', 'importKind': 'esm_named',
               'purl': 'pkg:npm/other@1', 'resolution': 'resolved', 'callSites': []}
        result = self.make_case([label], [], [obs])
        self.assertEqual(result['importEvaluation']['fp'], 1)
        self.assertEqual(result['importEvaluation']['fn'], 1)

    def test_aggregate_uses_counts_and_reports_denominators(self):
        result = aggregate([{'tp': 2, 'fp': 1, 'fn': 0},
                            {'tp': 1, 'fp': 0, 'fn': 2}])
        self.assertEqual(result['predicted'], 4)
        self.assertEqual(result['expected'], 5)
        self.assertEqual(result['precision'], .75)
        self.assertEqual(result['recall'], .6)
        self.assertIsNone(aggregate([])['recall'])

    def test_runner_preserves_git_status_leading_space(self):
        try:
            from .run_s6_usage_evaluation import command
        except ImportError:
            from run_s6_usage_evaluation import command
        result = subprocess.CompletedProcess([], 0, ' M docs/evidence/s6-04/manifest.json\n')
        with patch('subprocess.run', return_value=result):
            self.assertEqual(command('git', 'status'),
                             ' M docs/evidence/s6-04/manifest.json')

    def test_provenance_tracks_build_inputs(self):
        try:
            from . import run_s6_usage_evaluation as runner
        except ImportError:
            import run_s6_usage_evaluation as runner
        with patch.object(runner, 'git', return_value='revision') as git:
            self.assertEqual(runner.analysis_commit(), 'revision')
            git.assert_called_once_with('log', '-1', '--format=%H', '--',
                                        'cmd', 'internal', 'scripts', 'testdata',
                                        'go.mod', 'go.sum')

    def test_partial_scan_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'complete analysis'):
            evaluate({'expected': {'thirdPartyImports': []}},
                     {'analysis': {'status': 'partial'}, 'observations': []})


if __name__ == '__main__':
    unittest.main()
