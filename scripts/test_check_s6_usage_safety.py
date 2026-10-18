"""Safety regressions adapted from the alternative review patch's test ideas."""
import copy
import unittest

try:
    from .check_s6_usage_safety import validate
except ImportError:
    from check_s6_usage_safety import validate


class SafetyTests(unittest.TestCase):
    def case(self, computed=False):
        imported = {'file': 'src/index.js', 'line': 1, 'specifier': 'lodash',
                    'imported': '*', 'local': 'lodash', 'kind': 'cjs_require',
                    'purl': 'pkg:npm/lodash@4.17.21'}
        if computed:
            imported.update(kind='dynamic_computed', computedSpecifier=True,
                            unresolvedReason='computed_specifier', purl='')
        labels = {'fixture': 'test', 'expected': {
            'thirdPartyImports': [imported], 'thirdPartyCalls': []}}
        obs = {'location': {'file': imported['file'], 'line': 1},
               'importedSpecifier': imported['specifier'], 'importedSymbol': '*',
               'localAlias': 'lodash', 'importKind': imported['kind'],
               'purl': imported['purl'], 'callSites': []}
        for key in ('computedSpecifier', 'unresolvedReason'):
            if key in imported:
                obs[key] = imported[key]
        graph = {'analysis': {'status': 'complete'}, 'observations': [obs]}
        return labels, graph

    def test_matching_computed_uncertainty_passes(self):
        validate(*self.case(computed=True))

    def test_missing_computed_flag_fails(self):
        labels, graph = self.case(computed=True)
        del graph['observations'][0]['computedSpecifier']
        with self.assertRaisesRegex(ValueError, 'computedSpecifier'):
            validate(labels, graph)

    def test_wrong_uncertainty_reason_fails(self):
        labels, graph = self.case(computed=True)
        graph['observations'][0]['unresolvedReason'] = 'not_in_inventory'
        with self.assertRaisesRegex(ValueError, 'unresolvedReason'):
            validate(labels, graph)

    def test_wrong_purl_cannot_match_the_expected_binding(self):
        labels, graph = self.case()
        graph['observations'][0]['purl'] = 'pkg:npm/other@1'
        with self.assertRaisesRegex(ValueError, 'Expected one binding'):
            validate(labels, graph)

    def test_omitted_false_flag_uses_contract_default(self):
        labels, graph = self.case()
        labels['expected']['thirdPartyImports'][0]['computedSpecifier'] = False
        validate(labels, graph)

    def test_partial_analysis_fails(self):
        labels, graph = self.case()
        graph['analysis']['status'] = 'partial'
        with self.assertRaisesRegex(ValueError, 'not complete'):
            validate(labels, graph)

    def test_unanalysed_occurrence_must_stay_visible(self):
        labels, graph = self.case()
        expected = {'purl': 'pkg:npm/other@1', 'reason': 'computed_specifier'}
        labels['expected']['unanalysedOccurrences'] = [expected]
        with self.assertRaisesRegex(ValueError, 'Missing unanalysed'):
            validate(labels, graph)
        graph['unanalysedOccurrences'] = [copy.deepcopy(expected)]
        validate(labels, graph)

    def test_reexport_reachability_must_remain_unknown(self):
        labels, graph = self.case()
        labels['expected']['unresolvedCalls'] = [{
            'file': 'src/index.js', 'line': 1, 'symbol': '',
            'reachability': 'unknown', 'unresolvedReason': 'reexport_chain'}]
        call = {'file': 'src/index.js', 'line': 1, 'calledSymbol': '',
                'reachability': 'reachable', 'unresolvedReason': 'reexport_chain'}
        graph['observations'][0]['callSites'] = [call]
        with self.assertRaisesRegex(ValueError, 'reachability'):
            validate(labels, graph)
        call['reachability'] = 'unknown'
        validate(labels, graph)

    def test_invented_reexport_symbol_is_rejected(self):
        labels, graph = self.case()
        labels['expected']['unresolvedCalls'] = [{
            'file': 'src/index.js', 'line': 1, 'symbol': ''}]
        graph['observations'][0]['callSites'] = [{
            'file': 'src/index.js', 'line': 1, 'calledSymbol': 'invented'}]
        with self.assertRaisesRegex(ValueError, 'Expected one call'):
            validate(labels, graph)


if __name__ == '__main__':
    unittest.main()
