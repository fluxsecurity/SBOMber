"""Regression checks for Issue #152 measurement integrity (no Go required)."""
import copy
import unittest

from evaluate_reachability import summarise


def graph():
    return {
        "entryPoints": [{"entryPointId": "ep", "function": "main", "file": "app.js"}],
        "analyser": {"reachabilityAnalysed": True},
        "analysis": {"status": "partial"},
        "coverage": {"entryPointsDetected": 1, "callPathsResolved": 1,
                     "callPathsUnresolved": 2, "thirdPartyCallSitesResolved": 2,
                     "thirdPartyCallSitesUnresolved": 1},
        "parseFailures": [], "unanalysedOccurrences": [],
        "observations": [{
            "observationId": "obs", "importedSpecifier": "lodash", "resolution": "resolved",
            "location": {"file": "app.js", "line": 1, "column": 1},
            "callSites": [
                {"file": "app.js", "line": 3, "resolution": "resolved", "calledSymbol": "merge",
                 "reachability": "reachable", "entryPointId": "ep",
                 "callPath": [{"function": "main", "file": "app.js", "line": 2}]},
                {"file": "app.js", "line": 8, "resolution": "resolved", "calledSymbol": "merge",
                 "reachability": "unknown", "enclosingFunction": "callback"},
                {"file": "app.js", "line": 1, "column": 1, "resolution": "unresolved",
                 "reachability": "unknown", "unresolvedReason": "outside_supported_syntax"},
            ]}],
    }


class MeasurementTests(unittest.TestCase):
    def test_marker_does_not_inflate_resolved_symbol_subset(self):
        metrics, rows = summarise(graph())
        self.assertEqual(metrics["resolutionDenominator"], 3)
        self.assertAlmostEqual(metrics["resolutionRate"], 1 / 3)
        self.assertEqual(metrics["resolvedSymbolResolutionDenominator"], 2)
        self.assertEqual(metrics["resolvedSymbolResolutionRate"], 0.5)
        self.assertEqual(metrics["possibleSyntheticMarkers"], 1)
        self.assertEqual(sum(metrics["unknownByCause"].values()), 2)
        self.assertEqual(rows[1]["causeCategory"], "no_resolved_entry_point_path")

    def test_no_pass_has_na_rate_not_zero_or_success(self):
        data = graph()
        data["analyser"]["reachabilityAnalysed"] = False
        data["entryPoints"] = []
        data["coverage"].update(entryPointsDetected=0, callPathsResolved=0, callPathsUnresolved=0)
        for call in data["observations"][0]["callSites"]:
            call["reachability"] = "not_analysed"
            call.pop("entryPointId", None)
            call.pop("callPath", None)
        metrics, _ = summarise(data)
        self.assertIsNone(metrics["resolutionRate"])
        self.assertIsNone(metrics["resolvedSymbolResolutionRate"])
        self.assertEqual(metrics["notAnalysed"], 3)

    def test_coverage_mismatch_is_not_published(self):
        data = graph()
        data["coverage"]["callPathsResolved"] = 99
        with self.assertRaisesRegex(ValueError, "callPathsResolved"):
            summarise(data)

    def test_unknown_cannot_carry_a_path(self):
        data = graph()
        data["observations"][0]["callSites"][1]["callPath"] = [{"function": "guess"}]
        with self.assertRaisesRegex(ValueError, "proven path"):
            summarise(data)

    def test_unresolved_import_cannot_be_reachable(self):
        data = graph()
        data["observations"][0]["resolution"] = "unresolved"
        with self.assertRaisesRegex(ValueError, "resolved import"):
            summarise(data)

    def test_empty_call_scope_has_na_rate(self):
        data = graph()
        data["observations"][0]["callSites"] = []
        data["coverage"].update(callPathsResolved=0, callPathsUnresolved=0,
                                thirdPartyCallSitesResolved=0, thirdPartyCallSitesUnresolved=0)
        metrics, _ = summarise(data)
        self.assertIsNone(metrics["resolutionRate"])
        self.assertEqual(metrics["contractCallRecords"], 0)

    def test_does_not_mutate_saved_graph(self):
        data = graph()
        original = copy.deepcopy(data)
        summarise(data)
        self.assertEqual(data, original)


if __name__ == "__main__":
    unittest.main()
