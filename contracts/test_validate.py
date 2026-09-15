#!/usr/bin/env python3
"""Regression tests for the format-aware contract validator."""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
VALIDATOR = HERE / "validate.py"
FIXTURES = HERE / "fixtures"

CONTRACT_FILES = [
    "canonical-scan.sample.json",
    "usage-graph.sample.json",
    "localisation.sample.json",
    "decision-results.sample.json",
    "vex-decision.sample.json",
]


class ContractValidatorTests(unittest.TestCase):
    def make_fixture_dir(self):
        tmp = tempfile.TemporaryDirectory()
        base = Path(tmp.name)

        for name in CONTRACT_FILES:
            shutil.copy(FIXTURES / name, base / name)

        return tmp, base

    def run_validator(self, base):
        return subprocess.run(
            [sys.executable, str(VALIDATOR), "--dir", str(base)],
            text=True,
            capture_output=True,
            check=False,
        )

    def load_json(self, path):
        with open(path) as f:
            return json.load(f)

    def save_json(self, path, data):
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")

    def test_each_supported_format_accepts_its_own_vocabulary(self):
        for fmt, token in (
            ("openvex", "under_investigation"),
            ("cyclonedx", "in_triage"),
        ):
            with self.subTest(format=fmt):
                tmp, base = self.make_fixture_dir()
                try:
                    decisions_path = base / "decision-results.sample.json"
                    decisions = self.load_json(decisions_path)

                    for decision in decisions["decisions"]:
                        mapping = decision.get("vexMapping", {})
                        if mapping.get("statement") == "under_investigation":
                            mapping["statement"] = token

                    self.save_json(decisions_path, decisions)

                    vex_path = base / "vex-decision.sample.json"
                    vex = self.load_json(vex_path)
                    vex["format"] = fmt
                    vex["investigationState"] = token
                    self.save_json(vex_path, vex)

                    result = self.run_validator(base)

                    self.assertEqual(
                        result.returncode,
                        0,
                        msg=result.stdout + result.stderr,
                    )
                finally:
                    tmp.cleanup()

    def test_mixed_vex_vocabularies_are_rejected(self):
        tmp, base = self.make_fixture_dir()
        try:
            path = base / "decision-results.sample.json"
            decisions = self.load_json(path)

            changed = False
            for decision in decisions["decisions"]:
                mapping = decision.get("vexMapping", {})
                if mapping.get("statement") == "under_investigation":
                    mapping["statement"] = "in_triage"
                    changed = True
                    break

            self.assertTrue(changed)
            self.save_json(path, decisions)

            result = self.run_validator(base)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "VEX vocabularies are not mixed",
                result.stdout + result.stderr,
            )
        finally:
            tmp.cleanup()

    def test_not_affected_without_manual_reviewer_is_rejected(self):
        tmp, base = self.make_fixture_dir()
        try:
            path = base / "decision-results.sample.json"
            decisions = self.load_json(path)

            mapping = decisions["decisions"][0]["vexMapping"]
            mapping["statement"] = "not_affected"
            mapping.pop("manuallyReviewedBy", None)

            self.save_json(path, decisions)

            result = self.run_validator(base)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "no automated not_affected",
                result.stdout + result.stderr,
            )
        finally:
            tmp.cleanup()



    def make_unsupported_decisions(self, base):
        path = base / "decision-results.sample.json"
        decisions = self.load_json(path)

        decisions["distribution"] = {
            "totalFindings": len(decisions["decisions"]),
            "usageDetected": 0,
            "noUsageDetected": 0,
            "unknown": 0,
            "unsupported": len(decisions["decisions"]),
        }

        for decision in decisions["decisions"]:
            decision["state"] = "unsupported"
            decision["analysisConfidence"] = "low"
            decision["confidenceCriteria"] = [
                "Component 2 usage analysis reported unsupported"
            ]
            decision["justification"] = (
                "Component 2 did not analyse this ecosystem, so no usage "
                "determination was made."
            )
            decision["basedOn"] = {
                "usageObservationIds": [],
                "coverageSummary": {
                    "parseCoveragePercent": 0,
                    "unresolvedImportsInScope": 0,
                },
            }
            decision["vexMapping"] = {"statement": "omit"}

        self.save_json(path, decisions)

    def use_unsupported_usage(self, base):
        shutil.copy(
            FIXTURES / "usage-graph.unsupported.sample.json",
            base / "usage-graph.sample.json",
        )

    def test_usage_graph_complete_analysis_is_valid(self):
        tmp, base = self.make_fixture_dir()
        try:
            result = self.run_validator(base)
            self.assertEqual(
                result.returncode,
                0,
                msg=result.stdout + result.stderr,
            )
        finally:
            tmp.cleanup()

    def test_usage_graph_unsupported_analysis_is_valid(self):
        tmp, base = self.make_fixture_dir()
        try:
            self.use_unsupported_usage(base)
            self.make_unsupported_decisions(base)

            result = self.run_validator(base)

            self.assertEqual(
                result.returncode,
                0,
                msg=result.stdout + result.stderr,
            )
        finally:
            tmp.cleanup()

    def test_complete_analysis_requires_analyzer_id(self):
        tmp, base = self.make_fixture_dir()
        try:
            path = base / "usage-graph.sample.json"
            usage = self.load_json(path)
            usage["analysis"].pop("analyzerId", None)
            self.save_json(path, usage)

            result = self.run_validator(base)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("analyzerId", result.stdout + result.stderr)
        finally:
            tmp.cleanup()

    def test_unsupported_analysis_requires_reason_code(self):
        tmp, base = self.make_fixture_dir()
        try:
            self.use_unsupported_usage(base)
            self.make_unsupported_decisions(base)

            path = base / "usage-graph.sample.json"
            usage = self.load_json(path)
            usage["analysis"].pop("reasonCode", None)
            self.save_json(path, usage)

            result = self.run_validator(base)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("reasonCode", result.stdout + result.stderr)
        finally:
            tmp.cleanup()

    def test_reachable_call_requires_call_path(self):
        tmp, base = self.make_fixture_dir()
        try:
            path = base / "usage-graph.sample.json"
            usage = self.load_json(path)

            changed = False
            for observation in usage["observations"]:
                for call_site in observation["callSites"]:
                    if call_site["reachability"] == "reachable":
                        call_site.pop("callPath", None)
                        changed = True
                        break
                if changed:
                    break

            self.assertTrue(changed)
            self.save_json(path, usage)

            result = self.run_validator(base)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "reachable requires a call path",
                result.stdout + result.stderr,
            )
        finally:
            tmp.cleanup()

    def test_unsupported_analysis_cannot_emit_nonunsupported_findings(self):
        tmp, base = self.make_fixture_dir()
        try:
            self.use_unsupported_usage(base)

            result = self.run_validator(base)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "analysis-level unsupported maps to finding-level unsupported",
                result.stdout + result.stderr,
            )
        finally:
            tmp.cleanup()

    def test_partial_and_failed_analysis_cannot_produce_negative_evidence(self):
        for status in ("partial", "failed"):
            with self.subTest(status=status):
                tmp, base = self.make_fixture_dir()
                try:
                    path = base / "usage-graph.sample.json"
                    usage = self.load_json(path)
                    usage["analysis"]["status"] = status

                    if status == "failed":
                        usage["analysis"]["reasonCode"] = "analysis_failed"

                    self.save_json(path, usage)

                    result = self.run_validator(base)

                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(
                        "incomplete analysis cannot produce negative evidence",
                        result.stdout + result.stderr,
                    )
                finally:
                    tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
