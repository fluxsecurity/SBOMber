#!/usr/bin/env python3
"""Tests for verify_provenance.py: the committed run passes, and a broken
trace or a gitHead that moved since the freeze fails."""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "verify_provenance.py"
RESULTS = HERE / "results" / "provenance" / "localisation.json"


class VerifyProvenanceTests(unittest.TestCase):
    def run_on(self, edit=None):
        doc = json.loads(RESULTS.read_text())
        if edit:
            doc = copy.deepcopy(doc)
            edit(doc)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "localisation.json"
            path.write_text(json.dumps(doc))
            return subprocess.run([sys.executable, str(SCRIPT), "--results", str(path)],
                                  text=True, capture_output=True, check=False)

    def result(self, doc, cid):
        return next(r for r in doc["results"] if r["findingId"] == cid)

    def test_committed_run_verifies(self):
        out = self.run_on()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("provenance verifies for all 10 frozen cases", out.stdout)

    def test_candidate_without_evidence_fails(self):
        def edit(doc):
            del self.result(doc, "c04")["candidateSymbols"][0]["evidence"]
        out = self.run_on(edit)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("c04: candidate decode cites no artefact", out.stdout)

    def test_unverified_or_unknown_artefact_fails(self):
        def edit(doc):
            r = self.result(doc, "c01")
            for a in r["provenance"]["artefacts"]:
                if a["kind"] == "source_file":
                    a["verified"] = False
                    a["note"] = "tampered"
            self.result(doc, "c02")["candidateSymbols"][0]["evidence"] = ["github:evil/evil@0000000000:x.js"]
        out = self.run_on(edit)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("is not verified (tampered)", out.stdout)
        self.assertIn("is not in provenance.artefacts", out.stdout)

    def test_moved_githead_or_foreign_commit_fails(self):
        def edit(doc):
            for tc in self.result(doc, "c04")["provenance"]["tagChecks"]:
                tc["registryGitHead"] = "f" * 40
            r = self.result(doc, "c10")
            for tc in r["provenance"]["tagChecks"]:
                tc["fixCommits"] = ["e" * 40]
            for a in r["provenance"]["artefacts"]:
                if a["kind"] == "source_file":
                    a["commit"] = "e" * 40
        out = self.run_on(edit)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("c04: npm gitHead for", out.stdout)
        self.assertIn("c10: candidates were read from none of the ground-truth commits", out.stdout)

    def test_closed_set_missing_the_public_symbol_fails(self):
        def edit(doc):
            for c in self.result(doc, "c06")["candidateSymbols"]:
                c.update({"visibility": "internal", "exposedVia": ["notWhatAppsCall"],
                          "exposedViaSource": "export_resolution", "exposedViaComplete": True})
        out = self.run_on(edit)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("c06: closed candidate set whose join keys ['notWhatAppsCall'] miss every expected public symbol", out.stdout)


if __name__ == "__main__":
    unittest.main()
