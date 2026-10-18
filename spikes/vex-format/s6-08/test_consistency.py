#!/usr/bin/env python3
"""Tests for consistency.py: the committed run passes, and each kind of
disagreement between the outputs fails it."""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "consistency.py"
RESULTS = HERE / "results"


class ConsistencyTests(unittest.TestCase):
    def run_on(self, edit=None):
        tmp = tempfile.TemporaryDirectory()
        out = Path(tmp.name)
        for f in RESULTS.iterdir():
            shutil.copy(f, out / f.name)
        if edit:
            edit(out)
        res = subprocess.run([sys.executable, str(SCRIPT), str(out)], text=True, capture_output=True)
        tmp.cleanup()
        return res

    def edit_json(self, out, name, fn):
        p = out / name
        d = json.loads(p.read_text())
        fn(d)
        p.write_text(json.dumps(d))

    def test_committed_run_is_consistent(self):
        res = self.run_on()
        self.assertEqual(res.returncode, 0, res.stdout[-2000:] + res.stderr)
        self.assertIn("No problems.", res.stdout)

    def test_vex_status_that_disagrees_with_the_decision_fails(self):
        def edit(out):
            def flip(d):
                for st in d["statements"]:
                    if st["vulnerability"]["name"] == "CVE-2020-7788":
                        st["status"] = "affected"
                        st["action_statement"] = "Upgrade ini."
            self.edit_json(out, "demo-app.package.openvex.json", flip)
        res = self.run_on(edit)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("package VEX says affected for find-003, decision maps to under_investigation", res.stdout)

    def test_finding_missing_from_the_human_report_fails(self):
        def edit(out):
            p = out / "report.html"
            s = p.read_text()
            start = s.index('<tr data-finding-id="find-004">')
            p.write_text(s[:start] + s[s.index("</tr>", start) + 5:])
            t = out / "report.txt"
            t.write_text("\n".join(l for l in t.read_text().splitlines() if "CVE-2020-28500" not in l))
        res = self.run_on(edit)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("find-004 (CVE-2020-28500, unknown) is missing from report.html", res.stdout)
        self.assertIn("is missing from report.txt", res.stdout)

    def test_untrusted_extra_rows_and_invalid_vex_fail(self):
        def edit(out):
            p = out / "report.html"
            p.write_text(p.read_text().replace(
                "</tbody>", '<tr data-finding-id="find-999">\n<td class="id">CVE-0000-0001</td>\n<td>usage_detected, x</td></tr></tbody>', 1))
            self.edit_json(out, "demo-app.application.openvex.json",
                           lambda d: d["statements"][0].update({"status": "not_affected"}))
        res = self.run_on(edit)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("report.html has a row for find-999, which the scan did not report", res.stdout)
        self.assertIn("application VEX asserts not_affected", res.stdout)


if __name__ == "__main__":
    unittest.main()
