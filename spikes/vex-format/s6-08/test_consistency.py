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
        res = subprocess.run(
            [sys.executable, str(SCRIPT), str(out)], text=True, capture_output=True
        )
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
        self.assertIn(
            "package VEX says affected for find-003, decision maps to under_investigation",
            res.stdout,
        )

    def test_finding_missing_from_the_human_report_fails(self):
        def edit(out):
            p = out / "report.html"
            s = p.read_text()
            start = s.index('<tr data-finding-id="find-004">')
            p.write_text(s[:start] + s[s.index("</tr>", start) + 5 :])
            t = out / "report.txt"
            t.write_text(
                "\n".join(
                    l for l in t.read_text().splitlines() if "CVE-2020-28500" not in l
                )
            )

        res = self.run_on(edit)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn(
            "find-004 (CVE-2020-28500, unknown) is missing from report.html", res.stdout
        )
        self.assertIn("is missing from report.txt", res.stdout)

    def test_untrusted_extra_rows_and_invalid_vex_fail(self):
        def edit(out):
            p = out / "report.html"
            p.write_text(
                p.read_text().replace(
                    "</tbody>",
                    '<tr data-finding-id="find-999">\n<td class="id">CVE-0000-0001</td>\n<td>usage_detected, x</td></tr></tbody>',
                    1,
                )
            )
            self.edit_json(
                out,
                "demo-app.application.openvex.json",
                lambda d: d["statements"][0].update({"status": "not_affected"}),
            )

        res = self.run_on(edit)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn(
            "report.html has a row for find-999, which the scan did not report",
            res.stdout,
        )
        self.assertIn("application VEX asserts not_affected", res.stdout)

    def test_duplicate_decision_fails(self):
        def edit(out):
            def change(d):
                d["decisions"].append(d["decisions"][0].copy())
                d["distribution"]["usageDetected"] += 1
                d["distribution"]["totalFindings"] += 1

            self.edit_json(out, "decision-results.json", change)

        self.assertNotEqual(self.run_on(edit).returncode, 0)

    def test_html_wrong_package_heading_fails(self):
        def edit(out):
            p = out / "report.html"
            p.write_text(
                p.read_text().replace(
                    "<h3>pkg:npm/ini@1.3.5 ", "<h3>pkg:npm/foreign@9.0.0 "
                )
            )

        self.assertNotEqual(self.run_on(edit).returncode, 0)

    def test_consumer_wrong_package_fails(self):
        def edit(out):
            def change(d):
                for m in d["matches"]:
                    m["artifact"]["purl"] = "pkg:npm/foreign@9.0.0"

            self.edit_json(out, "grype-consumer-package.json", change)

        self.assertNotEqual(self.run_on(edit).returncode, 0)

    def test_unpinned_consumer_fails(self):
        def edit(out):
            self.edit_json(
                out,
                "grype-consumer-package.json",
                lambda d: d["descriptor"].update(version="99.0.0"),
            )

        self.assertNotEqual(self.run_on(edit).returncode, 0)

    def test_missing_original_scanner_findings_fails(self):
        def edit(out):
            for name in ["grype.json", "grype-consumer-package.json"]:
                self.edit_json(out, name, lambda d: d.update(matches=[]))

        self.assertNotEqual(self.run_on(edit).returncode, 0)

    def test_foreign_vex_product_fails(self):
        def edit(out):
            self.edit_json(
                out,
                "demo-app.package.openvex.json",
                lambda d: d["statements"][0]["products"].append(
                    {"@id": "pkg:npm/foreign@9.0.0"}
                ),
            )

        self.assertNotEqual(self.run_on(edit).returncode, 0)

    def test_different_scan_identity_fails(self):
        def edit(out):
            self.edit_json(
                out, "usage-graph.json", lambda d: d.update(scanId="another-scan")
            )

        self.assertNotEqual(self.run_on(edit).returncode, 0)

    def set_policy_case(self, out, fid, state, statement):
        scan = json.loads((out / "canonical-scan.json").read_text())
        finding = next(f for f in scan["findings"] if f["findingId"] == fid)
        names = {finding["vulnerabilityId"], *finding.get("aliases", [])}

        def match(m):
            return (
                m["vulnerability"]["id"] in names
                and m["artifact"]["purl"] == finding["purl"]
            )

        def change_dec(d):
            r = next(r for r in d["decisions"] if r["findingId"] == fid)
            fields = {
                "usage_detected": "usageDetected",
                "no_usage_detected": "noUsageDetected",
                "unknown": "unknown",
                "unsupported": "unsupported",
            }
            d["distribution"][fields[r["state"]]] -= 1
            d["distribution"][fields[state]] += 1
            r["state"] = state
            r["vexMapping"] = {"statement": statement}
            if state == "usage_detected":
                r["basedOn"]["localisationConfidence"] = "low"

        self.edit_json(out, "decision-results.json", change_dec)
        for subject in ["application", "package"]:

            def change_vex(d):
                for st in list(d["statements"]):
                    if st["vulnerability"]["name"] == finding["vulnerabilityId"]:
                        if statement == "omit":
                            d["statements"].remove(st)
                        else:
                            st["status"] = statement

            self.edit_json(out, f"demo-app.{subject}.openvex.json", change_vex)
        p = out / "report.html"
        text = p.read_text()
        start = text.index(f'<tr data-finding-id="{fid}">')
        end = text.index("</tr>", start)
        import re

        part = re.sub(r"<td>([a-z_]+),", f"<td>{state},", text[start:end], count=1)
        p.write_text(text[:start] + part + text[end:])
        p = out / "report.txt"
        p.write_text(
            "\n".join(
                (
                    re.sub(r"\[([a-z_]+),", f"[{state},", line, count=1)
                    if finding["vulnerabilityId"] in line
                    else line
                )
                for line in p.read_text().splitlines()
            )
            + "\n"
        )

        def change_consumer(d):
            original = json.loads((out / "grype.json").read_text())
            baseline = json.loads((out / "grype-consumer-baseline.json").read_text())
            d["matches"] = [m for m in d["matches"] if not match(m)]
            d["ignoredMatches"] = [
                m for m in d.get("ignoredMatches", []) if not match(m)
            ]
            key = "matches" if statement == "under_investigation" else "ignoredMatches"
            source = (
                original["matches"] if key == "matches" else baseline["ignoredMatches"]
            )
            d[key].extend(m for m in source if match(m))

        self.edit_json(out, "grype-consumer-package.json", change_consumer)

    def test_unsupported_stays_in_reports_but_is_omitted_from_vex(self):
        res = self.run_on(
            lambda out: self.set_policy_case(out, "find-004", "unsupported", "omit")
        )
        self.assertEqual(res.returncode, 0, res.stdout[-2500:] + res.stderr)

    def test_guarded_positive_may_stay_under_investigation(self):
        res = self.run_on(
            lambda out: self.set_policy_case(
                out, "find-001", "usage_detected", "under_investigation"
            )
        )
        self.assertEqual(res.returncode, 0, res.stdout[-2500:] + res.stderr)

    def test_different_consumer_database_fails(self):
        def edit(out):
            self.edit_json(
                out,
                "grype-consumer-package.json",
                lambda d: d["descriptor"]["db"]["status"].update(built="different"),
            )

        self.assertNotEqual(self.run_on(edit).returncode, 0)

    def test_missing_ignored_inventory_fails(self):
        def edit(out):
            self.edit_json(
                out,
                "grype-consumer-baseline.json",
                lambda d: d.update(ignoredMatches=[]),
            )

        self.assertNotEqual(self.run_on(edit).returncode, 0)

    def test_application_consumer_must_load_its_vex(self):
        def edit(out):
            self.edit_json(
                out,
                "grype-consumer-application.json",
                lambda d: d["descriptor"]["configuration"].update(
                    {"vex-documents": []}
                ),
            )

        self.assertNotEqual(self.run_on(edit).returncode, 0)

    def test_wrong_application_product_fails(self):
        def edit(out):
            self.edit_json(
                out,
                "demo-app.application.openvex.json",
                lambda d: d["statements"][0]["products"][0].update(
                    {"@id": "pkg:npm/foreign-app@1.0.0"}
                ),
            )

        self.assertNotEqual(self.run_on(edit).returncode, 0)

    def test_manifest_detects_changed_artefact_bytes(self):
        def edit(out):
            import hashlib, importlib.util

            spec = importlib.util.spec_from_file_location("consistency", SCRIPT)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            # Synthetic metadata for this boundary test, not a measured replay.
            (out / "localisation-verify.json").write_text(
                json.dumps(
                    {
                        "online": True,
                        "candidates": 25,
                        "candidatesTraced": 25,
                        "issues": [],
                    }
                )
            )
            meta = {
                "mode": "live",
                "sourceDirty": False,
                "sbomberRevision": "a" * 40,
                "binarySha256": "b" * 64,
                "inputSha256": {
                    str(f.relative_to(HERE)): hashlib.sha256(f.read_bytes()).hexdigest()
                    for f in sorted((HERE / "demo-app").rglob("*"))
                    if f.is_file()
                },
                "sha256": {
                    name: hashlib.sha256((out / name).read_bytes()).hexdigest()
                    for name in module.ARTIFACTS
                },
            }
            (out / "run-metadata.json").write_text(json.dumps(meta))
            p = out / "localisation-trace.json"
            p.write_text(p.read_text() + "\n")

        result = self.run_on(edit)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("bytes differ from the live run manifest", result.stdout)


if __name__ == "__main__":
    unittest.main()
