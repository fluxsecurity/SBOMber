"""Verify provisional labels cannot silently enter the measured audit scope."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from summarise_audit_label_provenance import ROOT, summarise


class AuditLabelProvenanceTests(unittest.TestCase):
    def fixture(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        shutil.copytree(ROOT / 'testdata/audit',root / 'testdata/audit')
        out = root / 'docs/evidence/s5-14'
        out.mkdir(parents=True)
        for name in ('audit-results.json','audit-results.original-93.json'):
            shutil.copyfile(ROOT / 'docs/evidence/s5-14' / name,out / name)
        return root

    def test_scope_and_timing_are_separate(self):
        got = summarise(self.fixture())
        self.assertEqual((got['activeCaseCount'],got['activeFindingCount'],got['provisionalFindingCount']),(2,46,47))
        self.assertEqual(got['activeTimingStrata']['retrospective'],{'abstained':1})
        self.assertEqual(got['activeTimingStrata']['worksheet_origin'],{'agree_usage':1,'over_reported_usage':4,'abstained':40})
        self.assertFalse(got['readyToClose124'])

    def test_provisional_case_cannot_be_reintroduced(self):
        root = self.fixture()
        folder = root / 'testdata/audit/appsecco-dvna'
        shutil.copyfile(folder / 'labels.provisional.json',folder / 'labels.json')
        with self.assertRaises(ValueError):
            summarise(root)

    def test_changed_label_identity_is_rejected(self):
        root = self.fixture()
        path = root / 'testdata/audit/gitaalekhyapaul-vuln-app/labels.json'
        doc = json.loads(path.read_text())
        doc['labels'][0]['purl'] = 'pkg:npm/wrong@1.0.0'
        path.write_text(json.dumps(doc))
        with self.assertRaises(ValueError):
            summarise(root)

    def test_duplicate_report_row_is_rejected(self):
        root = self.fixture()
        path = root / 'docs/evidence/s5-14/audit-results.json'
        doc = json.loads(path.read_text())
        doc['cases'][0]['rows'][0] = copy.deepcopy(doc['cases'][0]['rows'][1])
        path.write_text(json.dumps(doc))
        with self.assertRaises(ValueError):
            summarise(root)


if __name__ == '__main__':
    unittest.main()
