"""End-to-end tests using two archived amass JSONL snapshots.

Snapshot 2 introduces a new subdomain (staging.example.com), drops one
(old.example.com) and changes the IP of www.example.com — the diff engine
must catch all three.
"""

import json
import tempfile
import unittest
from pathlib import Path

from recon.db import ReconDB
from recon.differ import diff_scans
from recon.report import render_markdown
from recon.scanner import import_and_store, parse_json_lines

SNAP1 = [
    {"name": "example.com", "type": "fqdn", "addresses": [{"ip": "93.184.216.34"}],
     "tag": "dns", "sources": ["DNS"]},
    {"name": "www.example.com", "type": "fqdn", "addresses": [{"ip": "93.184.216.34"}],
     "tag": "dns", "sources": ["DNS"]},
    {"name": "mail.example.com", "type": "fqdn", "addresses": [{"ip": "93.184.216.40"}],
     "tag": "cert", "sources": ["Crtsh"]},
    {"name": "old.example.com", "type": "fqdn", "addresses": [{"ip": "93.184.216.99"}],
     "tag": "dns", "sources": ["DNS"]},
]

SNAP2 = [
    {"name": "example.com", "type": "fqdn", "addresses": [{"ip": "93.184.216.34"}],
     "tag": "dns", "sources": ["DNS"]},
    {"name": "www.example.com", "type": "fqdn", "addresses": [{"ip": "93.184.216.35"}],
     "tag": "dns", "sources": ["DNS"]},
    {"name": "mail.example.com", "type": "fqdn", "addresses": [{"ip": "93.184.216.40"}],
     "tag": "cert", "sources": ["Crtsh"]},
    {"name": "staging.example.com", "type": "fqdn", "addresses": [{"ip": "10.0.0.7"}],
     "tag": "api", "sources": ["AlienVault"]},
]


def _write_jsonl(path: Path, records) -> None:
    path.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")


class ParserTest(unittest.TestCase):
    def test_parse_skips_garbage(self):
        lines = ['{"name":"a.example.com","type":"fqdn"}', "not json", "", "{}"]
        assets = list(parse_json_lines(lines))
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].name, "a.example.com")


class PipelineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.db = ReconDB(root / "test.db")
        _write_jsonl(root / "snap1.jsonl", SNAP1)
        _write_jsonl(root / "snap2.jsonl", SNAP2)
        self.root = root

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_baseline_then_diff(self):
        id1, n1 = import_and_store(self.db, "example.com", str(self.root / "snap1.jsonl"))
        self.assertEqual(n1, 4)

        # Baseline: everything is new
        base = diff_scans("example.com", None, [], id1, self.db.get_assets(id1))
        self.assertEqual(len(base.new_assets), 4)

        id2, n2 = import_and_store(self.db, "example.com", str(self.root / "snap2.jsonl"))
        self.assertEqual(n2, 4)

        prev = self.db.previous_scan_id("example.com", id2)
        self.assertEqual(prev, id1)

        diff = diff_scans(
            "example.com", prev, self.db.get_assets(prev), id2, self.db.get_assets(id2)
        )
        self.assertEqual([a.name for a in diff.new_assets], ["staging.example.com"])
        self.assertEqual([a.name for a in diff.removed_assets], ["old.example.com"])
        self.assertEqual(len(diff.changed_assets), 1)
        self.assertEqual(diff.changed_assets[0][1].name, "www.example.com")
        self.assertEqual(diff.unchanged_count, 2)
        self.assertTrue(diff.has_changes)

    def test_report_mentions_changes(self):
        id1, _ = import_and_store(self.db, "example.com", str(self.root / "snap1.jsonl"))
        id2, _ = import_and_store(self.db, "example.com", str(self.root / "snap2.jsonl"))
        diff = diff_scans(
            "example.com", id1, self.db.get_assets(id1), id2, self.db.get_assets(id2)
        )
        md = render_markdown(diff)
        self.assertIn("staging.example.com", md)
        self.assertIn("old.example.com", md)
        self.assertIn("**1 new**", md)

    def test_no_change_between_identical_scans(self):
        id1, _ = import_and_store(self.db, "example.com", str(self.root / "snap1.jsonl"))
        id2, _ = import_and_store(self.db, "example.com", str(self.root / "snap1.jsonl"))
        diff = diff_scans(
            "example.com", id1, self.db.get_assets(id1), id2, self.db.get_assets(id2)
        )
        self.assertFalse(diff.has_changes)
        self.assertIn("No changes detected", render_markdown(diff))


if __name__ == "__main__":
    unittest.main()
