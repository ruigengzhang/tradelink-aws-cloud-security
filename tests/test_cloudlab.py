import json
import subprocess
import sys
import unittest
from pathlib import Path

from cloudlab.scanner import SnapshotError, compare, scan


ROOT = Path(__file__).resolve().parents[1]


def fixture(name):
    return json.loads((ROOT / "fixtures" / (name + ".json")).read_text(encoding="utf-8"))


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.baseline = fixture("baseline")
        self.fixed = fixture("remediated")

    def test_baseline_identifies_exactly_three_risks(self):
        result = scan(self.baseline)
        self.assertEqual(len(result.inventory), 4)
        self.assertEqual(
            [(item.rule, item.severity) for item in result.findings],
            [("TL-EC2-01", "High"), ("TL-IAM-01", "High"), ("TL-S3-01", "Medium")],
        )

    def test_retest_keeps_inventory_and_resolves_all_three(self):
        result = compare(scan(self.baseline), scan(self.fixed))
        self.assertEqual(len(result["resolved"]), 3)
        self.assertEqual(result["still_open"], [])
        self.assertEqual(result["new"], [])

    def test_compare_classifies_remaining_and_new_findings(self):
        self.baseline["s3_buckets"][1]["public_access_block"]["BlockPublicAcls"] = False
        first = scan(fixture("baseline"))
        result = compare(first, scan(self.baseline))
        self.assertEqual(len(result["still_open"]), 3)
        self.assertEqual(len(result["new"]), 1)
        self.assertEqual(result["resolved"], [])

    def test_omitted_resource_cannot_be_reported_as_fixed(self):
        self.fixed["iam_policies"].clear()
        with self.assertRaisesRegex(SnapshotError, "Missing: iam_policies/TradeDocumentsWorker"):
            compare(scan(self.baseline), scan(self.fixed))

    def test_s3_combines_account_and_bucket_flags(self):
        flags = self.baseline["account_public_access_block"]
        flags.update(BlockPublicPolicy=True, RestrictPublicBuckets=True)
        self.assertNotIn("TL-S3-01", {finding.rule for finding in scan(self.baseline).findings})

    def test_s3_missing_flag_is_a_validation_error(self):
        del self.fixed["s3_buckets"][0]["public_access_block"]["IgnorePublicAcls"]
        with self.assertRaisesRegex(SnapshotError, "IgnorePublicAcls must be bool"):
            scan(self.fixed)

    def test_policy_lists_with_wildcards_still_match(self):
        policy = self.fixed["iam_policies"][0]
        policy["Statement"].append(
            {"Effect": "Allow", "Action": ["s3:GetObject", "*"], "Resource": ["*"]}
        )
        self.assertEqual([f.rule for f in scan(self.fixed).findings], ["TL-IAM-01"])

    def test_narrower_deny_or_conditional_policies_do_not_match_rule(self):
        for statement in [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
            {"Effect": "Deny", "Action": "*", "Resource": "*"},
            {"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"},
            {"Effect": "Allow", "Action": "*", "NotResource": "arn:aws:s3:::demo/*"},
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
            },
        ]:
            with self.subTest(statement=statement):
                self.fixed["iam_policies"][0]["Statement"] = [statement]
                self.assertEqual(scan(self.fixed).findings, ())

    def test_ipv6_port_range_and_all_protocols_match(self):
        for rule in [
            {"protocol": "tcp", "from_port": 20, "to_port": 23, "sources": ["::/0"]},
            {"protocol": "-1", "sources": ["0.0.0.0/0"]},
        ]:
            with self.subTest(rule=rule):
                self.fixed["security_groups"][0]["ingress"] = [rule]
                self.assertEqual([f.rule for f in scan(self.fixed).findings], ["TL-EC2-01"])

    def test_udp_private_ssh_and_public_https_do_not_match(self):
        self.fixed["security_groups"][0]["ingress"] = [
            {"protocol": "udp", "from_port": 22, "to_port": 22, "sources": ["0.0.0.0/0"]},
            {"protocol": "tcp", "from_port": 22, "to_port": 22, "sources": ["10.0.0.0/8"]},
            {"protocol": "tcp", "from_port": 443, "to_port": 443, "sources": ["0.0.0.0/0"]},
        ]
        self.assertEqual(scan(self.fixed).findings, ())

    def test_invalid_cidr_is_a_validation_error(self):
        self.fixed["security_groups"][0]["ingress"][0]["sources"] = ["bad-source"]
        with self.assertRaisesRegex(SnapshotError, "invalid CIDR"):
            scan(self.fixed)

    def test_duplicate_id_is_a_validation_error(self):
        self.fixed["s3_buckets"].append(self.fixed["s3_buckets"][0])
        with self.assertRaisesRegex(SnapshotError, "Duplicate resource ID"):
            scan(self.fixed)


class CliTests(unittest.TestCase):
    def cli(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "cloudlab", *args],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )

    def test_scan_prints_machine_readable_evidence(self):
        result = self.cli("scan", "fixtures/baseline.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["resources_assessed"], 4)
        self.assertEqual(len(payload["findings"]), 3)
        self.assertIn("remediation", payload["findings"][0])

    def test_compare_succeeds_after_fix(self):
        result = self.cli("compare", "fixtures/baseline.json", "fixtures/remediated.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Resolved: 3", result.stdout)
        self.assertIn("Still Open: 0", result.stdout)

    def test_compare_fails_when_findings_remain(self):
        result = self.cli("compare", "fixtures/baseline.json", "fixtures/baseline.json")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Still Open: 3", result.stdout)

    def test_missing_snapshot_returns_error_without_traceback(self):
        result = self.cli("scan", "fixtures/does-not-exist.json")
        self.assertEqual(result.returncode, 2)
        self.assertIn("does-not-exist.json", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
