"""Only finite restore-trust delta fixtures; no full controller import, SDK, HTTP or native targets."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
import xml.etree.ElementTree as ET

TREE = ast.parse(Path(__file__).with_name("hosted_caps.py").read_text(encoding="utf-8"))
NODES = {n.name: n for n in TREE.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
CERTIFICATES = ast.literal_eval(next(n.value for n in TREE.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "RESTORE_REPOSITORY_CERTIFICATES" for t in n.targets)))
NAMES = ("Failure", "need", "save", "build_nuget_config", "validate_nuget_config", "observe_locked_restore_log", "capture_restore_diagnostic", "locked_offline_restore")
CODE = compile(ast.fix_missing_locations(ast.Module(body=[NODES[name] for name in NAMES], type_ignores=[])), "<isolated-restore-trust-source>", "exec")
INPUT_BYTES = 0


def fixture_input(data):
    global INPUT_BYTES
    INPUT_BYTES += len(data)
    if INPUT_BYTES > 524288:
        raise RuntimeError("Fixture input budget exceeded")
    return data


class RestoreTrustFixtures(unittest.TestCase):
    def setUp(self):
        parent = Path(os.environ["MATCHING10_SOURCE_FIXTURE_TEMP"]).resolve()
        temporary = tempfile.TemporaryDirectory(prefix="restore-trust-fixture-", dir=parent)
        self.addCleanup(temporary.cleanup)
        self.run = Path(temporary.name).resolve()
        self.assertTrue(self.run.is_relative_to(parent))
        self.env = {"Path": Path, "ET": ET, "hashlib": hashlib, "json": json, "re": re, "os": os, "RESTORE_REPOSITORY_CERTIFICATES": CERTIFICATES}
        exec(CODE, self.env)
        self.offline = 'E:/owned offline & <tag> "quote" snowman-\u2603'
        self.xml = fixture_input(self.env["build_nuget_config"](self.offline))
        self.policy = self.env["validate_nuget_config"](self.xml, self.offline)
        self.ctx = {"runRoot": self.run, "SDKLaunchAttempts": 3, "SDKProcessesStarted": 3, "lockedRestoreExitCode": 1}

    def reject_tree(self, tree, cause):
        data = fixture_input(ET.tostring(tree, encoding="utf-8"))
        with self.assertRaises(self.env["Failure"]) as raised:
            self.env["validate_nuget_config"](data, self.offline)
        self.assertEqual(raised.exception.cause, cause)

    def test_01_xml_escaping_roundtrips_controlled_path(self):
        tree = ET.fromstring(self.xml)
        self.assertEqual(tree.find("packageSources/add").attrib["value"], self.offline)
        self.assertIn(b"&amp;", self.xml)
        self.assertIn(b"&lt;", self.xml)
        self.assertIn(b"&quot;", self.xml)

    def test_02_exact_three_trust_pins_require_and_closed_feed(self):
        tree = ET.fromstring(self.xml)
        certs = tree.findall("trustedSigners/repository/certificate")
        self.assertEqual(len(certs), 3)
        self.assertEqual({c.attrib["fingerprint"] for c in certs}, set(CERTIFICATES))
        self.assertTrue(all(c.attrib["hashAlgorithm"] == "SHA256" and c.attrib["allowUntrustedRoot"] == "false" for c in certs))
        self.assertIsNotNone(tree.find("trustedSigners/clear"))
        self.assertEqual(tree.find("config/add").attrib["value"], "require")
        self.assertEqual(self.policy["configSHA256"], hashlib.sha256(self.xml).hexdigest())

    def test_03_missing_trust_section_denied(self):
        tree = ET.fromstring(self.xml); tree.remove(tree.find("trustedSigners"))
        self.reject_tree(tree, "NUGET_CONFIG_SECTIONS")

    def test_04_missing_certificate_denied(self):
        tree = ET.fromstring(self.xml); repo = tree.find("trustedSigners/repository"); repo.remove(repo[0])
        self.reject_tree(tree, "NUGET_CONFIG_EXACT_TRUST_SET")

    def test_05_foreign_certificate_denied(self):
        tree = ET.fromstring(self.xml); tree.find("trustedSigners/repository/certificate").set("fingerprint", "F" * 64)
        self.reject_tree(tree, "NUGET_CONFIG_EXACT_TRUST_SET")

    def test_06_untrusted_root_true_denied(self):
        tree = ET.fromstring(self.xml); tree.find("trustedSigners/repository/certificate").set("allowUntrustedRoot", "true")
        self.reject_tree(tree, "NUGET_CONFIG_EXACT_TRUST_SET")

    def test_07_accept_mode_denied(self):
        tree = ET.fromstring(self.xml); tree.find("config/add").set("value", "accept")
        self.reject_tree(tree, "NUGET_CONFIG_REQUIRE")

    def test_08_foreign_online_package_feed_denied(self):
        tree = ET.fromstring(self.xml); tree.find("packageSources/add").set("value", "https://foreign.invalid/packages")
        self.reject_tree(tree, "NUGET_CONFIG_CLOSED_SOURCE")

    def test_09_extra_fallback_denied(self):
        tree = ET.fromstring(self.xml); ET.SubElement(tree.find("fallbackPackageFolders"), "add", {"key": "foreign", "value": "ENV_SENTINEL"})
        self.reject_tree(tree, "NUGET_CONFIG_FALLBACK")

    def test_10_extra_author_trust_denied(self):
        tree = ET.fromstring(self.xml); ET.SubElement(tree.find("trustedSigners"), "author", {"name": "foreign"})
        self.reject_tree(tree, "NUGET_CONFIG_TRUST_REPOSITORY")

    def test_11_wrong_repository_service_index_denied(self):
        tree = ET.fromstring(self.xml); tree.find("trustedSigners/repository").set("serviceIndex", "https://foreign.invalid/index.json")
        self.reject_tree(tree, "NUGET_CONFIG_TRUST_REPOSITORY")

    def test_12_dtd_denied_without_entity_resolution(self):
        data = fixture_input(b'<!DOCTYPE configuration [<!ENTITY x "ENV_SENTINEL">]><configuration/>')
        with self.assertRaises(self.env["Failure"]) as raised:
            self.env["validate_nuget_config"](data, self.offline)
        self.assertEqual(raised.exception.cause, "NUGET_CONFIG_XML_CAP_OR_DTD")

    def test_13_diagnostic_bytehash_code_limit_and_redaction(self):
        data = fixture_input(b'private/path?env=ENV_SENTINEL argv locals https://private.invalid\nerror NU3034: secret\nerror MSB4018: secret\nerror NETSDK1004: secret\n' + b''.join(('error NU%04d: secret\n' % (1100 + i)).encode() for i in range(30)) + b'warning NU9999: not-an-error\nerror NU12345: not-four-digits\n')
        (self.run / "locked-offline-restore.log").write_bytes(data)
        report = self.env["capture_restore_diagnostic"](self.ctx, self.policy, self.env["Failure"]("COMMAND_FAILED", "ENV_SENTINEL"))
        encoded = json.dumps(report)
        self.assertEqual(report["byteCount"], len(data))
        self.assertEqual(report["byteSHA256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(report["actualExitCode"], 1)
        self.assertEqual(report["SDKProcessesStartedByController"], 3)
        self.assertEqual(len(report["errorCodes"]), 32)
        self.assertTrue(report["codeLimitReached"])
        self.assertNotIn("NU9999", report["errorCodes"])
        self.assertNotIn("NU12345", report["errorCodes"])
        for secret in ("ENV_SENTINEL", "private/path", "https://", "argv", "locals", str(self.run)):
            self.assertNotIn(secret, encoded)
        self.assertLessEqual(len(encoded.encode()), 8192)

    def test_14_missing_log_is_unknown(self):
        report = self.env["capture_restore_diagnostic"](self.ctx, self.policy)
        self.assertEqual(report["state"], "UNKNOWN_MISSING")
        self.assertIsNone(report["byteSHA256"])
        self.assertEqual(report["errorCodes"], [])

    def test_15_oversize_metadata_is_unknown_without_body_read(self):
        class OversizeOwnedLog:
            def is_symlink(self): return False
            def is_file(self): return True
            def stat(self): return SimpleNamespace(st_size=8388609)
            def open(self, *args): raise AssertionError("Oversize body must not be read")
        report = self.env["observe_locked_restore_log"](OversizeOwnedLog())
        self.assertEqual(report["state"], "UNKNOWN_OVERSIZE")
        self.assertIsNone(report["byteSHA256"])

    def test_16_unparsed_log_is_unknown_with_exact_bytehash(self):
        data = fixture_input(b'\x8bENV_SENTINEL unknown output without allowed errors')
        (self.run / "locked-offline-restore.log").write_bytes(data)
        report = self.env["capture_restore_diagnostic"](self.ctx, self.policy)
        self.assertEqual(report["state"], "UNKNOWN_NO_ALLOWLISTED_ERROR_CODES")
        self.assertEqual(report["byteSHA256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(report["errorCodes"], [])

    def test_17_primary_restore_failure_survives_diagnostic_failure(self):
        config = self.run / "NuGet.Config"; config.write_bytes(self.xml)
        primary = self.env["Failure"]("COMMAND_FAILED", "locked-offline-restore exit=1")
        calls = []
        def failed_command(ctx, argv, name, cap, sdk):
            calls.append((argv, name, cap, sdk)); raise primary
        def failed_diagnostic(*args): raise self.env["Failure"]("SECONDARY_DIAGNOSTIC_FAILURE")
        self.env["command"] = failed_command; self.env["capture_restore_diagnostic"] = failed_diagnostic
        with self.assertRaises(self.env["Failure"]) as raised:
            self.env["locked_offline_restore"](self.ctx, "FAKE_SDK_NOT_EXECUTED", config, self.run / "packages", self.offline)
        self.assertIs(raised.exception, primary)
        self.assertIn("--locked-mode", calls[0][0])
        self.assertIn("--configfile", calls[0][0])
        self.assertEqual(calls[0][1:], ("locked-offline-restore", 180, True))

    def test_18_exact_config_guard_stops_before_mock_sdk(self):
        tree = ET.fromstring(self.xml); tree.find("auditSources/add").set("value", "https://foreign.invalid/index.json")
        config = self.run / "NuGet.Config"; config.write_bytes(fixture_input(ET.tostring(tree, encoding="utf-8")))
        calls = []
        self.env["command"] = lambda *args, **kwargs: calls.append(True)
        with self.assertRaises(self.env["Failure"]) as raised:
            self.env["locked_offline_restore"](self.ctx, "FAKE_SDK_NOT_EXECUTED", config, self.run / "packages", self.offline)
        self.assertEqual(raised.exception.cause, "NUGET_CONFIG_AUDIT_SOURCE")
        self.assertEqual(calls, [])


if __name__ == "__main__":
    started = time.monotonic()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RestoreTrustFixtures)
    if suite.countTestCases() != 18:
        raise RuntimeError("Exactly eighteen delta fixtures required")
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    elapsed = time.monotonic() - started
    print(json.dumps({"tests": result.testsRun, "inputBytes": INPUT_BYTES, "seconds": elapsed, "SDK": 0, "HTTP": 0, "native": 0, "fullControllerImport": False, "optimization": sys.flags.optimize}))
    raise SystemExit(0 if result.wasSuccessful() and elapsed <= 30 and INPUT_BYTES <= 524288 else 1)
