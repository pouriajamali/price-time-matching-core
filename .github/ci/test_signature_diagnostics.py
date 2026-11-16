"""Finite source-fixture checks; never import the controller or invoke SDK/OS/network APIs."""
import ast
import base64
import json
import os
from pathlib import Path
import re
import tempfile
import unittest

SOURCE = Path(__file__).with_name("hosted_caps.py")
TREE = ast.parse(SOURCE.read_text(encoding="utf-8"))
FUNCTIONS = {n.name: n for n in TREE.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
REPO_CERT = next(ast.literal_eval(n.value) for n in TREE.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "REPO_CERT" for t in n.targets))
MS_CERT = next(ast.literal_eval(n.value) for n in TREE.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "MS_CERT" for t in n.targets))
TEST_PACKAGES = json.loads(ast.literal_eval(next(n.value.args[0] for n in TREE.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "TEST_PACKAGES" for t in n.targets))))
ENV = {"re": re, "base64": base64, "json": json, "os": os, "Path": Path, "hashlib": __import__("hashlib"), "REPO_CERT": REPO_CERT, "MS_CERT": MS_CERT, "TEST_PACKAGES": TEST_PACKAGES}
MODULE = ast.Module(body=[FUNCTIONS[n] for n in ("Failure", "need", "save", "test_repository_pin", "signature_observations", "signature_diagnostic")], type_ignores=[])
exec(compile(ast.fix_missing_locations(MODULE), "<isolated-diagnostic-source>", "exec"), ENV)
SPEC = dict(TEST_PACKAGES["microsoft.bcl.asyncinterfaces"])
NORMALIZED = SPEC["normalized"]
EXPECTED_BCL_REPOSITORY = SPEC["repositoryCertificate"]
OLD_REPOSITORY_DATA = "5A2901D6ADA3D18260B9C6DFE2133C95D74B9EEF6AE0E5DC334C8454D1477DF4"


def fixture(repo_cert=EXPECTED_BCL_REPOSITORY):
    return ("Verifying microsoft.bcl.asyncinterfaces.6.0.0\n"
            "/private-fixture-only/never-export?query=ENV_SENTINEL\n"
            "Content hash: " + NORMALIZED + "\nSignature type: Author\nSHA256 hash: " + "A" * 64 +
            ("\nSignature type: Repository\nSHA256 hash: " + repo_cert if repo_cert else "") + "\n")


def isolated_guard(function, causes, arguments):
    statements = [n for n in ast.walk(FUNCTIONS[function]) if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
                  and isinstance(n.value.func, ast.Name) and n.value.func.id == "need" and len(n.value.args) > 1
                  and isinstance(n.value.args[1], ast.Constant) and n.value.args[1].value in causes]
    assert len(statements) == len(causes)
    return compile(ast.fix_missing_locations(ast.Module(body=statements, type_ignores=[])), "<isolated-policy-guards>", "exec")


PIN_GUARD = isolated_guard("input_policy", {"NUGET_REPOSITORY_SIGNATURE_ABSENT", "NUGET_REPOSITORY_CERT_MISMATCH"}, ())
CHILD_GUARD = isolated_guard("linux_parent", {"CHILD_FAILED", "CHILD_PREEXIT_MEMBERSHIP"}, ())


class SignatureDiagnosticFixtures(unittest.TestCase):
    def observation(self, text, exit_code=0):
        return ENV["signature_observations"](text, [SPEC], exit_code)

    def test_exact_pin_is_observation_only(self):
        row = self.observation(fixture())["packages"][0]
        self.assertEqual(row["repositoryObservation"], "OBSERVED_REPOSITORY_PIN_MATCH")
        self.assertEqual(row["normalizedContentHashObserved"], NORMALIZED)
        self.assertEqual(row["observedFingerprintHexBySection"]["repository"], [EXPECTED_BCL_REPOSITORY])

    def test_runtime_certificate_is_not_fallback_for_bcl(self):
        row = self.observation(fixture(REPO_CERT))["packages"][0]
        self.assertEqual(row["repositoryObservation"], "OBSERVED_REPOSITORY_CERT_MISMATCH")
        with self.assertRaises(ENV["Failure"]) as raised:
            exec(PIN_GUARD, dict(ENV, signatures={"repository": REPO_CERT}, expected_repository=EXPECTED_BCL_REPOSITORY, identity=SPEC["id"]))
        self.assertEqual(raised.exception.cause, "NUGET_REPOSITORY_CERT_MISMATCH")

    def test_absent_repository_and_unknown_partition_are_distinct(self):
        self.assertEqual(self.observation(fixture(None))["packages"][0]["repositoryObservation"], "ABSENT_REPOSITORY_SECTION")
        self.assertEqual(self.observation(fixture() + fixture())["packages"][0]["repositoryObservation"], "PARSER_PARTITION_UNKNOWN")
        with self.assertRaises(ENV["Failure"]) as raised:
            exec(PIN_GUARD, dict(ENV, signatures={}, identity=SPEC["id"]))
        self.assertEqual(raised.exception.cause, "NUGET_REPOSITORY_SIGNATURE_ABSENT")

    def test_unknown_fingerprint_never_becomes_cert_match(self):
        row = self.observation(fixture().replace("SHA256 hash: " + EXPECTED_BCL_REPOSITORY, "SHA256 hash: private/path?query=ENV_SENTINEL"))["packages"][0]
        self.assertEqual(row["repositoryObservation"], "PARSER_FINGERPRINT_FIELD_UNKNOWN")
        self.assertEqual(row["observedFingerprintHexBySection"]["repository"], [])

    def test_failed_verify_and_missing_output_remain_unknown_or_failed(self):
        self.assertEqual(self.observation(fixture(), 1)["verifyOutcome"], "VERIFY_EXIT_FAILURE")
        report = self.observation("", None)
        self.assertEqual(report["verifyOutcome"], "VERIFY_EXIT_UNKNOWN")
        self.assertEqual(report["packages"][0]["repositoryObservation"], "PARSER_PARTITION_UNKNOWN")

    def test_report_has_no_raw_stderr_path_query_or_environment(self):
        temp_root = Path(os.environ["MATCHING10_SOURCE_FIXTURE_TEMP"]).resolve()
        with tempfile.TemporaryDirectory(prefix="signature-fixture-", dir=temp_root) as directory:
            run = Path(directory).resolve()
            self.assertTrue(run.is_relative_to(temp_root))
            (run / "nuget-signatures.log").write_text(fixture(), encoding="utf-8")
            ctx = {"runRoot": str(run), "rid": "linux-x64", "binding": {"source": "1" * 40, "controllerSHA256": "2" * 64, "payloadSHA256": "3" * 64}, "signatureVerifyExitCode": 0, "SDKLaunchAttempts": 2, "SDKProcessesStarted": 2}
            inspected = {SPEC["id"]: {"raw": {"bytes": 123, "sha256": "4" * 64, "sha512": "5" * 128, "url": "https://never-export.invalid/private?ENV_SENTINEL"}, "signatureFileSHA256": SPEC["signatureFileSHA256"]}}
            report = ENV["signature_diagnostic"](ctx, [SPEC], inspected)
            encoded = json.dumps(report)
            self.assertNotIn("ENV_SENTINEL", encoded)
            self.assertNotIn("/private", encoded)
            self.assertNotIn("https://", encoded)
            self.assertNotIn("rawBase64", encoded)
            self.assertEqual(report["status"], "OBSERVABILITY_ONLY_NOT_ADMISSION")
            self.assertTrue(report["inputCompleteWithinCap"])
            self.assertLess(len(encoded.encode()), 131072)

    def test_mixed_era_pins_bind_each_exact_identity(self):
        old = SPEC
        new = TEST_PACKAGES["xunit.v3"]
        for spec in (old, new):
            pin = ENV["test_repository_pin"](spec["id"], spec["version"], spec["rawSHA512"], spec["normalized"], spec["signatureFileSHA256"])
            self.assertEqual(pin, spec["repositoryCertificate"])
        self.assertEqual(old["repositoryCertificate"], OLD_REPOSITORY_DATA)
        self.assertEqual(new["repositoryCertificate"], REPO_CERT)
        new_output = fixture().replace("microsoft.bcl.asyncinterfaces.6.0.0", "xunit.v3.4.0.3").replace(NORMALIZED, new["normalized"]).replace(EXPECTED_BCL_REPOSITORY, REPO_CERT)
        rows = ENV["signature_observations"](fixture() + new_output, [old, new], 0)["packages"]
        self.assertTrue(all(row["repositoryObservation"] == "OBSERVED_REPOSITORY_PIN_MATCH" for row in rows))

    def test_changed_raw_normalized_cms_or_version_is_denied(self):
        values = [SPEC["id"], SPEC["version"], SPEC["rawSHA512"], SPEC["normalized"], SPEC["signatureFileSHA256"]]
        for index, changed, cause in ((0, "unknown.package", "TEST_SIGNER_PACKAGE_IDENTITY"),
                                       (1, "6.0.1", "TEST_SIGNER_PACKAGE_IDENTITY"),
                                       (2, "0" * 128, "TEST_SIGNER_RAW_IDENTITY"),
                                       (3, base64.b64encode(bytes(64)).decode(), "TEST_SIGNER_NORMALIZED_IDENTITY"),
                                       (4, "0" * 64, "TEST_SIGNER_SIGNATURE_FILE_IDENTITY")):
            with self.subTest(field=index):
                candidate = list(values); candidate[index] = changed
                with self.assertRaises(ENV["Failure"]) as raised:
                    ENV["test_repository_pin"](*candidate)
                self.assertEqual(raised.exception.cause, cause)

    def test_insufficient_provenance_holds_only_that_package(self):
        spec = TEST_PACKAGES["microsoft.win32.registry"]
        self.assertIsNone(spec["repositoryCertificate"])
        with self.assertRaises(ENV["Failure"]) as raised:
            ENV["test_repository_pin"](spec["id"], spec["version"], spec["rawSHA512"], spec["normalized"], spec["signatureFileSHA256"])
        self.assertEqual(raised.exception.cause, "TEST_SIGNER_PROVENANCE_UNKNOWN")
        self.assertEqual(ENV["test_repository_pin"](SPEC["id"], SPEC["version"], SPEC["rawSHA512"], SPEC["normalized"], SPEC["signatureFileSHA256"]), EXPECTED_BCL_REPOSITORY)

    def test_failed_sdk_verify_still_stops_before_pin_admission(self):
        code = isolated_guard("command", {"COMMAND_FAILED"}, ())
        fake = type("FakeExit", (), {"returncode": 1})()
        with self.assertRaises(ENV["Failure"]) as raised:
            exec(code, dict(ENV, proc=fake, expected=0, name="nuget-signatures"))
        self.assertEqual(raised.exception.cause, "COMMAND_FAILED")

    def test_failed_child_preserves_primary_cause(self):
        result = {"status": "FAIL_INCOMPLETE", "error": {"cause": "NUGET_REPOSITORY_SIGNER"}, "naturalMembersBeforeExit": None}
        with self.assertRaises(ENV["Failure"]) as raised:
            exec(CHILD_GUARD, dict(ENV, result=result, identity={"pid": 7}))
        self.assertEqual(raised.exception.cause, "CHILD_FAILED")
        self.assertIn("NUGET_REPOSITORY_SIGNER", str(raised.exception))

    def test_remaining_child_is_still_denied(self):
        with self.assertRaises(ENV["Failure"]) as raised:
            exec(CHILD_GUARD, dict(ENV, result={"status": "PASS", "naturalMembersBeforeExit": [7, 8]}, identity={"pid": 7}))
        self.assertEqual(raised.exception.cause, "CHILD_PREEXIT_MEMBERSHIP")
        exec(CHILD_GUARD, dict(ENV, result={"status": "PASS", "naturalMembersBeforeExit": [7]}, identity={"pid": 7}))

    def test_forced_cleanup_cannot_pass(self):
        for name in ("linux_parent", "windows_parent"):
            result = next(n for n in ast.walk(FUNCTIONS[name]) if isinstance(n, ast.Dict) and {"status", "forcedCleanup", "allOwnedTerminal"} <= {k.value for k in n.keys if isinstance(k, ast.Constant)})
            expression = result.values[next(i for i, k in enumerate(result.keys) if isinstance(k, ast.Constant) and k.value == "status")]
            code = compile(ast.fix_missing_locations(ast.Expression(body=expression)), "<isolated-terminal-expression>", "eval")
            self.assertEqual(eval(code, {"error": None, "terminal": True, "forced": True, "active_before": 0}), "FAIL_INCOMPLETE")


if __name__ == "__main__":
    unittest.main()
