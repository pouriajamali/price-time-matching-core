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
ENV = {"re": re, "base64": base64, "json": json, "os": os, "Path": Path, "hashlib": __import__("hashlib"), "REPO_CERT": REPO_CERT, "MS_CERT": MS_CERT}
MODULE = ast.Module(body=[FUNCTIONS[n] for n in ("Failure", "need", "save", "signature_observations", "signature_diagnostic")], type_ignores=[])
exec(compile(ast.fix_missing_locations(MODULE), "<isolated-diagnostic-source>", "exec"), ENV)
NORMALIZED = base64.b64encode(bytes(range(64))).decode("ascii")
SPEC = {"id": "microsoft.bcl.asyncinterfaces", "version": "6.0.0", "implicit": False, "rawSHA512": "0" * 128, "normalized": NORMALIZED}
OLD_REPOSITORY_DATA = "5A2901D6ADA3D18260B9C6DFE2133C95D74B9EEF6AE0E5DC334C8454D1477DF4"


def fixture(repo_cert=REPO_CERT):
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
        self.assertEqual(row["observedFingerprintHexBySection"]["repository"], [REPO_CERT])

    def test_old_certificate_remains_denied(self):
        row = self.observation(fixture(OLD_REPOSITORY_DATA))["packages"][0]
        self.assertEqual(row["repositoryObservation"], "OBSERVED_REPOSITORY_CERT_MISMATCH")
        with self.assertRaises(ENV["Failure"]) as raised:
            exec(PIN_GUARD, dict(ENV, signatures={"repository": OLD_REPOSITORY_DATA}, identity=SPEC["id"]))
        self.assertEqual(raised.exception.cause, "NUGET_REPOSITORY_CERT_MISMATCH")

    def test_absent_repository_and_unknown_partition_are_distinct(self):
        self.assertEqual(self.observation(fixture(None))["packages"][0]["repositoryObservation"], "ABSENT_REPOSITORY_SECTION")
        self.assertEqual(self.observation(fixture() + fixture())["packages"][0]["repositoryObservation"], "PARSER_PARTITION_UNKNOWN")
        with self.assertRaises(ENV["Failure"]) as raised:
            exec(PIN_GUARD, dict(ENV, signatures={}, identity=SPEC["id"]))
        self.assertEqual(raised.exception.cause, "NUGET_REPOSITORY_SIGNATURE_ABSENT")

    def test_unknown_fingerprint_never_becomes_cert_match(self):
        row = self.observation(fixture().replace("SHA256 hash: " + REPO_CERT, "SHA256 hash: private/path?query=ENV_SENTINEL"))["packages"][0]
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
            inspected = {SPEC["id"]: {"raw": {"bytes": 123, "sha256": "4" * 64, "sha512": "5" * 128, "url": "https://never-export.invalid/private?ENV_SENTINEL"}}}
            report = ENV["signature_diagnostic"](ctx, [SPEC], inspected)
            encoded = json.dumps(report)
            self.assertNotIn("ENV_SENTINEL", encoded)
            self.assertNotIn("/private", encoded)
            self.assertNotIn("https://", encoded)
            self.assertNotIn("rawBase64", encoded)
            self.assertEqual(report["status"], "OBSERVABILITY_ONLY_NOT_ADMISSION")
            self.assertTrue(report["inputCompleteWithinCap"])
            self.assertLess(len(encoded.encode()), 131072)

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
