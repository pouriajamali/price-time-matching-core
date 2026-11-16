"""Finite offline metadata fixtures. HTTP is replaced by an in-memory response; no controller import."""
import ast
from email.message import Message
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tempfile
import time
from types import SimpleNamespace
import unittest
import urllib.request
import zlib

TREE = ast.parse(Path(__file__).with_name("hosted_caps.py").read_text(encoding="utf-8"))
NODES = {node.name: node for node in TREE.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
NAMES = ("Failure", "need", "unique", "load", "save", "remaining", "bounded_get", "metadata_transport_receipt", "decode_metadata_bytes", "bounded_json_get", "vulnerability_page_entries")
CODE = compile(ast.fix_missing_locations(ast.Module(body=[NODES[name] for name in NAMES], type_ignores=[])), "<isolated-metadata-source>", "exec")
URL = "https://api.nuget.org/v3/vulnerabilities/index.json"
PLAIN = b'{"key":"value"}'


class Response:
    status = 200

    def __init__(self, body, headers, url):
        self.stream = io.BytesIO(body)
        self.headers = Message()
        for key, value in headers:
            self.headers.add_header(key, value)
        self.url = url
        self.reads = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stream.close()

    def read(self, size):
        self.reads += 1
        return self.stream.read(size)

    def geturl(self):
        return self.url


class MetadataTransportFixtures(unittest.TestCase):
    def setUp(self):
        parent = Path(os.environ["MATCHING10_SOURCE_FIXTURE_TEMP"]).resolve()
        self.temporary = tempfile.TemporaryDirectory(prefix="metadata-fixture-", dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.assertTrue(self.root.is_relative_to(parent))
        self.serial = 0
        self.parses = 0
        self.env = {"Path": Path, "hashlib": hashlib, "json": json, "os": os, "re": re, "time": time, "zlib": zlib}
        exec(CODE, self.env)
        original_load = self.env["load"]

        def parse_after_receipt(path, cap):
            receipt = json.loads((self.context["runRoot"] / "advisory-transport.json").read_bytes())
            row = receipt["records"][-1]
            self.assertEqual(row["status"], "DECODED_BEFORE_PARSE")
            self.assertTrue(row["rawComplete"] and row["decodedComplete"])
            self.assertIsNotNone(row["rawSHA256"])
            self.assertIsNotNone(row["decodedSHA256"])
            self.parses += 1
            return original_load(path, cap)

        self.env["load"] = parse_after_receipt
        self.env["budget"] = lambda ctx, force=False: self.env["remaining"](ctx)
        self.env["stage"] = lambda ctx, name, cap: ctx.setdefault("stages", []).append((name, cap))

    def run_case(self, body, encoding="identity", limit=100000, headers=None, total=None, url=URL, expired=False):
        self.serial += 1
        run = self.root / str(self.serial)
        run.mkdir()
        self.context = {"runRoot": run, "binding": {"source": "1" * 40}, "rid": "linux-x64", "deadlineMono": time.monotonic() + (-1 if expired else 30)}
        deadline = self.context["deadlineMono"]
        supplied = [("Content-Length", str(len(body)))] if headers is None else list(headers)
        if encoding is not None:
            supplied.append(("Content-Encoding", encoding))
        self.response = Response(body, supplied, url)

        def open_offline(request, timeout):
            self.assertEqual(request.get_header("Accept-encoding"), "identity")
            self.assertEqual(request.get_header("User-agent"), "Matching10-BoundedInput/1")
            self.assertLessEqual(timeout, 30)
            self.assertEqual(request.full_url, url)
            return self.response

        self.env["urllib"] = SimpleNamespace(request=SimpleNamespace(HTTPRedirectHandler=urllib.request.HTTPRedirectHandler, Request=urllib.request.Request, build_opener=lambda *args: SimpleNamespace(open=open_offline)))
        try:
            return self.env["bounded_json_get"](self.context, url, run / "index.json", limit, [0] if total is None else total, "vulnerability-index")
        finally:
            self.assertEqual(self.context["deadlineMono"], deadline)

    def receipt(self):
        return json.loads((self.context["runRoot"] / "advisory-transport.json").read_bytes())["records"][-1]

    def denied(self, cause, *args, **kwargs):
        before = self.parses
        with self.assertRaises(self.env["Failure"]) as raised:
            self.run_case(*args, **kwargs)
        self.assertEqual(raised.exception.cause, cause)
        self.assertEqual(self.receipt()["failureCause"], cause)
        return before

    def test_identity_json_and_preparse_receipt(self):
        record, data = self.run_case(PLAIN)
        self.assertEqual(data, {"key": "value"})
        self.assertEqual(record["bytes"], 2 * len(PLAIN))
        self.assertEqual(self.receipt()["decodedSHA256"], hashlib.sha256(PLAIN).hexdigest())
        self.assertEqual(self.parses, 1)

    def test_single_gzip_json_and_preparse_receipt(self):
        wire = gzip.compress(PLAIN, mtime=0)
        record, data = self.run_case(wire, "gzip")
        self.assertEqual(data, {"key": "value"})
        self.assertEqual(record["bytes"], len(wire) + len(PLAIN))
        self.assertEqual(self.receipt()["rawSHA256"], hashlib.sha256(wire).hexdigest())
        self.assertTrue(self.receipt()["decodedComplete"])

    def test_gzip_crc_and_isize_corruption_denied(self):
        for position in (-8, -4):
            wire = bytearray(gzip.compress(PLAIN, mtime=0)); wire[position] ^= 1
            with self.subTest(trailer=position):
                self.denied("METADATA_GZIP_CRC_OR_FORMAT_INVALID", bytes(wire), "gzip")
                self.assertFalse(self.receipt()["parseAttempted"])

    def test_truncated_gzip_denied(self):
        self.denied("METADATA_GZIP_TRUNCATED", gzip.compress(PLAIN, mtime=0)[:-3], "gzip")
        self.assertFalse(self.receipt()["decodedComplete"])

    def test_inflate_bomb_and_combined_cap_denied(self):
        wire = gzip.compress(b"A" * 100000, mtime=0)
        self.denied("METADATA_DECODED_BYTES_CAP", wire, "gzip", limit=len(wire) + 64)
        self.assertFalse(self.receipt()["parseAttempted"])
        self.denied("METADATA_DECODED_BYTES_CAP", PLAIN, limit=2 * len(PLAIN) - 1)

    def test_trailing_and_multimember_denied(self):
        wire = gzip.compress(PLAIN, mtime=0)
        for extra in (b"trailing", gzip.compress(b"{}", mtime=0)):
            with self.subTest(extra=extra[:8]):
                self.denied("METADATA_GZIP_TRAILING_OR_MULTIMEMBER", wire + extra, "gzip")
                self.assertFalse(self.receipt()["parseAttempted"])

    def test_unsupported_encoding_and_header_magic_mismatch_denied(self):
        self.denied("METADATA_CONTENT_ENCODING_UNSUPPORTED", PLAIN, "br;path=/private?ENV_SENTINEL")
        self.assertEqual(self.response.reads, 0)
        self.denied("METADATA_ENCODING_HEADER_MISMATCH", gzip.compress(PLAIN, mtime=0), None)
        self.denied("METADATA_ENCODING_HEADER_MISMATCH", PLAIN, "gzip")

    def test_header_length_and_duplicate_encoding_denied(self):
        self.denied("METADATA_DUPLICATE_ENCODING_OR_LENGTH", PLAIN, "identity", headers=[("Content-Encoding", "gzip")])
        self.denied("METADATA_CONTENT_LENGTH_MISMATCH", PLAIN, headers=[("Content-Length", "1")])

    def test_invalid_utf8_json_and_duplicate_field_denied(self):
        self.denied("METADATA_UTF8_INVALID", b"\xff")
        self.denied("METADATA_JSON_INVALID", b"not-json")
        self.denied("DUPLICATE_JSON_FIELD", b'{"key":1,"key":2}')

    def test_aggregate_total_and_absolute_deadline_remain_bounded(self):
        self.denied("INPUT_TRANSPORT_BYTES", PLAIN, total=[536870912 - len(PLAIN) - 1])
        self.denied("ROW_MONOTONIC_DEADLINE", PLAIN, expired=True)
        self.assertFalse(self.receipt()["parseAttempted"])

    def test_receipt_has_no_body_url_path_query_or_environment(self):
        self.denied("METADATA_CONTENT_ENCODING_UNSUPPORTED", PLAIN, "br;ENV_SENTINEL", url=URL + "?private=ENV_SENTINEL")
        encoded = json.dumps(self.receipt())
        for forbidden in ("ENV_SENTINEL", "https://", "private", str(self.root), PLAIN.decode()):
            self.assertNotIn(forbidden, encoded)

    def test_receipt_write_failure_does_not_replace_primary_failure(self):
        original = self.env["metadata_transport_receipt"]

        def fail_only_secondary(ctx, entry):
            if entry["status"] == "FAILED":
                raise self.env["Failure"]("SECONDARY_RECEIPT_FAILURE")
            original(ctx, entry)

        self.env["metadata_transport_receipt"] = fail_only_secondary
        with self.assertRaises(self.env["Failure"]) as raised:
            self.run_case(b"\xff")
        self.assertEqual(raised.exception.cause, "METADATA_UTF8_INVALID")
        self.assertEqual(self.receipt()["status"], "DECODED_BEFORE_PARSE")

    def test_raw_binary_transport_does_not_inflate_or_change_hash_guards(self):
        raw = b"\x1f\x8bnot-an-archive"
        self.serial += 1; run = self.root / str(self.serial); run.mkdir()
        self.context = {"runRoot": run, "deadlineMono": time.monotonic() + 30}
        response = Response(raw, [("Content-Encoding", "gzip")], URL)
        self.env["urllib"] = SimpleNamespace(request=SimpleNamespace(HTTPRedirectHandler=urllib.request.HTTPRedirectHandler, Request=urllib.request.Request, build_opener=lambda *args: SimpleNamespace(open=lambda *args, **kwargs: response)))
        record = self.env["bounded_get"](self.context, URL, run / "raw.bin", len(raw), [0], expected_size=len(raw), expected_sha512=hashlib.sha512(raw).hexdigest())
        self.assertEqual((run / "raw.bin").read_bytes(), raw)
        self.assertEqual(record["sha512"], hashlib.sha512(raw).hexdigest())

    def test_documented_exact_empty_vulnerability_array_is_valid(self):
        self.assertEqual(self.env["vulnerability_page_entries"]([]), {})

    def test_nonempty_vulnerability_array_is_denied(self):
        with self.assertRaises(self.env["Failure"]) as raised:
            self.env["vulnerability_page_entries"]([{"versions": "[1.0,2.0)"}])
        self.assertEqual(raised.exception.cause, "VULNERABILITY_PAGE_SHAPE")


if __name__ == "__main__":
    unittest.main()
