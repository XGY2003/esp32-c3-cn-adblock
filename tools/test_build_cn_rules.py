"""Offline contract tests; real-source availability is checked by the workflow."""
import email.message
import hashlib
import http.client
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import build_cn_rules as rules


class DomainParsingTests(unittest.TestCase):
    def test_plain_names_and_firmware_www_normalization(self):
        parsed = rules.parse_domains(
            b"\xef\xbb\xbf#TITLE=anti-AD\n#VER=20261014065816\n\n"
            b"WWW.Example.COM.\nexample.com\ntracker.example.net\n"
            b"xn--bcher-kva.example\n"
        )
        self.assertEqual(parsed.domains, {
            "example.com", "tracker.example.net", "xn--bcher-kva.example",
        })
        self.assertEqual(parsed.valid_lines, 4)
        self.assertEqual(parsed.comment_lines, 2)
        self.assertEqual(parsed.invalid_lines, 0)
        self.assertEqual(parsed.metadata["VER"], "20261014065816")

    def test_rejects_rule_syntax_urls_comments_and_invalid_dns_names(self):
        invalid = [
            "127.0.0.1", "0.0.0.0 ads.example.com", "https://ads.example.com/",
            "||ads.example.com^", "@@||example.com^", "*.example.com",
            ".example.com", "example.com # comment", "ad_server.example.com",
            "-ads.example.com", "ads-.example.com", "a..example.com",
            "localhost", "com", "www.com", "example.123", "bad..",
            "a" * 64 + ".example.com", "例子.中国", "example.com:443",
            ".".join(["a" * 63] * 4) + ".com", "example.com\x00",
        ]
        for value in invalid:
            with self.subTest(value=value):
                self.assertIsNone(rules.normalize_domain(value))
        parsed = rules.parse_domains(b"good.example\n||bad.example^\n0.0.0.0 bad.example\n")
        self.assertEqual(parsed.domains, {"good.example"})
        self.assertEqual(parsed.invalid_lines, 2)

    def test_html_bad_utf8_empty_and_oversized_sources_fail(self):
        for source in (
            b"<!DOCTYPE html>\nerror.example.com\n",
            b"good.example\n\xff", b"# only a comment\n",
            b"x" * (rules.MAX_SOURCE_BYTES + 1),
        ):
            with self.subTest(size=len(source)):
                with self.assertRaises(rules.BuildError):
                    rules.parse_domains(source)

    def test_allowlist_rejects_mistyped_entry_instead_of_silently_ignoring_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "allowlist.txt"
            path.write_text("# comment\nlogin.example.com # why\n", encoding="utf-8")
            with self.assertRaisesRegex(rules.BuildError, "line 2"):
                rules.read_allowlist(path)

    def test_official_metadata_counts_valid_lines_before_normalized_deduplication(self):
        parsed = rules.parse_domains(
            b"#TITLE=anti-AD\n#TOTAL_LINES=3\n\n# a comment\n"
            b"ads.example.com\nwww.ads.example.com\nads.example.com\n",
            require_metadata=True,
        )
        self.assertEqual(parsed.valid_lines, 3)
        self.assertEqual(parsed.domains, {"ads.example.com"})

    def test_official_metadata_is_required_and_must_match_the_complete_body(self):
        cases = [
            b"ads.example.com\n",
            b"#TITLE=another-list\n#TOTAL_LINES=1\nads.example.com\n",
            b"#TITLE=anti-AD\nads.example.com\n",
            b"#TITLE=anti-AD\n#TOTAL_LINES=invalid\nads.example.com\n",
            b"#TITLE=anti-AD\n#TOTAL_LINES=-1\nads.example.com\n",
            b"#TITLE=anti-AD\n#TOTAL_LINES=2\nads.example.com\n",
            b"#TITLE=anti-AD\n#TOTAL_LINES=1\nads.example.com\n||bad.example^\n",
        ]
        for source in cases:
            with self.subTest(source=source):
                with self.assertRaises(rules.BuildError):
                    rules.parse_domains(source, require_metadata=True)


class MatchingContractTests(unittest.TestCase):
    def test_removes_only_children_covered_by_the_actual_parent(self):
        domains = {"ads.example.com", "img.ads.example.com", "notads.example.com",
                   "myads.example.com", "example.net", "x.example.net"}
        self.assertEqual(rules.remove_redundant_children(domains),
                         {"ads.example.com", "notads.example.com", "myads.example.com", "example.net"})

    def test_allowing_a_child_removes_its_blocked_ancestors(self):
        blocked = {"example.com", "login.example.com", "cdn.login.example.com",
                   "ads.example.com", "tracking.other.com", "notexample.com"}
        allowed = {"login.example.com"}
        filtered, report = rules.apply_allowlist(blocked, allowed)
        self.assertEqual(filtered, {"ads.example.com", "tracking.other.com", "notexample.com"})
        self.assertEqual(report["removed_blocked_ancestors"], ["example.com"])
        self.assertFalse(any(parent in filtered for parent in rules.parent_domains("login.example.com")))
        self.assertFalse(any(parent in filtered for parent in rules.parent_domains("cdn.login.example.com")))
        # Explicit sibling rules remain; only coverage from the removed ancestor is lost.
        self.assertTrue(any(parent in filtered for parent in rules.parent_domains("img.ads.example.com")))

    def test_allowing_parent_removes_child_rules_with_label_boundaries(self):
        filtered, _ = rules.apply_allowlist(
            {"example.com", "a.example.com", "b.a.example.com", "notexample.com"},
            {"example.com"},
        )
        self.assertEqual(filtered, {"notexample.com"})

    def test_known_fnv1a_vector_matches_firmware_low_40_bits(self):
        # Published 64-bit FNV-1a("hello") = a430d84680aabd0b.
        self.assertEqual(rules.fnv40("hello"), 0x4680AABD0B)
        self.assertEqual(rules.fnv40("a"), 0x4C8601EC8C)


class FakeResponse:
    def __init__(self, body, headers=None, url="https://rules.example/domains.txt"):
        import io
        self.stream = io.BytesIO(body)
        self.headers = email.message.Message()
        for key, value in (headers or {}).items():
            self.headers[key] = value
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.stream.close()

    def geturl(self):
        return self.url

    def read(self, length):
        return self.stream.read(length)


class DownloadTests(unittest.TestCase):
    def test_download_enforces_https_and_checks_content_type_and_length(self):
        with self.assertRaises(rules.BuildError):
            rules.download_source("http://rules.example/domains.txt")
        cases = [
            FakeResponse(b"good.example\n", {"Content-Type": "text/html"}),
            FakeResponse(b"good.example\n", {"Content-Length": "100"}),
            FakeResponse(b"x", {"Content-Length": str(rules.MAX_SOURCE_BYTES + 1)}),
            FakeResponse(b"x", {"Content-Length": "invalid"}),
            FakeResponse(b"x", {"Content-Encoding": "gzip"}),
            FakeResponse(b"x", url="http://rules.example/domains.txt"),
        ]
        for response in cases:
            with self.subTest(headers=str(response.headers), url=response.url):
                with mock.patch.object(rules.urllib.request, "urlopen", return_value=response):
                    with self.assertRaises(rules.BuildError):
                        rules.download_source("https://rules.example/domains.txt")

    def test_download_caps_a_chunked_response_without_content_length(self):
        response = FakeResponse(b"x" * (rules.MAX_SOURCE_BYTES + 1))
        with mock.patch.object(rules.urllib.request, "urlopen", return_value=response):
            with self.assertRaisesRegex(rules.BuildError, "exceeds"):
                rules.download_source("https://rules.example/domains.txt")

    def test_fallback_is_used_without_merging_a_failed_primary(self):
        body = b"good.example\n"
        with mock.patch.object(rules, "download_source", side_effect=[rules.BuildError("network down"),
                                                                      (body, "https://mirror.example/list")]):
            parsed, source, attempts = rules.select_source(["primary", "fallback"], 1)
        self.assertEqual(parsed.domains, {"good.example"})
        self.assertEqual(source["requested"], "fallback")
        self.assertEqual(len(attempts), 1)


class IncompleteResponse(FakeResponse):
    def read(self, length):
        raise http.client.IncompleteRead(b"partial content", 1000)


class BuildContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = b"#TITLE=anti-AD test\n" + b"".join(
            f"ad{i}.example.net\n".encode("ascii") for i in range(rules.MIN_HASHES)
        )

    def make_paths(self, directory):
        root = Path(directory)
        allowlist = root / "allowlist.txt"
        allowlist.write_text("# empty\n", encoding="utf-8")
        source = root / "domains.txt"
        source.write_bytes(self.source)
        return root / "dist", allowlist, source

    def test_real_format_manifest_and_companion_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            output, allowlist, source = self.make_paths(directory)
            manifest = rules.build(output, allowlist, [str(source)])
            blob = (output / "blocklist.bin").read_bytes()
            checksum = (output / "blocklist.bin.sha256").read_text(encoding="ascii")
            self.assertEqual(len(blob), rules.MIN_HASHES * 5)
            self.assertRegex(checksum, r"\A[0-9a-f]{64}\n\Z")
            self.assertEqual(checksum.strip(), hashlib.sha256(blob).hexdigest())
            unpacked = [int.from_bytes(blob[i:i + 5], "little") for i in range(0, len(blob), 5)]
            self.assertEqual(unpacked, sorted(set(unpacked)))
            self.assertIn(rules.fnv40("ad321.example.net"), unpacked)
            self.assertEqual(manifest["source"]["sha256"], hashlib.sha256(self.source).hexdigest())
            self.assertEqual(json.loads((output / "manifest.json").read_text(encoding="utf-8")), manifest)

    def test_failed_fetch_does_not_replace_any_existing_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            output, allowlist, source = self.make_paths(directory)
            rules.build(output, allowlist, [str(source)])
            before = {path.name: path.read_bytes() for path in output.iterdir()}
            with mock.patch.object(rules, "download_source", side_effect=rules.BuildError("offline")):
                with self.assertRaisesRegex(rules.BuildError, "all rule sources failed"):
                    rules.build(output, allowlist)
            self.assertEqual(before, {path.name: path.read_bytes() for path in output.iterdir()})

    def test_undersized_or_excessive_allowlist_result_preserves_old_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            output, allowlist, source = self.make_paths(directory)
            rules.build(output, allowlist, [str(source)])
            before = {path.name: path.read_bytes() for path in output.iterdir()}
            allowlist.write_text("example.net\n", encoding="utf-8")
            with self.assertRaisesRegex(rules.BuildError, "minimum"):
                rules.build(output, allowlist, [str(source)])
            self.assertEqual(before, {path.name: path.read_bytes() for path in output.iterdir()})

    def test_truncated_http_response_uses_fallback_and_all_failures_preserve_old_table(self):
        with tempfile.TemporaryDirectory() as directory:
            output, allowlist, source = self.make_paths(directory)
            rules.build(output, allowlist, [str(source)])
            official_source = (f"#TITLE=anti-AD\n#TOTAL_LINES={rules.MIN_HASHES}\n".encode("ascii")
                               + self.source.split(b"\n", 1)[1])
            fallback_response = FakeResponse(official_source, url=rules.DEFAULT_SOURCES[1])
            with mock.patch.object(rules.urllib.request, "urlopen", side_effect=[
                IncompleteResponse(b""), fallback_response,
            ]) as opener:
                manifest = rules.build(output, allowlist)
            self.assertEqual(opener.call_count, 2)
            self.assertEqual(manifest["source"]["requested"], rules.DEFAULT_SOURCES[1])
            self.assertIn("IncompleteRead", manifest["failed_source_attempts"][0]["error"])
            before = {path.name: path.read_bytes() for path in output.iterdir()}
            with mock.patch.object(rules.urllib.request, "urlopen", side_effect=[
                IncompleteResponse(b""), IncompleteResponse(b""),
            ]):
                with self.assertRaisesRegex(rules.BuildError, "all rule sources failed"):
                    rules.build(output, allowlist)
            self.assertEqual(before, {path.name: path.read_bytes() for path in output.iterdir()})

    def test_http_200_truncated_domain_body_falls_back_or_preserves_old_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            output, allowlist, source = self.make_paths(directory)
            rules.build(output, allowlist, [str(source)])
            official_source = (f"#TITLE=anti-AD\n#TOTAL_LINES={rules.MIN_HASHES}\n".encode("ascii")
                               + self.source.split(b"\n", 1)[1])
            # This shortened source still clears the 10k safety floor. Only the
            # declared full-list count exposes the incomplete HTTP 200 body.
            truncated_source = official_source.replace(
                f"#TOTAL_LINES={rules.MIN_HASHES}\n".encode("ascii"),
                b"#TOTAL_LINES=110164\n",
            )
            with mock.patch.object(rules.urllib.request, "urlopen", side_effect=[
                FakeResponse(truncated_source), FakeResponse(official_source, url=rules.DEFAULT_SOURCES[1]),
            ]):
                manifest = rules.build(output, allowlist)
            self.assertEqual(manifest["source"]["requested"], rules.DEFAULT_SOURCES[1])
            self.assertIn("TOTAL_LINES", manifest["failed_source_attempts"][0]["error"])
            self.assertEqual(manifest["rules"]["hashes"], rules.MIN_HASHES)
            before = {path.name: path.read_bytes() for path in output.iterdir()}
            with mock.patch.object(rules.urllib.request, "urlopen", side_effect=[
                FakeResponse(truncated_source), FakeResponse(truncated_source),
            ]):
                with self.assertRaisesRegex(rules.BuildError, "all rule sources failed"):
                    rules.build(output, allowlist)
            self.assertEqual(before, {path.name: path.read_bytes() for path in output.iterdir()})

    def test_local_publication_installs_checksum_last(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            with mock.patch.object(rules.os, "replace", wraps=rules.os.replace) as replace:
                rules.publish_artifacts(output, {
                    "blocklist.bin.sha256": b"checksum\n",
                    "blocklist.bin": b"binary",
                    "manifest.json": b"{}\n",
                })
            self.assertEqual([call.args[1].name for call in replace.call_args_list],
                             ["blocklist.bin", "manifest.json", "blocklist.bin.sha256"])

    def test_capacity_is_hard_failure_never_truncation(self):
        domains = {f"ad{i}.example.net" for i in range(rules.MAX_HASHES + 1)}
        with self.assertRaisesRegex(rules.BuildError, "refusing to truncate"):
            rules.encode_domains(domains, set(), rules.MIN_HASHES)

    def test_minimum_safety_floor_cannot_be_disabled(self):
        with self.assertRaisesRegex(rules.BuildError, "between"):
            rules.encode_domains({"ads.example.com"}, set(), 1)

    def test_detects_a_hash_collision_with_an_allowed_domain(self):
        domains = {f"ad{i}.example.net" for i in range(rules.MIN_HASHES)}
        original = rules.fnv40
        with mock.patch.object(rules, "fnv40", side_effect=lambda value:
                               original("ad0.example.net") if value == "allowed.example.com" else original(value)):
            with self.assertRaisesRegex(rules.BuildError, "collision"):
                rules.encode_domains(domains, {"allowed.example.com"}, rules.MIN_HASHES)


if __name__ == "__main__":
    unittest.main()
