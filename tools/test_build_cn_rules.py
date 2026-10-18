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
import check_update_url as publication


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
        self.status = 200

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


class StrongProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.anti = (f"#TITLE=anti-AD\n#TOTAL_LINES={rules.MIN_HASHES}\n".encode()
                    + b"".join(f"anti{i}.example.net\n".encode() for i in range(rules.MIN_HASHES)))
        cls.adrules = b"".join(
            f"domain:ad{i}.example.org\n".encode() for i in range(rules.MIN_HASHES)
        )

    def setUp(self):
        # Small offline fixtures; production's independent AdRules floor is 100k.
        self.floor = mock.patch.object(rules, "MIN_ADRULES_DOMAINS", rules.MIN_HASHES)
        self.floor.start()
        self.addCleanup(self.floor.stop)

    def make_paths(self, directory):
        root = Path(directory)
        anti = root / "anti.txt"
        adrules = root / "adrules.txt"
        allow = root / "allow.txt"
        anti.write_bytes(self.anti)
        adrules.write_bytes(self.adrules)
        allow.write_text("# no exceptions\n", encoding="utf-8")
        return root / "dist", allow, anti, adrules

    def build(self, output, allow, anti, adrules):
        return rules.build(output, allow, [str(anti)], profile="strong",
                           adrules_sources=[str(adrules)])

    def test_only_mosdns_suffix_syntax_is_accepted(self):
        parsed = rules.parse_domains(b"# comment\ndomain:WWW.ADS.Example.COM.\n",
                                     source_format="mosdns", strict=True)
        self.assertEqual(parsed.domains, {"ads.example.com"})
        invalid = [b"good.example", b"full:exact.example", b"regexp:.*",
                   b"0.0.0.0 bad.example", b"||bad.example^", b"||bad.example/path^",
                   b"||bad.example^$third-party", b"@@||bad.example^",
                   b"domain:bad.example/path", b"domain:bad.example$important",
                   b"domain:bad.example # comment", b"domain:*.bad.example",
                   b"domain:domain:bad.example", b"domain:127.0.0.1"]
        for line in invalid:
            with self.subTest(line=line), self.assertRaises(rules.BuildError):
                rules.parse_domains(b"domain:good.example\n" + line + b"\n",
                                    source_format="mosdns", strict=True)
        for body in [b"<html>\ndomain:good.example\n</html>\n",
                     b"domain:good.example", b"domain:good.example\n\xff\n"]:
            with self.subTest(body=body), self.assertRaises(rules.BuildError):
                rules.parse_domains(body, source_format="mosdns", strict=True)

    def test_strong_anti_source_also_rejects_mixed_format(self):
        with self.assertRaisesRegex(rules.BuildError, "invalid"):
            rules.parse_domains(b"good.example\n0.0.0.0 hosts.example\n", strict=True)

    def test_both_sources_and_full_provenance_are_published(self):
        with tempfile.TemporaryDirectory() as directory:
            output, allow, anti, adrules = self.make_paths(directory)
            manifest = self.build(output, allow, anti, adrules)
            self.assertEqual(manifest["profile"], "strong")
            self.assertEqual(manifest["required_sources"], ["anti-AD", "Cats-Team/AdRules"])
            self.assertEqual(manifest["rules"]["hashes"], 2 * rules.MIN_HASHES)
            self.assertEqual(manifest["capacity"]["max_bytes"], rules.STRONG_MAX_OUTPUT_BYTES)
            self.assertEqual((output / "source-anti-ad-domains.txt").read_bytes(), self.anti)
            self.assertEqual((output / "source-adrules-mosdns.txt").read_bytes(), self.adrules)
            self.assertEqual(manifest["sources"][1]["sha256"], hashlib.sha256(self.adrules).hexdigest())
            self.assertIn("not 0BSD", manifest["sources"][1]["license"])
            for name, metadata in manifest["artifacts"].items():
                body = (output / name).read_bytes()
                self.assertEqual(len(body), metadata["bytes"])
                self.assertEqual(hashlib.sha256(body).hexdigest(), metadata["sha256"])
            domains = set((output / "domains.txt").read_text().splitlines())
            self.assertIn("anti123.example.net", domains)
            self.assertIn("ad123.example.org", domains)
            # A second build from the stored inputs has identical rule bytes.
            second = output / "reproduced"
            rules.build(second, output / "allowlist.txt", [str(output / "source-anti-ad-domains.txt")],
                        profile="strong", adrules_sources=[str(output / "source-adrules-mosdns.txt")])
            self.assertEqual((second / "blocklist.bin").read_bytes(), (output / "blocklist.bin").read_bytes())

    def test_allowlist_removes_ancestors_across_sources_without_losing_sibling_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            output, allow, anti, adrules = self.make_paths(directory)
            anti.write_bytes(self.anti + b"tracking.example.com\n")
            adrules.write_bytes(self.adrules + b"domain:login.tracking.example.com\n"
                               b"domain:cdn.login.tracking.example.com\ndomain:ads.tracking.example.com\n")
            allow.write_text("login.tracking.example.com\n", encoding="utf-8")
            manifest = self.build(output, allow, anti, adrules)
            domains = set((output / "domains.txt").read_text().splitlines())
            self.assertNotIn("tracking.example.com", domains)
            self.assertNotIn("login.tracking.example.com", domains)
            self.assertNotIn("cdn.login.tracking.example.com", domains)
            self.assertIn("ads.tracking.example.com", domains)
            self.assertEqual(manifest["allowlist"]["removed_blocked_ancestors"], ["tracking.example.com"])

    def test_failed_adrules_after_valid_anti_does_not_replace_any_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            output, allow, anti, adrules = self.make_paths(directory)
            self.build(output, allow, anti, adrules)
            before = {p.name: p.read_bytes() for p in output.iterdir()}
            adrules.write_bytes(b"<html>service unavailable</html>\n")
            with self.assertRaisesRegex(rules.BuildError, "all rule sources failed"):
                self.build(output, allow, anti, adrules)
            self.assertEqual(before, {p.name: p.read_bytes() for p in output.iterdir()})

    def test_failed_anti_does_not_publish_adrules_only(self):
        with tempfile.TemporaryDirectory() as directory:
            output, allow, anti, adrules = self.make_paths(directory)
            self.build(output, allow, anti, adrules)
            before = {p.name: p.read_bytes() for p in output.iterdir()}
            anti.write_bytes(b"bad\n")
            with self.assertRaisesRegex(rules.BuildError, "all rule sources failed"):
                self.build(output, allow, anti, adrules)
            self.assertEqual(before, {p.name: p.read_bytes() for p in output.iterdir()})

    def test_adrules_fallback_replaces_failed_input_instead_of_merging_it(self):
        poisoned = b"domain:must-not-survive.example\n||wrong-format.example^\n"
        with mock.patch.object(rules, "download_source", side_effect=[
            (poisoned, "https://primary.example/list"), (self.adrules, "https://fallback.example/list"),
        ]):
            parsed, source, attempts = rules.select_source(
                ["primary", "fallback"], rules.MIN_HASHES, source_format="mosdns", strict=True)
        self.assertNotIn("must-not-survive.example", parsed.domains)
        self.assertEqual(source["requested"], "fallback")
        self.assertEqual(len(attempts), 1)

    def test_strong_capacity_is_explicit_and_legacy_stays_small(self):
        self.assertEqual(rules.profile_limits("legacy"), (110000, 550000))
        self.assertEqual(rules.profile_limits("strong"), (300000, 1500000))
        domains = {f"ad{i}.example.net" for i in range(rules.MAX_HASHES + 1)}
        with self.assertRaisesRegex(rules.BuildError, "refusing to truncate"):
            rules.encode_domains(domains, set(), rules.MIN_HASHES)
        blob, _ = rules.encode_domains(domains, set(), rules.MIN_HASHES, "strong")
        self.assertGreater(len(blob), rules.MAX_OUTPUT_BYTES)
        with self.assertRaisesRegex(rules.BuildError, "unknown"):
            rules.profile_limits("mistyped")

    def test_default_profile_never_fetches_adrules(self):
        with tempfile.TemporaryDirectory() as directory:
            output, allow, _, _ = self.make_paths(directory)
            with mock.patch.object(rules, "download_source", return_value=(self.anti, rules.DEFAULT_SOURCES[0])) as download:
                manifest = rules.build(output, allow)
            self.assertEqual(download.call_count, 1)
            self.assertEqual(manifest["profile"], "legacy")
            self.assertEqual(manifest["required_sources"], ["anti-AD"])
            self.assertEqual(manifest["capacity"]["max_bytes"], 550000)
            self.assertFalse((output / "source-adrules-mosdns.txt").exists())
            with self.assertRaisesRegex(rules.BuildError, "strong"):
                rules.build(output, allow, adrules_sources=["unexpected"])

    def test_small_adrules_source_is_not_accepted_as_success(self):
        with mock.patch.object(rules, "download_source", return_value=(b"domain:one.example\n", "local")):
            with self.assertRaisesRegex(rules.BuildError, "all rule sources failed"):
                rules.select_source(["local"], 100000, source_format="mosdns", strict=True)


class PublicationProfileTests(unittest.TestCase):
    def test_large_publication_requires_explicit_strong_profile(self):
        blob = b"".join(i.to_bytes(5, "little") for i in range(120000))
        checksum = (hashlib.sha256(blob).hexdigest() + "\n").encode("ascii")
        for profile in ("legacy", "strong"):
            with self.subTest(profile=profile):
                opener = mock.Mock()
                opener.open.side_effect = [
                    FakeResponse(checksum, {"Content-Length": str(len(checksum))}),
                    FakeResponse(blob, {"Content-Length": str(len(blob))}),
                ]
                with mock.patch.object(publication.urllib.request, "build_opener", return_value=opener):
                    if profile == "legacy":
                        with self.assertRaisesRegex(ValueError, "Content-Length"):
                            publication.check("https://rules.example/blocklist.bin")
                    else:
                        result = publication.check("https://rules.example/blocklist.bin", profile="strong")
                        self.assertEqual(result["bytes"], 600000)
                        self.assertEqual(result["profile"], "strong")
                        self.assertEqual(result["sha256"], checksum.decode().strip())
        self.assertEqual(publication.MAX_BYTES, 550000)


if __name__ == "__main__":
    unittest.main()
