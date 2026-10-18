#!/usr/bin/env python3
"""Build bounded China-focused DNS lists for ESP32-C3 and ESP32-S3.

The default legacy profile retains anti-AD only and its 550000-byte C3 limit.
The strong S3 profile requires BOTH anti-AD and Cats-Team AdRules (MosDNS format).
Mirrors are fallbacks for the SAME list, never additional lists to merge. Format:
strictly increasing unsigned 40-bit FNV-1a hashes, five little-endian bytes each.

Firmware strips one leading ``www.`` and matches blocked parent domains. This
builder uses the same normalization and removes redundant child rules. An
allowlisted domain removes BOTH blocked ancestors and blocked descendants: a
hash-only table cannot express exceptions under a blocked parent. Consequently
allowing ``login.example.com`` may also allow other children of ``example.com``.
Review ``allowlist.removed_blocked_ancestors`` in manifest.json after changes.

All downloads and validation finish before any existing output is replaced.
Files are staged first, with the companion checksum installed last. A consumer MUST check
the SHA-256 and retain its old table on mismatch: updating fixed release assets
is not an atomic operation. HTTPS verifies transport; SHA-256 detects corruption
or a publication race and is not a separate publisher signature.

Python 3.10+, standard library only. Run from any directory:
    python tools/build_cn_rules.py --output-dir data
    python tools/build_cn_rules.py --source saved-domains.txt --output-dir dist
    python tools/build_cn_rules.py --profile strong --output-dir dist-s3
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from typing import Iterable
import urllib.error
import urllib.parse
import urllib.request


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCES = (
    "https://anti-ad.net/domains.txt",
    "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt",
)
# These HTTPS mirrors are linked by Cats-Team/AdRules' official README.
ADRULES_SOURCES = (
    "https://adrules.top/mosdns_adrules.txt",
    "https://gp.adrules.top/mosdns_adrules.txt",
    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/mosdns_adrules.txt",
)
HASH_BYTES = 5
HASH_MASK = (1 << (HASH_BYTES * 8)) - 1
FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
U64_MASK = (1 << 64) - 1
MIN_HASHES = 10_000
MAX_HASHES = 110_000
MAX_OUTPUT_BYTES = 550_000
STRONG_MAX_HASHES = 300_000
STRONG_MAX_OUTPUT_BYTES = 1_500_000
MIN_ADRULES_DOMAINS = 100_000
CAPACITY_PROFILES = {
    "legacy": (MAX_HASHES, MAX_OUTPUT_BYTES),
    "strong": (STRONG_MAX_HASHES, STRONG_MAX_OUTPUT_BYTES),
}
MAX_SOURCE_BYTES = 8 * 1024 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 30
DOWNLOAD_DEADLINE_SECONDS = 120
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
TLD = re.compile(r"(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})\Z", re.ASCII)


class BuildError(Exception):
    """An input or safety check failed; previously published rules stay usable."""


@dataclass
class ParsedDomains:
    domains: set[str]
    valid_lines: int
    invalid_lines: int
    comment_lines: int
    empty_lines: int
    metadata: dict[str, str]
    source_body: bytes = b""


def normalize_domain(value: str) -> str | None:
    """Accept only a plain DNS hostname, lowercasing and matching firmware www.

    No hosts-file, URL, ABP, wildcard, underscore, inline comment, or Unicode
    syntax is accepted. IDNs must already be ASCII punycode. A single final dot
    (the DNS root notation) is accepted. IP addresses and one-label names are not.
    """
    if not value or not value.isascii() or value != value.strip():
        return None
    domain = value.lower()
    if domain.endswith("."):
        domain = domain[:-1]
    if not domain or len(domain) > 253:
        return None
    labels = domain.split(".")
    if len(labels) < 2 or not all(LABEL.fullmatch(label) for label in labels):
        return None
    if not TLD.fullmatch(labels[-1]):
        return None
    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        pass
    if domain.startswith("www."):
        domain = domain[4:]
    return domain if "." in domain else None


def parse_domains(body: bytes, require_metadata: bool = False, *,
                  source_format: str = "domains", strict: bool = False) -> ParsedDomains:
    if source_format not in {"domains", "mosdns"}:
        raise BuildError(f"unsupported source format {source_format}")
    if len(body) > MAX_SOURCE_BYTES:
        raise BuildError(f"source exceeds {MAX_SOURCE_BYTES} bytes")
    try:
        text = body.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as exc:
        raise BuildError("source is not valid UTF-8 text") from exc
    if "<" in text or ">" in text or "\x00" in text:
        raise BuildError("source contains HTML/XML markup or a NUL byte")
    if strict and not text.endswith("\n"):
        raise BuildError("strict source must end with a newline; possibly truncated")
    domains: set[str] = set()
    valid = invalid = comments = empty = 0
    metadata: dict[str, str] = {}
    for original in text.splitlines():
        line = original.strip()
        if not line:
            empty += 1
        elif line.startswith(("#", "!")):
            comments += 1
            if line.startswith("#") and "=" in line:
                key, value = line[1:].split("=", 1)
                if key in {"TITLE", "VER", "URL", "TOTAL_LINES"}:
                    metadata[key] = value[:512]
        else:
            # Only MosDNS domain: suffix rules have the firmware's parent-match
            # semantics. Reject full:, regexp:, hosts, ABP, paths and modifiers.
            value = line
            if source_format == "mosdns":
                value = line[7:] if line.startswith("domain:") else ""
            domain = normalize_domain(value)
            if domain is None:
                invalid += 1
            else:
                valid += 1
                domains.add(domain)
    if not domains:
        raise BuildError("source contains no valid domain rules")
    if strict and invalid:
        raise BuildError(f"source contains {invalid} invalid {source_format} rule lines")
    if require_metadata:
        if metadata.get("TITLE") != "anti-AD":
            raise BuildError("official anti-AD source is missing its exact TITLE=anti-AD header")
        declared_count = metadata.get("TOTAL_LINES", "")
        if not re.fullmatch(r"[0-9]+", declared_count, flags=re.ASCII):
            raise BuildError("official anti-AD source has no valid numeric TOTAL_LINES header")
        if int(declared_count) != valid:
            raise BuildError(f"official anti-AD TOTAL_LINES={declared_count} does not match {valid} valid domain lines")
        if invalid:
            raise BuildError(f"official anti-AD source contains {invalid} invalid domain lines")
    return ParsedDomains(domains, valid, invalid, comments, empty, metadata, body)


def parent_domains(domain: str) -> Iterable[str]:
    """Yield the domain and its DNS parent suffixes, stopping before the TLD."""
    labels = domain.split(".")
    for index in range(len(labels) - 1):
        yield ".".join(labels[index:])


def read_allowlist(path: Path) -> tuple[set[str], str]:
    try:
        body = path.read_bytes()
    except OSError as exc:
        raise BuildError(f"cannot read allowlist {path}: {exc}") from exc
    if len(body) > 1024 * 1024:
        raise BuildError("allowlist exceeds 1 MiB")
    try:
        text = body.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as exc:
        raise BuildError("allowlist is not valid UTF-8") from exc
    allowed: set[str] = set()
    for number, original in enumerate(text.splitlines(), start=1):
        line = original.strip()
        if not line or line.startswith(("#", "!")):
            continue
        domain = normalize_domain(line)
        if domain is None:
            raise BuildError(f"invalid plain domain in allowlist at line {number}")
        allowed.add(domain)
    return allowed, hashlib.sha256(body).hexdigest()


def apply_allowlist(blocked: set[str], allowed: set[str]) -> tuple[set[str], dict]:
    ancestors = {parent for domain in allowed for parent in parent_domains(domain)}
    removed_ancestors = blocked & ancestors
    # Also remove explicit child rules; a parent allow entry means its subtree.
    removed_children = {
        domain for domain in blocked
        if any(parent in allowed for parent in parent_domains(domain))
    }
    removed = removed_ancestors | removed_children
    return blocked - removed, {
        "entries": sorted(allowed),
        "removed_rules": len(removed),
        "removed_blocked_ancestors": sorted(removed_ancestors - allowed),
        "removed_descendant_or_exact_rules": len(removed_children),
        "policy": "remove blocked ancestors and allowed subtrees; siblings under removed ancestors may also be allowed",
    }


def remove_redundant_children(domains: set[str]) -> set[str]:
    """Parent matching means a blocked parent already covers every child."""
    return {
        domain for domain in domains
        if not any(parent in domains for parent in list(parent_domains(domain))[1:])
    }


def fnv40(domain: str) -> int:
    value = FNV_OFFSET
    for byte in domain.encode("ascii"):
        value = ((value ^ byte) * FNV_PRIME) & U64_MASK
    return value & HASH_MASK


def profile_limits(profile: str) -> tuple[int, int]:
    try:
        return CAPACITY_PROFILES[profile]
    except KeyError as exc:
        raise BuildError(f"unknown build profile {profile}") from exc


def encode_domains(domains: set[str], allowed: set[str], min_hashes: int,
                   profile: str = "legacy") -> tuple[bytes, int]:
    max_hashes, max_bytes = profile_limits(profile)
    hashes = {fnv40(domain) for domain in domains}
    if not MIN_HASHES <= min_hashes <= max_hashes:
        raise BuildError(f"min_hashes must be between {MIN_HASHES} and {max_hashes}")
    if len(hashes) < min_hashes:
        raise BuildError(f"only {len(hashes)} hashes; minimum is {min_hashes}")
    if len(hashes) > max_hashes or len(hashes) * HASH_BYTES > max_bytes:
        raise BuildError(f"{len(hashes)} hashes exceed the {max_hashes}-hash / {max_bytes}-byte capacity; refusing to truncate")
    for domain in allowed:
        if any(fnv40(parent) in hashes for parent in parent_domains(domain)):
            raise BuildError(f"40-bit hash collision prevents allowing {domain}; refusing output")
    blob = b"".join(value.to_bytes(HASH_BYTES, "little") for value in sorted(hashes))
    return blob, len(domains) - len(hashes)


def download_source(source: str) -> tuple[bytes, str]:
    parsed = urllib.parse.urlparse(source)
    if not parsed.scheme or re.match(r"^[A-Za-z]:[\\/]", source):
        path = Path(source)
        try:
            with path.open("rb") as stream:
                body = stream.read(MAX_SOURCE_BYTES + 1)
        except OSError as exc:
            raise BuildError(f"cannot read {source}: {exc}") from exc
        if len(body) > MAX_SOURCE_BYTES:
            raise BuildError(f"source exceeds {MAX_SOURCE_BYTES} bytes")
        return body, str(path.resolve())
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise BuildError("remote rule sources must be HTTPS URLs without credentials")
    request = urllib.request.Request(source, headers={
        "User-Agent": "esp32-cn-rules/1.0 (+https://github.com/M-Abozaid/esp32-c3-adblock)",
        "Accept": "text/plain, application/octet-stream;q=0.8",
        "Accept-Encoding": "identity",
    })
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
            final_url = response.geturl()
            if urllib.parse.urlparse(final_url).scheme != "https":
                raise BuildError("source redirected away from HTTPS")
            mime_type = response.headers.get_content_type()
            if mime_type in {"text/html", "application/xhtml+xml", "application/json"}:
                raise BuildError(f"unexpected source Content-Type {mime_type}")
            encoding = response.headers.get("Content-Encoding", "identity").lower()
            if encoding != "identity":
                raise BuildError(f"unexpected source Content-Encoding {encoding}")
            length = response.headers.get("Content-Length")
            if length is not None:
                try:
                    declared_length = int(length)
                except ValueError as exc:
                    raise BuildError("invalid source Content-Length") from exc
                if not 0 < declared_length <= MAX_SOURCE_BYTES:
                    raise BuildError(f"source Content-Length is outside 1..{MAX_SOURCE_BYTES}")
            chunks: list[bytes] = []
            total = 0
            while True:
                if time.monotonic() - started > DOWNLOAD_DEADLINE_SECONDS:
                    raise BuildError("source download deadline exceeded")
                chunk = response.read(min(65536, MAX_SOURCE_BYTES + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_SOURCE_BYTES:
                    raise BuildError(f"source exceeds {MAX_SOURCE_BYTES} bytes")
                chunks.append(chunk)
            body = b"".join(chunks)
            if length is not None and len(body) != declared_length:
                raise BuildError("source download is truncated")
            return body, final_url
    except (OSError, urllib.error.URLError, http.client.HTTPException, ValueError) as exc:
        raise BuildError(f"download failed for {source}: {exc}") from exc


def select_source(sources: Iterable[str], min_hashes: int, *, source_format: str = "domains",
                  strict: bool = False) -> tuple[ParsedDomains, dict, list[dict]]:
    attempts: list[dict] = []
    for source in sources:
        try:
            body, resolved = download_source(source)
            # Official domains-only files declare their line count. Require it
            # so an HTTP 200 response with a truncated body cannot replace the
            # old table merely because its remaining portion exceeds 10k rules.
            # Custom/local sources remain usable without anti-AD-specific headers.
            parsed = parse_domains(body, require_metadata=source in DEFAULT_SOURCES,
                                   source_format=source_format, strict=strict)
            if len(parsed.domains) < min_hashes:
                raise BuildError(f"source has only {len(parsed.domains)} unique domains; minimum is {min_hashes}")
            return parsed, {
                "requested": source,
                "resolved": resolved,
                "retrieved_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "sha256": hashlib.sha256(body).hexdigest(),
                "bytes": len(body),
                "format": source_format,
                "upstream_metadata": parsed.metadata,
                "valid_lines": parsed.valid_lines,
                "invalid_lines_rejected": parsed.invalid_lines,
                "comment_lines": parsed.comment_lines,
                "empty_lines": parsed.empty_lines,
                "unique_normalized_domains": len(parsed.domains),
            }, attempts
        except BuildError as exc:
            attempts.append({"source": source, "error": str(exc)})
            print(f"source unavailable: {exc}", file=sys.stderr)
    raise BuildError("all rule sources failed; existing outputs were not changed")


def publish_artifacts(output_dir: Path, artifacts: dict[str, bytes]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    # TemporaryDirectory uses the destination filesystem, making each replace
    # atomic. Validation errors above never touch an existing artifact.
    with tempfile.TemporaryDirectory(prefix=".cn-rules-", dir=output_dir) as directory:
        staged = Path(directory)
        for name, data in artifacts.items():
            with (staged / name).open("wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        # Publish the checksum last; a racing downloader must retry on mismatch.
        for name in sorted(artifacts, key=lambda value: value == "blocklist.bin.sha256"):
            os.replace(staged / name, output_dir / name)


def build(output_dir: Path, allowlist_path: Path, sources: Iterable[str] = DEFAULT_SOURCES,
          min_hashes: int = MIN_HASHES, *, profile: str = "legacy",
          adrules_sources: Iterable[str] | None = None) -> dict:
    max_hashes, max_bytes = profile_limits(profile)
    if not MIN_HASHES <= min_hashes <= max_hashes:
        raise BuildError(f"minimum must be between {MIN_HASHES} and {max_hashes}")
    if profile != "strong" and adrules_sources is not None:
        raise BuildError("AdRules sources require --profile strong")
    allowed, allowlist_sha = read_allowlist(allowlist_path)
    parsed, source, failed_attempts = select_source(sources, min_hashes, strict=profile == "strong")
    source.update(name="anti-AD", license="MIT", license_file="anti-AD-MIT.txt",
                  upstream="https://github.com/privacy-protection-tools/anti-AD")
    source_reports = [source]
    merged = set(parsed.domains)
    extra_artifacts: dict[str, bytes] = {}
    if profile == "strong":
        # A failure of either required list aborts before publish_artifacts.
        # Never publish an anti-AD-only replacement under the S3 release tag.
        adrules, ad_source, failures = select_source(
            ADRULES_SOURCES if adrules_sources is None else adrules_sources,
            MIN_ADRULES_DOMAINS, source_format="mosdns", strict=True,
        )
        ad_source.update(name="Cats-Team/AdRules", license="mixed upstream licenses; not 0BSD",
                         license_file="AdRules-NOTICE.md",
                         upstream="https://github.com/Cats-Team/AdRules",
                         licensing_source="https://github.com/Cats-Team/AdRules/blob/script/Source.md")
        source_reports.append(ad_source)
        failed_attempts.extend(failures)
        merged.update(adrules.domains)
        extra_artifacts = {
            "source-anti-ad-domains.txt": parsed.source_body,
            "source-adrules-mosdns.txt": adrules.source_body,
        }
        for name in ("anti-AD-MIT.txt", "AdRules-NOTICE.md", "AdRules-UPSTREAM-SOURCES.md",
                     "AdRules-UPSTREAM-README.md"):
            extra_artifacts[name] = (PROJECT_ROOT / "LICENSES" / name).read_bytes()
    filtered, allow_report = apply_allowlist(merged, allowed)
    compact = remove_redundant_children(filtered)
    blob, collisions = encode_domains(compact, allowed, min_hashes, profile)
    checksum = hashlib.sha256(blob).hexdigest()
    manifest = {
        "schema_version": 2,
        "profile": profile,
        "builder_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "required_sources": [item["name"] for item in source_reports],
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "format": {
            "algorithm": "FNV-1a-64 truncated to low 40 bits",
            "hash_bytes": HASH_BYTES,
            "byte_order": "little",
            "sort": "unsigned numeric ascending; unique",
            "normalization": "ASCII lowercase; strip one leading www.; match parent domains",
        },
        "source": source,
        "sources": source_reports,
        "failed_source_attempts": failed_attempts,
        "allowlist": {**allow_report, "sha256": allowlist_sha},
        "rules": {
            "merged_unique_domains": len(merged),
            "after_allowlist": len(filtered),
            "redundant_children_removed": len(filtered) - len(compact),
            "retained_domains": len(compact),
            "hash_collisions": collisions,
            "hashes": len(blob) // HASH_BYTES,
        },
        "capacity": {"min_hashes": min_hashes, "max_hashes": max_hashes, "max_bytes": max_bytes},
        "artifacts": {"blocklist.bin": {"bytes": len(blob), "sha256": checksum}},
    }
    if profile == "strong":
        extra_artifacts["domains.txt"] = ("\n".join(sorted(compact)) + "\n").encode("ascii")
        extra_artifacts["allowlist.txt"] = ("\n".join(sorted(allowed)) + "\n").encode("ascii")
    manifest["artifacts"].update({
        name: {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        for name, content in extra_artifacts.items()
    })
    artifacts = {
        **extra_artifacts,
        "blocklist.bin": blob,
        "blocklist.bin.sha256": (checksum + "\n").encode("ascii"),
        "manifest.json": (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    }
    publish_artifacts(output_dir, artifacts)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / "data")
    parser.add_argument("--allowlist", type=Path, default=PROJECT_ROOT / "rules" / "allowlist.txt")
    parser.add_argument("--profile", choices=sorted(CAPACITY_PROFILES), default="legacy",
                        help="legacy: anti-AD/C3; strong: anti-AD + AdRules/S3")
    parser.add_argument("--source", help="one local domains file or HTTPS source; overrides the default anti-AD source pair")
    parser.add_argument("--fallback-source", action="append", default=[], help="same-list fallback for --source; never merged")
    parser.add_argument("--adrules-source", help="override strong profile's AdRules MosDNS source")
    parser.add_argument("--adrules-fallback-source", action="append", default=[],
                        help="same AdRules MosDNS list fallback; never merged")
    parser.add_argument("--min-hashes", type=int, default=MIN_HASHES, help=f"minimum accepted final hashes (cannot be below {MIN_HASHES})")
    args = parser.parse_args(argv)
    if args.fallback_source and not args.source:
        parser.error("--fallback-source requires --source")
    if args.adrules_fallback_source and not args.adrules_source:
        parser.error("--adrules-fallback-source requires --adrules-source")
    if (args.adrules_source or args.adrules_fallback_source) and args.profile != "strong":
        parser.error("AdRules options require --profile strong")
    sources = (args.source, *args.fallback_source) if args.source else DEFAULT_SOURCES
    adrules_sources = ((args.adrules_source, *args.adrules_fallback_source)
                      if args.adrules_source else None)
    try:
        manifest = build(args.output_dir, args.allowlist, sources, args.min_hashes,
                         profile=args.profile, adrules_sources=adrules_sources)
    except (BuildError, OSError) as exc:
        print(f"BUILD FAILED: {exc}", file=sys.stderr)
        return 1
    print(f"profile: {manifest['profile']}")
    for source in manifest["sources"]:
        print(f"source: {source['name']}: {source['resolved']}")
        print(f"source domains: {source['valid_lines']:,} valid lines, "
              f"{source['invalid_lines_rejected']:,} rejected lines")
    print(f"rules: {manifest['rules']['hashes']:,} hashes; "
          f"{manifest['artifacts']['blocklist.bin']['bytes']:,} bytes; "
          f"{manifest['rules']['redundant_children_removed']:,} redundant children removed")
    print(f"sha256: {manifest['artifacts']['blocklist.bin']['sha256']}")
    print(f"output: {args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
