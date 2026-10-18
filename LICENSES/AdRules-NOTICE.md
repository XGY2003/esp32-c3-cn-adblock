# China strong DNS profile: sources and licensing

The `strong` profile is a transformed merge of anti-AD and Cats-Team AdRules.
It is a separate S3 artifact; the legacy C3 profile remains anti-AD only.

## Sources

- anti-AD: <https://github.com/privacy-protection-tools/anti-AD>
  - Preferred HTTPS input: <https://anti-ad.net/domains.txt>
  - Same-list fallback: <https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt>
  - MIT notice: `anti-AD-MIT.txt`.
- Cats-Team AdRules: <https://github.com/Cats-Team/AdRules>
  - Preferred official Cloudflare Pages mirror: <https://adrules.top/mosdns_adrules.txt>
  - Official GitHub Pages mirror: <https://gp.adrules.top/mosdns_adrules.txt>
  - Raw same-list fallback: <https://raw.githubusercontent.com/Cats-Team/AdRules/main/mosdns_adrules.txt>
  - This is the MosDNS DNS list, accepting only `domain:hostname` suffix entries.
    Browser cosmetic rules, hosts entries, regexes, URLs, ABP paths/modifiers,
    and MosDNS `full:` entries are not converted into broader domain blocks.

## AdRules licensing is inherited, not 0BSD

Cats-Team's script branch licenses its merger code under 0BSD. That license
does **not** license the generated rules in the main branch. The official
README states that generated rules retain the licenses of the original
upstream authors, including GPL-3.0, MIT and CC BY-SA 4.0.

The unmodified official README and upstream attribution table retrieved on
2026-10-18 are preserved as `AdRules-UPSTREAM-README.md` and
`AdRules-UPSTREAM-SOURCES.md`. The latter also lists LGPL, Creative Commons
noncommercial/share-alike entries, custom licenses and entries with no or
unknown license, and warns that the table may be outdated. We do not claim
that the combined dataset has a single permissive license or that this
snapshot clears every upstream's redistribution requirements. Preserve these
notices, the original upstream terms and attribution when redistributing.

Official licensing references:

- <https://github.com/Cats-Team/AdRules/blob/script/README.md#license>
- <https://github.com/Cats-Team/AdRules/blob/script/Source.md>

## Reproducible transformation

Each strong build requires both lists to download and validate successfully.
Mirrors are alternatives for the same source, never independent additions.
It normalizes ASCII DNS names to lowercase, strips one leading `www.`, merges
sources, applies the repository allowlist, removes redundant descendants and
encodes sorted, unique, 40-bit FNV-1a hashes as five little-endian bytes each.
An allowed child removes blocked ancestors as well as its own subtree; the
manifest records this consequence. Capacity overflow is an error, not truncation.

The release includes both original source bodies, normalized final domains,
effective allowlist, source URLs and SHA-256 digests, statistics, and these
notices. `tools/build_cn_rules.py` and its offline tests are the transformation
source. The manifest identifies every output's digest. SHA-256 detects damage
or a publication race; it is not an independent publisher signature.

Build with `python tools/build_cn_rules.py --profile strong --output-dir dist-s3`.
Offline reproduction accepts `--source source-anti-ad-domains.txt
--adrules-source source-adrules-mosdns.txt --allowlist allowlist.txt`.
The binary must be published to `cn-rules-s3`, never the legacy `cn-rules` tag.
