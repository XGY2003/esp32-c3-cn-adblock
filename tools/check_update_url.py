#!/usr/bin/env python3
"""Check a public publication URL against the candidate firmware's HTTP contract.

This runs on the computer or CI runner; it does not prove ESP32 connectivity.
Usage: python tools/check_update_url.py https://your-host/rules/blocklist.bin
S3: python tools/check_update_url.py --profile strong https://your-host/s3/blocklist.bin
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import ssl
import urllib.parse
import urllib.request

from build_cn_rules import CAPACITY_PROFILES, profile_limits

MAX_BYTES = profile_limits('legacy')[1]


class HttpsRedirects(urllib.request.HTTPRedirectHandler):
    max_redirections = 3

    def redirect_request(self, request, fp, code, message, headers, new_url):
        if urllib.parse.urlsplit(new_url).scheme != 'https':
            raise ValueError('Publication redirected to a non-HTTPS URL')
        return super().redirect_request(request, fp, code, message, headers, new_url)


def check(url: str, profile: str = 'legacy') -> dict:
    maximum_bytes = profile_limits(profile)[1]
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.query or parsed.fragment or parsed.username:
        raise ValueError('Use a stable HTTPS URL without query, fragment, or user information')
    header = (Path(__file__).resolve().parents[1] / 'src' / 'update-ca.h').read_text(encoding='utf-8')
    roots = '\n'.join(re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', header, re.S))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=roots)
    opener = urllib.request.build_opener(HttpsRedirects(), urllib.request.HTTPSHandler(context=context))

    def download(target: str, maximum: int) -> bytes:
        request = urllib.request.Request(target, headers={'Accept-Encoding': 'identity', 'User-Agent': 'ESP32-CN-preflight/1'})
        with opener.open(request, timeout=20) as response:
            if response.status != 200:
                raise ValueError(f'HTTP {response.status}')
            if response.headers.get('Transfer-Encoding') or response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
                raise ValueError('Firmware requires an uncompressed, non-chunked response')
            size = int(response.headers.get('Content-Length', '-1'))
            if not 0 < size <= maximum:
                raise ValueError(f'Missing or invalid Content-Length: {size}')
            data = response.read(maximum + 1)
            if len(data) != size:
                raise ValueError('Response length mismatch')
            return data

    checksum = download(url + '.sha256', 66).decode('ascii').rstrip('\r\n')
    if not re.fullmatch('[0-9a-fA-F]{64}', checksum):
        raise ValueError('Checksum must be one line of 64 hex digits')
    data = download(url, maximum_bytes)
    if len(data) % 5:
        raise ValueError('Hash table is not a multiple of 5 bytes')
    values = [int.from_bytes(data[index:index + 5], 'little') for index in range(0, len(data), 5)]
    if any(a >= b for a, b in zip(values, values[1:])):
        raise ValueError('Hash table must be strictly sorted and unique')
    actual = hashlib.sha256(data).hexdigest()
    if actual != checksum.lower():
        raise ValueError('SHA256 mismatch; retry after publication has completed')
    return {'url': url, 'profile': profile, 'bytes': len(data), 'hashes': len(values), 'sha256': actual}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('url')
    parser.add_argument('--profile', choices=sorted(CAPACITY_PROFILES), default='legacy',
                        help='Use strong only for the expanded S3 firmware; default retains the C3 limit')
    arguments = parser.parse_args()
    try:
        print(check(arguments.url, arguments.profile))
    except Exception as error:
        parser.exit(1, f'Publication preflight failed: {error}\n')
