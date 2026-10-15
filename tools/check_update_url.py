#!/usr/bin/env python3
"""Check a public publication URL against the candidate firmware's HTTP contract.

This runs on the computer or CI runner; it does not prove ESP32 connectivity.
Usage: python tools/check_update_url.py https://your-host/rules/blocklist.bin
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import ssl
import urllib.parse
import urllib.request

MAX_BYTES = 550_000


class HttpsRedirects(urllib.request.HTTPRedirectHandler):
    max_redirections = 3

    def redirect_request(self, request, fp, code, message, headers, new_url):
        if urllib.parse.urlsplit(new_url).scheme != 'https':
            raise ValueError('Publication redirected to a non-HTTPS URL')
        return super().redirect_request(request, fp, code, message, headers, new_url)


def check(url: str) -> dict:
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
    data = download(url, MAX_BYTES)
    if len(data) % 5:
        raise ValueError('Hash table is not a multiple of 5 bytes')
    values = [int.from_bytes(data[index:index + 5], 'little') for index in range(0, len(data), 5)]
    if any(a >= b for a, b in zip(values, values[1:])):
        raise ValueError('Hash table must be strictly sorted and unique')
    actual = hashlib.sha256(data).hexdigest()
    if actual != checksum.lower():
        raise ValueError('SHA256 mismatch; retry after publication has completed')
    return {'url': url, 'bytes': len(data), 'hashes': len(values), 'sha256': actual}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('url')
    arguments = parser.parse_args()
    try:
        print(check(arguments.url))
    except Exception as error:
        parser.exit(1, f'Publication preflight failed: {error}\n')
