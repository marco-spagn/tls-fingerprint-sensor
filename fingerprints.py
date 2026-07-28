"""Compute JA3 and JA4 fingerprints from a parsed ClientHello.

- **JA3** (2017, Salesforce) is an MD5 over a comma-separated string of
  TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats. It is simple and
  ubiquitous but brittle: extension order matters, and it predates TLS 1.3
  niceties, so many modern clients collide or shift.

- **JA4** (2023, FoxIO) is the modern successor. It is a structured, human-
  readable prefix plus two truncated SHA-256 hashes, and it deliberately sorts
  ciphers/extensions so cosmetic reordering no longer changes the fingerprint.

Both implementations here follow the public specifications and strip GREASE
values before hashing, which is required for a stable fingerprint.
"""

from __future__ import annotations

import hashlib
from typing import List

from tls_clienthello import ClientHello, is_grease


def _no_grease(values: List[int]) -> List[int]:
    return [v for v in values if not is_grease(v)]


# --------------------------------------------------------------------------- #
# JA3
# --------------------------------------------------------------------------- #

def ja3_string(hello: ClientHello) -> str:
    """Build the raw JA3 string (before hashing)."""
    version = hello.legacy_version
    ciphers = "-".join(str(c) for c in _no_grease(hello.cipher_suites))
    extensions = "-".join(str(e) for e in _no_grease(hello.extensions))
    curves = "-".join(str(c) for c in _no_grease(hello.supported_groups))
    formats = "-".join(str(f) for f in hello.ec_point_formats)
    return f"{version},{ciphers},{extensions},{curves},{formats}"


def ja3_hash(hello: ClientHello) -> str:
    """Return the 32-char MD5 JA3 hash."""
    return hashlib.md5(ja3_string(hello).encode("ascii")).hexdigest()


# --------------------------------------------------------------------------- #
# JA4
# --------------------------------------------------------------------------- #

_TLS_VERSION_TOKENS = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
}


def _ja4_version_token(version: int) -> str:
    return _TLS_VERSION_TOKENS.get(version, "00")


def _sha256_12(values_hex: List[str]) -> str:
    """SHA-256 of a comma-joined list, truncated to 12 hex chars (JA4 rule)."""
    joined = ",".join(values_hex)
    return hashlib.sha256(joined.encode("ascii")).hexdigest()[:12]


def ja4(hello: ClientHello, transport: str = "t") -> str:
    """Compute a JA4 fingerprint of the form ``<a>_<b>_<c>``.

    - ``a`` = transport(t/q) + tls_version + sni(d/i) + cipher_count(2) +
      extension_count(2) + first_alpn(2 chars)
    - ``b`` = sha256(sorted ciphers)[:12]
    - ``c`` = sha256(sorted extensions, SNI & ALPN removed) + "_" +
      signature_algorithms(order preserved), then [:12]
    """
    ciphers = _no_grease(hello.cipher_suites)
    extensions = _no_grease(hello.extensions)

    sni = "d" if hello.has_sni else "i"

    if hello.alpn and hello.alpn[0]:
        first = hello.alpn[0]
        alpn = f"{first[0]}{first[-1]}"
    else:
        alpn = "00"

    version_token = _ja4_version_token(hello.negotiated_version)

    a = f"{transport}{version_token}{sni}{len(ciphers):02d}{len(extensions):02d}{alpn}"

    b = _sha256_12(sorted(f"{c:04x}" for c in ciphers))

    # Per JA4: exclude SNI (0x0000) and ALPN (0x0010) from the extension hash,
    # sort the remainder, then append the signature algorithms in original order.
    hash_exts = sorted(f"{e:04x}" for e in extensions if e not in (0x0000, 0x0010))
    sig_algs = [f"{s:04x}" for s in _no_grease(hello.signature_algorithms)]
    c_input = hash_exts + (["_"] + sig_algs if sig_algs else [])
    c = _sha256_12(c_input)

    return f"{a}_{b}_{c}"
