"""Raw TLS ClientHello parser.

Neither Python's ``ssl`` module nor Go's ``crypto/tls`` exposes the raw
ClientHello (extension order, GREASE values, supported groups, ...), yet those
are exactly the bytes a fingerprint such as JA3/JA4 is computed from. So we
parse the handshake ourselves, straight off the wire, before the TLS library
ever sees it.

This module is transport-agnostic: it turns a chunk of bytes (one TLS
handshake record) into a structured :class:`ClientHello`. The networking layer
in ``sensor.py`` is responsible for reading those bytes and replaying them into
the real handshake.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


def is_grease(value: int) -> bool:
    """Return True if ``value`` is a GREASE placeholder (RFC 8701).

    GREASE values have the form 0xNaNa: the high and low bytes are equal and the
    low nibble is 0xa (0x0a0a, 0x1a1a, ... 0xfafa). Real browsers sprinkle these
    into the ClientHello to keep middleboxes tolerant of unknown values; the
    Python ``ssl`` module, Go ``crypto/tls`` and most raw HTTP clients do not.
    """
    return (value >> 8) == (value & 0xFF) and (value & 0x0F) == 0x0A


class _Reader:
    """A tiny bounds-checked, big-endian cursor over a bytes buffer."""

    def __init__(self, data: bytes) -> None:
        self._d = data
        self._p = 0

    @property
    def remaining(self) -> int:
        return len(self._d) - self._p

    def u8(self) -> int:
        if self.remaining < 1:
            raise ValueError("unexpected end of data (u8)")
        v = self._d[self._p]
        self._p += 1
        return v

    def u16(self) -> int:
        if self.remaining < 2:
            raise ValueError("unexpected end of data (u16)")
        v = (self._d[self._p] << 8) | self._d[self._p + 1]
        self._p += 2
        return v

    def u24(self) -> int:
        if self.remaining < 3:
            raise ValueError("unexpected end of data (u24)")
        v = (self._d[self._p] << 16) | (self._d[self._p + 1] << 8) | self._d[self._p + 2]
        self._p += 3
        return v

    def take(self, n: int) -> bytes:
        if n < 0 or self.remaining < n:
            raise ValueError("unexpected end of data (take %d)" % n)
        v = self._d[self._p:self._p + n]
        self._p += n
        return v


@dataclass
class ClientHello:
    """Structured view of a parsed ClientHello."""

    legacy_version: int = 0
    cipher_suites: List[int] = field(default_factory=list)     # order preserved
    extensions: List[int] = field(default_factory=list)        # order preserved
    supported_versions: List[int] = field(default_factory=list)
    supported_groups: List[int] = field(default_factory=list)  # named curves
    ec_point_formats: List[int] = field(default_factory=list)
    signature_algorithms: List[int] = field(default_factory=list)
    alpn: List[str] = field(default_factory=list)
    server_name: Optional[str] = None

    @property
    def has_sni(self) -> bool:
        return self.server_name is not None

    @property
    def has_grease(self) -> bool:
        return (any(is_grease(c) for c in self.cipher_suites)
                or any(is_grease(e) for e in self.extensions))

    @property
    def negotiated_version(self) -> int:
        """The highest real (non-GREASE) TLS version the client offered."""
        real = [v for v in self.supported_versions if not is_grease(v)]
        if real:
            return max(real)
        return self.legacy_version


# TLS record content type for handshake messages.
RECORD_TYPE_HANDSHAKE = 0x16
# Handshake message type for ClientHello.
HANDSHAKE_TYPE_CLIENT_HELLO = 0x01


def record_length(header: bytes) -> int:
    """Given the 5-byte TLS record header, return the record body length.

    Raises ValueError if the header is not a handshake record.
    """
    if len(header) < 5:
        raise ValueError("record header too short")
    if header[0] != RECORD_TYPE_HANDSHAKE:
        raise ValueError("first record is not a handshake (type=0x%02x)" % header[0])
    return (header[3] << 8) | header[4]


def parse_client_hello(body: bytes) -> ClientHello:
    """Parse the handshake body of a ClientHello into a :class:`ClientHello`.

    Layout (RFC 8446 / 5246):
        handshake_type(1) length(3) client_version(2) random(32)
        session_id(1+n) cipher_suites(2+n) compression(1+n) extensions(2+n)
    """
    r = _Reader(body)

    if r.u8() != HANDSHAKE_TYPE_CLIENT_HELLO:
        raise ValueError("handshake is not a ClientHello")
    r.u24()  # handshake length (already bounded by the record)

    hello = ClientHello()
    hello.legacy_version = r.u16()
    r.take(32)  # random

    session_id_len = r.u8()
    r.take(session_id_len)

    cs_len = r.u16()
    cs_bytes = r.take(cs_len)
    hello.cipher_suites = [
        (cs_bytes[i] << 8) | cs_bytes[i + 1] for i in range(0, len(cs_bytes) - 1, 2)
    ]

    comp_len = r.u8()
    r.take(comp_len)

    if r.remaining < 2:
        return hello  # no extensions block (ancient client)
    ext_total = r.u16()
    ext_bytes = r.take(ext_total)
    _parse_extensions(ext_bytes, hello)

    return hello


def _parse_extensions(data: bytes, hello: ClientHello) -> None:
    r = _Reader(data)
    while r.remaining >= 4:
        ext_type = r.u16()
        ext_len = r.u16()
        ext_data = r.take(ext_len)
        hello.extensions.append(ext_type)

        if ext_type == 0x0000:      # server_name
            hello.server_name = _parse_sni(ext_data)
        elif ext_type == 0x000A:    # supported_groups (named curves)
            hello.supported_groups = _parse_u16_list(ext_data)
        elif ext_type == 0x000B:    # ec_point_formats
            er = _Reader(ext_data)
            n = er.u8()
            hello.ec_point_formats = list(er.take(n))
        elif ext_type == 0x000D:    # signature_algorithms
            hello.signature_algorithms = _parse_u16_list(ext_data)
        elif ext_type == 0x0010:    # ALPN
            hello.alpn = _parse_alpn(ext_data)
        elif ext_type == 0x002B:    # supported_versions
            er = _Reader(ext_data)
            n = er.u8()
            vb = er.take(n)
            hello.supported_versions = [
                (vb[i] << 8) | vb[i + 1] for i in range(0, len(vb) - 1, 2)
            ]


def _parse_u16_list(data: bytes) -> List[int]:
    """Parse a 2-byte-length-prefixed list of u16 values."""
    er = _Reader(data)
    list_len = er.u16()
    lb = er.take(list_len)
    return [(lb[i] << 8) | lb[i + 1] for i in range(0, len(lb) - 1, 2)]


def _parse_sni(data: bytes) -> Optional[str]:
    # The SNI host_name is carried on the wire as an ASCII A-label (already
    # punycode-encoded for IDNs), so decode it as ASCII rather than through the
    # 'idna' codec, which rejects the errors= argument and would raise.
    try:
        er = _Reader(data)
        er.u16()          # server_name_list length
        er.u8()           # name_type (0 = host_name)
        name_len = er.u16()
        return er.take(name_len).decode("ascii", errors="replace")
    except (ValueError, UnicodeError):
        return None


def _parse_alpn(data: bytes) -> List[str]:
    out: List[str] = []
    try:
        er = _Reader(data)
        er.u16()          # ALPN protocol list length
        while er.remaining > 0:
            plen = er.u8()
            if plen == 0:
                break
            out.append(er.take(plen).decode("ascii", errors="replace"))
    except ValueError:
        pass
    return out
