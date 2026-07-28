"""Defensive correlation engine.

This is the part a site operator (or a proxy network measuring its own egress)
actually cares about: given the *cryptographic* story told by the ClientHello
and the *application* story told by the HTTP headers, do they agree?

The engine is intentionally transparent and rule-based rather than a black-box
score, so every decision is explainable — which is what you want in production
when someone asks "why did you block this request?".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from tls_clienthello import ClientHello, is_grease


@dataclass
class Verdict:
    blocked: bool
    score: int                       # 0..100 suspicion score
    reasons: List[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return "BLOCK" if self.blocked else "ALLOW"


def _ua(headers: Dict[str, str]) -> str:
    return headers.get("user-agent", "")


def claims_chromium(headers: Dict[str, str]) -> bool:
    ua = _ua(headers).lower()
    if "mozilla/5.0" not in ua:
        return False
    return "chrome/" in ua or "edg/" in ua or "chromium/" in ua


def claims_safari(headers: Dict[str, str]) -> bool:
    """Genuine Apple Safari. Chromium UAs also carry the 'safari' token, so we
    require 'version/' and the absence of chrome/chromium/edge markers."""
    ua = _ua(headers).lower()
    if "mozilla/5.0" not in ua:
        return False
    return (
        "safari" in ua
        and "version/" in ua
        and "chrome" not in ua
        and "chromium" not in ua
        and "edg/" not in ua
    )


def claims_browser(headers: Dict[str, str]) -> bool:
    return claims_chromium(headers) or claims_safari(headers)


def evaluate(headers: Dict[str, str], hello: ClientHello) -> Verdict:
    """Correlate HTTP headers against the TLS fingerprint and return a Verdict.

    Headers are expected lower-cased by the caller.
    """
    reasons: List[str] = []
    score = 0

    browser_ua = claims_browser(headers)
    real_ext = [e for e in hello.extensions if not is_grease(e)]

    # Signal 1 (strong): a real browser ALWAYS emits GREASE in its ClientHello.
    # A browser User-Agent over a GREASE-free handshake is the classic tell of a
    # standard-library HTTP client (Python requests/urllib, curl, Go net/http).
    if browser_ua and not hello.has_grease:
        score += 70
        reasons.append(
            "browser User-Agent but ClientHello contains no GREASE values "
            "(standard-library TLS stack)"
        )

    # Signal 2 (medium): Chromium advertises Sec-CH-UA client hints. Safari never
    # does, so this rule is scoped to Chromium only.
    if claims_chromium(headers) and "sec-ch-ua" not in headers and len(real_ext) < 9:
        score += 40
        reasons.append(
            "Chromium User-Agent but no Sec-CH-UA header and a thin extension set "
            f"({len(real_ext)} extensions)"
        )

    # Signal 3 (medium): any current browser offers TLS 1.3. A browser UA whose
    # handshake tops out below TLS 1.3 is inconsistent.
    if browser_ua and hello.negotiated_version and hello.negotiated_version < 0x0304:
        score += 40
        reasons.append(
            "browser User-Agent but the handshake does not offer TLS 1.3 "
            f"(max=0x{hello.negotiated_version:04x})"
        )

    # Signal 4 (weak): browsers always send a server_name (SNI) extension.
    if browser_ua and not hello.has_sni:
        score += 20
        reasons.append("browser User-Agent but no SNI extension")

    if not reasons:
        reasons.append("TLS fingerprint is consistent with the declared User-Agent")

    score = min(score, 100)
    blocked = score >= 50
    return Verdict(blocked=blocked, score=score, reasons=reasons)
