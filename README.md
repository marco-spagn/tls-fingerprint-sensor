# TLS Fingerprint Sensor (JA3 / JA4 defensive correlation)

A small, real, **defensive** HTTPS sensor written in pure-Python (standard
library only). For every connection it captures the raw TLS `ClientHello`,
computes **JA3** and **JA4** fingerprints, correlates them against the HTTP
headers, records the result in SQLite, and exposes a live dashboard.

This is the observability/detection side of the bot-detection problem: the kind
of tool a site operator — or a proxy network measuring its own egress quality —
runs to answer *"which clients are hitting us, and do their crypto and
application layers tell the same story?"* It runs entirely on your own machine
against a self-signed certificate. It does not target anyone.

## Why this is not trivial

Neither Python's `ssl` module nor most TLS libraries expose the raw
`ClientHello`, yet that is exactly where JA3/JA4 live. The sensor therefore:

1. **Peeks** the first TLS record straight off the socket and parses the
   `ClientHello` itself (version, cipher order, ordered extensions, supported
   groups, ALPN, signature algorithms, GREASE).
2. **Replays** those bytes into an `ssl.MemoryBIO` so the real TLS handshake
   still completes normally. (You cannot hand already-consumed bytes back to
   `ssl.SSLSocket`, so a BIO pair is the correct mechanism.)

## The detection idea

**Chromium (BoringSSL) and Safari** emit **GREASE** values (RFC 8701) in their
`ClientHello`; standard HTTP clients — Python `requests`/`urllib`, `curl`, Go
`net/http` — do not. So a request whose **headers** claim to be Chrome but whose
**handshake** has no GREASE is almost certainly automation wearing a costume.

A subtlety worth calling out (and handled explicitly in the engine):
**Firefox does *not* reliably inject GREASE.** Treating "no GREASE" as proof of a
bot would therefore false-positive every genuine Firefox. So the GREASE rule is
scoped to Chromium/Safari User-Agents, and a **GREASE-independent** signal backs
it up: every mainstream browser — Chrome, Safari *and* Firefox — offers HTTP/2
(`h2`) in ALPN, whereas standard-library clients offer only `http/1.1`. That
catches an impostor spoofing a Firefox UA, where the GREASE rule intentionally
stays silent. The engine (`detection.py`) turns all of this into a transparent,
rule-by-rule score, and the dashboard's GREASE badge is UA-aware (it says
"normal for Firefox" rather than "tool/script" when the UA is Firefox).

## Files

| File                 | Role                                                                 |
|----------------------|----------------------------------------------------------------------|
| `tls_clienthello.py` | Raw `ClientHello` byte parser (transport-agnostic).                  |
| `fingerprints.py`    | JA3 (MD5) and JA4 (structured + SHA-256) computation.               |
| `detection.py`       | Rule-based correlation engine → `Verdict(blocked, score, reasons)`. |
| `storage.py`         | Thread-safe SQLite observation store + aggregates.                  |
| `sensor.py`          | The HTTPS sensor: peek → handshake → HTTP → verdict → dashboard.     |
| `probe.py`           | Demo client that spoofs a Chrome UA to show it gets flagged.         |

## Quick start

```bash
# 1. Local self-signed certificate
bash gen-certs.sh

# 2. (optional) install requests for the probe
pip install -r requirements.txt

# 3. Run the sensor
python sensor.py            # listens on https://0.0.0.0:8443
```

Then, from another terminal:

```bash
# Standard-library client spoofing Chrome -> BLOCK (403)
python probe.py

# Honest python-requests UA -> not flagged as a browser
python probe.py --honest
```

And open **https://localhost:8443/** in a real Chrome or Safari: it returns
**200 ALLOW**, because a genuine browser sends GREASE and a browser-grade
extension set. That side-by-side — real browser passes, spoofed client is
blocked — is the whole demonstration.

## What you'll see

The probe with a spoofed Chrome UA prints:

```
HTTP status : 403 Forbidden
verdict : BLOCK (score 70)
ja3     : a48c0d5f95b1ef98f560f324fd275da1
ja4     : t13d1812h1_85036bcba153_856db9a6daa0
reasons : browser User-Agent but ClientHello contains no GREASE values (standard-library TLS stack)
```

- **`/`** — HTML dashboard (auto-refreshes every 10s). It now centres on the
  **JA3 vs JA4 comparison**:
  - a *This connection* card showing **JA3 and JA4 side by side** — the JA3 MD5
    plus its raw pre-hash string, and the JA4 **decoded into its parts**
    (transport, TLS version, SNI flag, cipher/extension counts, ALPN, and the
    two SHA-256 halves), so you can see exactly what JA4 encodes that JA3 hides;
  - an *Observed handshake* panel (negotiated TLS version, GREASE yes/no, cipher
    / extension / signature-algorithm counts, ALPN, SNI);
  - a short **JA3 vs JA4 explainer** (order-sensitivity, structure, TLS 1.3/ALPN
    awareness);
  - a **JA3 ↔ JA4 correlation** table — per `(JA4, JA3)` pair with count,
    blocked count, GREASE, TLS version and cipher/extension counts, so you can
    spot when several JA3s collapse into one JA4 (cosmetic reordering that JA4
    folds together);
  - four headline counters: total requests, blocked, **unique JA3**, **unique
    JA4**;
  - an enriched *Recent observations* table (TLS, GREASE, ciph/ext, JA4 and JA3).
- **`/stats`** — JSON aggregates, now including `unique_ja3`, `unique_ja4`,
  `distinct_ja3` per JA4, a full `ja3_ja4_correlation` array, and a decoded
  `ja4_decoded` for the current connection (handy for scraping into Grafana/CI).
- **any other path** — plain-text verdict for the current connection.

## Endpoints

| Path        | Returns                                                        |
|-------------|---------------------------------------------------------------|
| `/`         | HTML dashboard (status 200 ALLOW / 403 BLOCK for the caller). |
| `/stats`    | JSON: totals + top JA4 fingerprints + this connection.        |
| other       | Plain-text verdict.                                           |

## Notes on the fingerprints

- **JA3** follows the original Salesforce definition:
  `MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats)`, GREASE
  stripped. It's ubiquitous but order-sensitive and dated.
- **JA4** follows the FoxIO definition:
  `a = t<ver><sni><nCiphers><nExts><alpn>`, `b = sha256(sorted ciphers)[:12]`,
  `c = sha256(sorted extensions without SNI/ALPN + "_" + sig-algs)[:12]`.
  Sorting makes it robust to the cosmetic reordering that breaks JA3.

## Extending it

- Add a JA4 allow/deny list keyed on known-good browser fingerprints.
- Front your real app and forward only ALLOW verdicts (reverse-proxy mode).
- Ship `/stats` to a metrics backend and alert on new high-volume JA4s.

## Legal / ethical note

Defensive, local, self-owned. Use it to understand and improve bot detection on
infrastructure you control — not to probe systems you don't.
