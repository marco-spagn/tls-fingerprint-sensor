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

Real browsers (Chrome, Safari, Firefox) emit **GREASE** values (RFC 8701) in
their `ClientHello` and carry a large, characteristic extension set. Standard
HTTP clients — Python `requests`/`urllib`, `curl`, Go `net/http` — do not. So a
request whose **headers** claim to be Chrome but whose **handshake** has no
GREASE is almost certainly automation wearing a costume. The engine
(`detection.py`) turns that intuition into a transparent, explainable score.

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

- **`/`** — HTML dashboard: this connection's verdict plus recent observations
  and the top JA4 fingerprints seen.
- **`/stats`** — JSON aggregates (handy for scraping into Grafana/CI).
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
