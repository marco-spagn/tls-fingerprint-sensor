"""TLS fingerprint sensor: a defensive HTTPS endpoint.

For every incoming connection the sensor:

  1. Peeks the raw ClientHello off the socket *before* the TLS library sees it.
  2. Parses it and computes JA3 + JA4 fingerprints.
  3. Completes the TLS handshake by replaying the peeked bytes into an
     ``ssl`` MemoryBIO (Python's ssl module cannot resume mid-stream otherwise).
  4. Reads the HTTP request, correlates headers vs. fingerprint, records the
     observation, and answers 200 (ALLOW) or 403 (BLOCK).

Paths:
  ``/``        -> HTML dashboard: this connection's verdict + recent observations
  ``/stats``   -> JSON aggregates (top JA4s, totals)
  anything else -> plain-text verdict for this connection

Everything runs locally against a self-signed certificate. Point your real
browser at https://localhost:8443/ to see an ALLOW, and run ``probe.py`` to see
a standard-library client get flagged.
"""

from __future__ import annotations

import argparse
import html
import json
import socket
import ssl
import threading
import time
from typing import Dict, Optional, Tuple

import detection
from fingerprints import decode_ja4, ja3_hash, ja3_string, ja4
from storage import Observation, Store, now
from tls_clienthello import is_grease, parse_client_hello, record_length


# --------------------------------------------------------------------------- #
# Low-level socket helpers
# --------------------------------------------------------------------------- #

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly ``n`` bytes from ``sock`` or raise ConnectionError on EOF."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed while reading %d bytes" % n)
        buf.extend(chunk)
    return bytes(buf)


def peek_client_hello(sock: socket.socket) -> Tuple[bytes, bytes]:
    """Read one TLS handshake record. Return (raw_record, handshake_body).

    ``raw_record`` (header + body) is replayed into the TLS engine afterwards so
    the handshake is not disturbed.
    """
    header = _recv_exact(sock, 5)
    body_len = record_length(header)          # raises if not a handshake
    body = _recv_exact(sock, body_len)
    return header + body, body


# --------------------------------------------------------------------------- #
# TLS over a MemoryBIO (so we can inject the already-read ClientHello)
# --------------------------------------------------------------------------- #

class BIOChannel:
    """Drive a server-side TLS handshake and I/O through ssl MemoryBIOs.

    We prime the inbound BIO with the bytes we already peeked, then pump data
    between the raw socket and the BIOs. This is the standard way to run TLS when
    you have consumed part of the stream yourself.
    """

    def __init__(self, sock: socket.socket, context: ssl.SSLContext, prefix: bytes) -> None:
        self._sock = sock
        self._inc = ssl.MemoryBIO()
        self._out = ssl.MemoryBIO()
        self._obj = context.wrap_bio(self._inc, self._out, server_side=True)
        if prefix:
            self._inc.write(prefix)

    def _flush_outgoing(self) -> None:
        data = self._out.read()
        if data:
            self._sock.sendall(data)

    def _feed_incoming(self) -> None:
        chunk = self._sock.recv(4096)
        if not chunk:
            self._inc.write_eof()
        else:
            self._inc.write(chunk)

    def do_handshake(self) -> None:
        while True:
            try:
                self._obj.do_handshake()
                self._flush_outgoing()
                return
            except ssl.SSLWantReadError:
                self._flush_outgoing()
                self._feed_incoming()

    def recv(self, size: int = 65536) -> bytes:
        while True:
            try:
                return self._obj.read(size)
            except ssl.SSLWantReadError:
                self._flush_outgoing()
                chunk = self._sock.recv(4096)
                if not chunk:
                    self._inc.write_eof()
                    try:
                        return self._obj.read(size)
                    except (ssl.SSLWantReadError, ssl.SSLZeroReturnError):
                        return b""
                self._inc.write(chunk)
            except ssl.SSLZeroReturnError:
                return b""

    def sendall(self, data: bytes) -> None:
        self._obj.write(data)
        self._flush_outgoing()

    def close(self) -> None:
        try:
            self._obj.unwrap()
            self._flush_outgoing()
        except (ssl.SSLError, OSError):
            pass


# --------------------------------------------------------------------------- #
# Minimal HTTP/1.1
# --------------------------------------------------------------------------- #

def read_http_request(channel: BIOChannel) -> Tuple[str, str, Dict[str, str]]:
    """Read one HTTP/1.1 request. Return (method, path, lower-cased headers)."""
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = channel.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > 65536:  # guard against oversized headers
            break

    text = bytes(buf).split(b"\r\n\r\n", 1)[0].decode("latin-1", errors="replace")
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        return "GET", "/", {}

    parts = lines[0].split(" ")
    method = parts[0] if parts else "GET"
    path = parts[1] if len(parts) > 1 else "/"

    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return method, path, headers


def http_response(status: str, body: str, content_type: str = "text/plain; charset=utf-8") -> bytes:
    payload = body.encode("utf-8")
    head = (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(payload)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    return head.encode("ascii") + payload


# --------------------------------------------------------------------------- #
# Dashboard rendering
# --------------------------------------------------------------------------- #

def render_dashboard(store: Store, this_verdict: Optional[dict]) -> str:
    total, blocked = store.totals()
    uja3, uja4 = store.distinct_counts()
    rows = store.recent(50)
    tops = store.top_fingerprints(15)
    corr = store.correlation(20)

    def esc(x: object) -> str:
        return html.escape(str(x))

    def grease_badge(present: bool, ua: str = "") -> str:
        if present:
            return "<span class='pill pill-ok'>GREASE ✓ browser-like</span>"
        hdr = {"user-agent": ua}
        # Absence of GREASE only *contradicts* a Chromium/Safari UA. For Firefox
        # it is normal, and for an honest tool UA it is expected — so don't cry
        # "tool/script" at a browser the signal doesn't even apply to.
        if detection.expects_grease(hdr):
            return "<span class='pill pill-bad'>no GREASE ✗ (contradicts UA)</span>"
        if detection.claims_firefox(hdr):
            return "<span class='pill pill-neutral'>no GREASE (normal for Firefox)</span>"
        return "<span class='pill pill-neutral'>no GREASE (tool/script)</span>"

    # ---- "this connection" card: JA3 vs JA4 side by side --------------------
    this_html = ""
    if this_verdict:
        colour = "#c0392b" if this_verdict["verdict"] == "BLOCK" else "#27ae60"
        reasons = "".join(f"<li>{esc(r)}</li>" for r in this_verdict["reasons"])
        d = this_verdict.get("ja4_decoded", {})
        decoded_rows = "".join(
            f"<tr><td class='muted'>{esc(k)}</td><td><code>{esc(v)}</code></td></tr>"
            for k, v in [
                ("transport", d.get("transport", "")),
                ("TLS version", d.get("tls_version", "")),
                ("SNI", d.get("sni", "")),
                ("cipher count", d.get("cipher_count", "")),
                ("extension count", d.get("extension_count", "")),
                ("ALPN", d.get("alpn", "")),
                ("ciphers hash (b)", d.get("ciphers_hash", "")),
                ("ext+sig hash (c)", d.get("exts_sig_hash", "")),
            ]
        )
        this_html = f"""
        <div class="card" style="border-left:6px solid {colour}">
          <h2>This connection —
              <span style="color:{colour}">{esc(this_verdict['verdict'])}</span>
              <span class="muted">(score {esc(this_verdict['score'])})</span></h2>
          <p><b>User-Agent:</b> {esc(this_verdict['user_agent']) or '<i>(none)</i>'}
             &nbsp; {grease_badge(this_verdict.get('has_grease', False),
                                  this_verdict.get('user_agent', ''))}</p>

          <div class="split">
            <div class="halfcard">
              <h3>JA3 <span class="muted">— MD5, order-sensitive (2017)</span></h3>
              <p><code class="big">{esc(this_verdict['ja3'])}</code></p>
              <p class="muted small">raw string (pre-hash):</p>
              <p><code class="small wrap">{esc(this_verdict.get('ja3_string',''))}</code></p>
            </div>
            <div class="halfcard">
              <h3>JA4 <span class="muted">— structured + SHA-256, sorted (2023)</span></h3>
              <p><code class="big">{esc(this_verdict['ja4'])}</code></p>
              <table class="mini">{decoded_rows}</table>
            </div>
          </div>

          <h3>Observed handshake</h3>
          <table class="mini kv">
            <tr><td class="muted">negotiated TLS</td><td>{esc(this_verdict.get('tls_version'))}</td>
                <td class="muted">GREASE</td><td>{esc(this_verdict.get('has_grease'))}</td></tr>
            <tr><td class="muted">cipher suites</td><td>{esc(this_verdict.get('n_ciphers'))}</td>
                <td class="muted">extensions</td><td>{esc(this_verdict.get('n_ext'))}</td></tr>
            <tr><td class="muted">signature algs</td><td>{esc(this_verdict.get('n_sig_algs'))}</td>
                <td class="muted">ALPN</td><td>{esc(this_verdict.get('alpn'))}</td></tr>
            <tr><td class="muted">SNI</td><td colspan="3">{esc(this_verdict.get('sni'))}</td></tr>
          </table>
          <ul>{reasons}</ul>
        </div>"""

    # ---- JA3 vs JA4 explainer ----------------------------------------------
    explainer = """
     <div class="card">
       <h2>JA3 vs JA4 — what each captures</h2>
       <table class="mini">
         <tr><th></th><th>JA3</th><th>JA4</th></tr>
         <tr><td class="muted">form</td><td>32-char MD5</td>
             <td><code>a_b_c</code>: readable prefix + two SHA-256 halves</td></tr>
         <tr><td class="muted">cipher / ext order</td>
             <td>order-<b>sensitive</b> (reordering ⇒ new hash)</td>
             <td><b>sorted</b> before hashing (robust to reshuffling)</td></tr>
         <tr><td class="muted">human-readable</td><td>no</td>
             <td>yes — TLS version, SNI, counts, ALPN visible</td></tr>
         <tr><td class="muted">TLS 1.3 / ALPN aware</td><td>partial</td><td>yes</td></tr>
       </table>
       <p class="muted small">Both strip GREASE before hashing, so GREASE is
          tracked separately (its <i>presence</i> is the browser tell).</p>
     </div>"""

    # ---- top JA4 (now with distinct-JA3 column) ----------------------------
    top_rows = "".join(
        f"<tr><td><code>{esc(ja4v)}</code></td><td>{esc(t)}</td>"
        f"<td class='{'block' if b else ''}'>{esc(b)}</td>"
        f"<td>{esc(d)}{' ⚠️' if d > 1 else ''}</td></tr>"
        for (ja4v, t, b, d) in tops
    )

    # ---- JA3 <-> JA4 correlation -------------------------------------------
    corr_rows = "".join(
        f"<tr>"
        f"<td><code>{esc(r[0])}</code></td>"
        f"<td><code>{esc(r[1])}</code></td>"
        f"<td>{esc(r[2])}</td>"
        f"<td class='{'block' if r[3] else ''}'>{esc(r[3])}</td>"
        f"<td>{grease_badge(bool(r[4]), r[8] if len(r) > 8 else '')}</td>"
        f"<td>{esc(r[5] and _tls_version_name(r[5]))}</td>"
        f"<td>{esc(r[6])}</td><td>{esc(r[7])}</td>"
        f"</tr>"
        for r in corr
    )

    # ---- recent observations (enriched) ------------------------------------
    recent_rows = "".join(
        f"<tr><td>{esc(time.strftime('%H:%M:%S', time.localtime(o.ts)))}</td>"
        f"<td>{esc(o.remote_ip)}</td>"
        f"<td class='{'block' if o.verdict=='BLOCK' else 'allow'}'>{esc(o.verdict)}</td>"
        f"<td>{esc(o.score)}</td>"
        f"<td>{esc(o.tls_version and _tls_version_name(o.tls_version))}</td>"
        f"<td>{'✓' if o.has_grease else '·'}</td>"
        f"<td>{esc(o.n_ciphers)}/{esc(o.n_ext)}</td>"
        f"<td><code>{esc(o.ja4)}</code></td>"
        f"<td><code class='small'>{esc(o.ja3[:12])}…</code></td>"
        f"<td>{esc(o.user_agent[:48])}</td></tr>"
        for o in rows
    )

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>TLS Fingerprint Sensor</title>
<meta http-equiv="refresh" content="10">
<style>
 body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem;
        color:#222; background:#fafafa }}
 h1 {{ margin-bottom:.2rem }} h3 {{ margin:.6rem 0 .3rem }}
 .card {{ background:#fff; padding:1rem 1.2rem; border-radius:8px;
          box-shadow:0 1px 4px rgba(0,0,0,.08); margin:1rem 0 }}
 .stats {{ display:flex; gap:1.5rem; flex-wrap:wrap; margin:.3rem 0 }}
 .stat {{ background:#fff; border-radius:8px; padding:.6rem 1rem;
          box-shadow:0 1px 4px rgba(0,0,0,.08); min-width:7rem }}
 .stat b {{ display:block; font-size:1.6rem; line-height:1.1 }}
 .split {{ display:flex; gap:1rem; flex-wrap:wrap }}
 .halfcard {{ flex:1 1 320px; background:#f7f9fb; border:1px solid #eee;
              border-radius:6px; padding:.6rem .8rem }}
 table {{ border-collapse:collapse; width:100%; background:#fff; font-size:.9rem }}
 table.mini {{ font-size:.85rem }} table.kv td {{ border:none; padding:.2rem .5rem }}
 th,td {{ text-align:left; padding:.4rem .6rem; border-bottom:1px solid #eee;
          vertical-align:top }}
 code {{ font-size:.82rem }} code.big {{ font-size:.95rem; font-weight:600 }}
 code.small {{ font-size:.75rem }} code.wrap {{ word-break:break-all }}
 .allow {{ color:#27ae60; font-weight:600 }}
 .block {{ color:#c0392b; font-weight:600 }}
 .muted {{ color:#888 }} .small {{ font-size:.8rem }}
 .pill {{ display:inline-block; padding:.05rem .5rem; border-radius:999px;
          font-size:.72rem; font-weight:600 }}
 .pill-ok {{ background:#e6f7ee; color:#1d8a4e }}
 .pill-bad {{ background:#fdecea; color:#c0392b }}
 .pill-neutral {{ background:#eef1f4; color:#667 }}
 .tblwrap {{ overflow-x:auto }}
</style></head><body>
 <h1>TLS Fingerprint Sensor</h1>
 <p class="muted">Defensive JA3 / JA4 correlation · auto-refresh 10s</p>
 <div class="stats">
   <div class="stat"><b>{esc(total)}</b>requests</div>
   <div class="stat"><b>{esc(blocked)}</b>blocked</div>
   <div class="stat"><b>{esc(uja3)}</b>unique JA3</div>
   <div class="stat"><b>{esc(uja4)}</b>unique JA4</div>
 </div>
 {this_html}
 {explainer}
 <div class="card">
   <h2>JA3 ↔ JA4 correlation <span class="muted small">— do the two agree?</span></h2>
   <p class="muted small">Same JA4 with several JA3 rows = clients JA3 splits but
      JA4 unifies. GREASE-free rows with a browser handshake shape are the ones
      the engine flags.</p>
   <div class="tblwrap">
   <table><tr><th>JA4</th><th>JA3</th><th>Count</th><th>Blocked</th>
     <th>GREASE</th><th>TLS</th><th>#ciph</th><th>#ext</th></tr>{corr_rows}</table>
   </div>
 </div>
 <div class="card">
   <h2>Top JA4 fingerprints</h2>
   <table><tr><th>JA4</th><th>Total</th><th>Blocked</th>
     <th>distinct JA3</th></tr>{top_rows}</table>
 </div>
 <div class="card">
   <h2>Recent observations</h2>
   <div class="tblwrap">
   <table><tr><th>Time</th><th>IP</th><th>Verdict</th><th>Score</th>
     <th>TLS</th><th>GRE</th><th>ciph/ext</th><th>JA4</th><th>JA3</th>
     <th>User-Agent</th></tr>{recent_rows}</table>
   </div>
 </div>
</body></html>"""


def _tls_version_name(v: int) -> str:
    return {0x0304: "1.3", 0x0303: "1.2", 0x0302: "1.1",
            0x0301: "1.0"}.get(v, f"0x{v:04x}")


# --------------------------------------------------------------------------- #
# Connection handling
# --------------------------------------------------------------------------- #

def handle_connection(sock: socket.socket, addr, context: ssl.SSLContext, store: Store) -> None:
    remote_ip = addr[0]
    try:
        raw_record, hello_body = peek_client_hello(sock)
    except (ConnectionError, ValueError) as exc:
        print(f"[peek] {remote_ip}: {exc}")
        sock.close()
        return

    # Fingerprint the handshake.
    try:
        hello = parse_client_hello(hello_body)
        ja3 = ja3_hash(hello)
        ja3_raw = ja3_string(hello)
        ja4_fp = ja4(hello)
    except ValueError as exc:
        print(f"[parse] {remote_ip}: {exc}")
        sock.close()
        return

    # Complete the handshake, replaying the peeked bytes.
    channel = BIOChannel(sock, context, prefix=raw_record)
    try:
        channel.do_handshake()
    except (ssl.SSLError, ConnectionError, OSError) as exc:
        print(f"[handshake] {remote_ip}: {exc}")
        sock.close()
        return

    try:
        method, path, headers = read_http_request(channel)
    except (ssl.SSLError, ConnectionError, OSError) as exc:
        print(f"[http] {remote_ip}: {exc}")
        channel.close()
        sock.close()
        return

    verdict = detection.evaluate(headers, hello)
    user_agent = headers.get("user-agent", "")

    real_ciphers = [c for c in hello.cipher_suites if not is_grease(c)]
    real_ext = [e for e in hello.extensions if not is_grease(e)]
    alpn_str = ", ".join(hello.alpn) if hello.alpn else ""

    store.record(Observation(
        ts=now(), remote_ip=remote_ip, ja3=ja3, ja4=ja4_fp,
        user_agent=user_agent, verdict=verdict.label, score=verdict.score,
        reason="; ".join(verdict.reasons),
        tls_version=hello.negotiated_version, n_ciphers=len(real_ciphers),
        n_ext=len(real_ext), has_grease=1 if hello.has_grease else 0,
        alpn=alpn_str, sni=hello.server_name or "",
    ))

    # Log line for the operator's console.
    colour = "\033[31m" if verdict.blocked else "\033[32m"
    print("-" * 70)
    print(f"[conn] {remote_ip}  {method} {path}")
    print(f"[ua  ] {user_agent}")
    print(f"[ja3 ] {ja3}")
    print(f"[ja4 ] {ja4_fp}   GREASE={hello.has_grease}  "
          f"TLS=0x{hello.negotiated_version:04x}  ext={len(hello.extensions)}")
    print(f"[verd] {colour}{verdict.label} (score {verdict.score})\033[0m "
          f"-> {'; '.join(verdict.reasons)}")

    def _tls_name(v: int) -> str:
        return {0x0304: "TLS 1.3", 0x0303: "TLS 1.2", 0x0302: "TLS 1.1",
                0x0301: "TLS 1.0"}.get(v, f"0x{v:04x}")

    this_verdict = {
        "verdict": verdict.label, "score": verdict.score, "reasons": verdict.reasons,
        "user_agent": user_agent, "ja3": ja3, "ja3_string": ja3_raw, "ja4": ja4_fp,
        "ja4_decoded": decode_ja4(ja4_fp),
        "tls_version": _tls_name(hello.negotiated_version),
        "has_grease": hello.has_grease,
        "n_ciphers": len(real_ciphers), "n_ext": len(real_ext),
        "alpn": alpn_str or "none", "sni": hello.server_name or "(none)",
        "n_sig_algs": len([s for s in hello.signature_algorithms if not is_grease(s)]),
    }

    if path.startswith("/stats"):
        total, blocked = store.totals()
        uja3, uja4 = store.distinct_counts()
        payload = {
            "total_requests": total,
            "total_blocked": blocked,
            "unique_ja3": uja3,
            "unique_ja4": uja4,
            "top_ja4": [
                {"ja4": j, "total": t, "blocked": b, "distinct_ja3": d}
                for (j, t, b, d) in store.top_fingerprints(20)
            ],
            "ja3_ja4_correlation": [
                {"ja4": r[0], "ja3": r[1], "total": r[2], "blocked": r[3],
                 "has_grease": bool(r[4]), "tls_version": _tls_name(r[5]),
                 "n_ciphers": r[6], "n_ext": r[7]}
                for r in store.correlation(20)
            ],
            "this_connection": this_verdict,
        }
        resp = http_response("200 OK", json.dumps(payload, indent=2),
                             "application/json")
    elif path == "/" or path.startswith("/dashboard"):
        status = "403 Forbidden" if verdict.blocked else "200 OK"
        resp = http_response(status, render_dashboard(store, this_verdict),
                             "text/html; charset=utf-8")
    else:
        status = "403 Forbidden" if verdict.blocked else "200 OK"
        body = (
            f"{status}\n"
            f"verdict : {verdict.label} (score {verdict.score})\n"
            f"ja3     : {ja3}\n"
            f"ja4     : {ja4_fp}\n"
            f"reasons : {'; '.join(verdict.reasons)}\n"
        )
        resp = http_response(status, body)

    try:
        channel.sendall(resp)
    except (ssl.SSLError, ConnectionError, OSError):
        pass
    finally:
        channel.close()
        sock.close()


def serve(host: str, port: int, certfile: str, keyfile: str, db: str) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    # Offer HTTP/1.1 via ALPN; the sensor speaks HTTP/1.1.
    try:
        context.set_alpn_protocols(["http/1.1"])
    except NotImplementedError:
        pass

    store = Store(db)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(128)

    print(f"TLS Fingerprint Sensor listening on https://{host}:{port}")
    print("Open the URL in a real browser (ALLOW) or run probe.py (BLOCK).")

    try:
        while True:
            sock, addr = listener.accept()
            threading.Thread(
                target=handle_connection,
                args=(sock, addr, context, store),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        listener.close()


def main() -> None:
    ap = argparse.ArgumentParser(description="Defensive TLS fingerprint sensor")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--cert", default="server.crt")
    ap.add_argument("--key", default="server.key")
    ap.add_argument("--db", default="observations.db")
    args = ap.parse_args()
    serve(args.host, args.port, args.cert, args.key, args.db)


if __name__ == "__main__":
    main()
