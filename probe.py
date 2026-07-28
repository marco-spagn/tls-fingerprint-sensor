"""Demonstration client.

Sends an HTTPS request to the local sensor while *spoofing* a Chrome User-Agent.
Because this uses the standard Python TLS stack (OpenSSL, no GREASE), the sensor
detects the mismatch between the browser header and the library fingerprint and
returns 403 — exactly what a defensive system should do.

Contrast this with opening https://localhost:8443/ in a real Chrome/Safari,
which passes (real browsers emit GREASE and a browser-grade extension set).

Usage:
    python probe.py                 # spoofed Chrome UA  -> expect BLOCK
    python probe.py --honest        # honest python UA   -> not flagged as a browser
"""

from __future__ import annotations

import argparse
import sys

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)       # type: ignore
except ImportError:
    print("This probe needs 'requests'. Install it with: pip install requests")
    sys.exit(1)

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="https://localhost:8443/probe")
    ap.add_argument("--honest", action="store_true",
                    help="send an honest python-requests User-Agent instead of spoofing Chrome")
    args = ap.parse_args()

    if args.honest:
        headers = {}  # requests will send its own python-requests/x.y User-Agent
        print("Sending HONEST python-requests User-Agent (not claiming to be a browser)")
    else:
        headers = {
            "User-Agent": CHROME_UA,
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        }
        print("Sending SPOOFED Chrome User-Agent over Python's TLS stack (no GREASE)")

    resp = requests.get(args.url, headers=headers, verify=False, timeout=10)

    print("=" * 60)
    print(f"HTTP status : {resp.status_code} {resp.reason}")
    print(resp.text)
    print("=" * 60)
    if resp.status_code == 403:
        print("RESULT: BLOCKED — the sensor caught the header/TLS mismatch.")
    else:
        print("RESULT: allowed / not flagged.")


if __name__ == "__main__":
    main()
