#!/usr/bin/env python3
"""XSS Demo — Stored/Reflected/DOM + encoding + CSP. Run: python3 xss_demo.py"""
import html, json, secrets, base64, urllib.parse

PAYLOADS = [
    '<script>alert(document.cookie)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><script>alert(1)</script>',
    '<iframe src=javascript:alert(1)>',
]

def main():
    print("=" * 60)
    print("  XSS DEMO — CSE804")
    print("=" * 60)

    # Stored XSS
    print("\n── ATTACK 1: Stored XSS (persists in DB, hits every visitor) ──")
    for p in PAYLOADS[:2]:
        safe = html.escape(p, quote=True)
        print(f"  Input:   {p}")
        print(f"  Encoded: {safe}")
        print(f"  Safe:    {'<' not in safe}")
        print()

    # Context-aware encoding
    print("── Context-Aware Output Encoding ──")
    val = '<script>alert(1)</script>'
    print(f"  HTML body:      {html.escape(val, quote=False)}")
    print(f"  HTML attribute: {html.escape(val, quote=True)}")
    print(f"  JavaScript:     {json.dumps(val)[1:-1]}")
    print(f"  URL parameter:  {urllib.parse.quote(val, safe='')}")

    # CSP nonce
    print("\n── CSP Nonce (eliminates XSS even if encoding missed) ──")
    nonce = base64.b64encode(secrets.token_bytes(16)).decode()
    csp = (f"default-src 'self'; script-src 'nonce-{nonce}' 'strict-dynamic'; "
           f"object-src 'none'; frame-ancestors 'none'")
    print(f"  Nonce:  {nonce}")
    print(f"  CSP:    {csp[:80]}...")
    print(f"  Usage:  <script nonce=\"{nonce}\">/* only this script runs */</script>")

    print("""
Defence Stack:
  1. Output encoding (html.escape, textContent not innerHTML)
  2. Content Security Policy (nonce-based, strict-dynamic)
  3. HttpOnly + Secure + SameSite=Strict cookies
  4. Trusted Types API (modern browsers)
""")

if __name__ == "__main__": main()
