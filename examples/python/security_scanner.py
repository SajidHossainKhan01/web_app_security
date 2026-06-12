#!/usr/bin/env python3
"""HTTP Security Header Scanner — CSE804. Run: python3 security_scanner.py https://example.com"""
import sys, ssl, urllib.request, urllib.error
from urllib.parse import urlparse

HEADERS_TO_CHECK = [
    ("Strict-Transport-Security", True,  "Set: max-age=31536000; includeSubDomains; preload"),
    ("Content-Security-Policy",   True,  "Start with Report-Only mode, then enforce"),
    ("X-Content-Type-Options",    True,  "Set: nosniff"),
    ("X-Frame-Options",           True,  "Set: DENY"),
    ("Referrer-Policy",           False, "Set: strict-origin-when-cross-origin"),
    ("Permissions-Policy",        False, "Set: camera=(), microphone=(), geolocation=()"),
]
DISCLOSE_HEADERS = ["Server","X-Powered-By","X-AspNet-Version","X-Generator"]

def scan(url):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"CSE804-Scanner/1.0"})
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
            headers = {k.lower(): v for k,v in dict(r.headers).items()}
    except Exception as e:
        print(f"Connection error: {e}"); return

    G = "\033[0;32m"; R = "\033[0;31m"; Y = "\033[1;33m"; N = "\033[0m"
    passed = failed = 0

    print(f"\n{'='*60}")
    print(f"  Security Header Scan: {url}")
    print(f"{'='*60}")

    print("\n  Required Headers:")
    for name, required, rec in HEADERS_TO_CHECK:
        val = headers.get(name.lower())
        if val:
            print(f"  {G}[+]{N} {name}: {val[:60]}")
            passed += 1
        else:
            sev = R if required else Y
            print(f"  {sev}[-]{N} {name} MISSING — {rec}")
            failed += 1

    print("\n  Information Disclosure:")
    for h in DISCLOSE_HEADERS:
        val = headers.get(h.lower())
        if val:
            has_ver = any(c.isdigit() for c in val)
            print(f"  {R if has_ver else Y}[!]{N} {h}: {val}")
            failed += 1
        else:
            print(f"  {G}[+]{N} {h}: not exposed")
            passed += 1

    print("\n  Cookies:")
    cookie = headers.get("set-cookie","")
    if cookie:
        for attr, label in [("httponly","HttpOnly"),("secure","Secure"),("samesite","SameSite")]:
            if attr in cookie.lower():
                print(f"  {G}[+]{N} Cookie {label} present")
            else:
                print(f"  {R}[-]{N} Cookie {label} MISSING")

    total = passed + failed
    score = int(passed/total*100) if total else 0
    grade = "A" if score>=90 else "B" if score>=75 else "C" if score>=60 else "D" if score>=40 else "F"
    print(f"\n  Score: {score}% (Grade: {grade}) | Pass: {passed} | Fail: {failed}")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    scan(sys.argv[1] if len(sys.argv)>1 else "https://httpbin.org")
