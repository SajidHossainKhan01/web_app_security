#!/usr/bin/env python3
"""SSRF Demo — Cloud metadata attack + allowlist defence. Run: python3 ssrf_demo.py"""
import ipaddress, urllib.parse

BLOCKED = [ipaddress.ip_network(n) for n in [
    "169.254.0.0/16","10.0.0.0/8","172.16.0.0/12",
    "192.168.0.0/16","127.0.0.0/8","0.0.0.0/8",
]]
ALLOWED = {"api.github.com", "api.stripe.com", "hooks.slack.com"}

def is_safe(url):
    try:
        p = urllib.parse.urlparse(url)
        if p.scheme not in {"https"}: return False, f"scheme {p.scheme!r} not allowed"
        h = p.hostname or ""
        if h not in ALLOWED:         return False, f"{h!r} not in allowlist"
        for pat in ["@","0x","0177",".nip.io","localhost","sslip.io"]:
            if pat in url.lower():   return False, f"bypass pattern {pat!r}"
        return True, "ok"
    except Exception as e:
        return False, str(e)

def main():
    print("=" * 60)
    print("  SSRF DEMO — CSE804")
    print("=" * 60)
    print("""
SSRF ATTACK:
  POST /api/fetch
  {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2Role"}

  Server fetches this internally -> IAM credentials leaked to attacker!
  Other targets: Redis (127.0.0.1:6379), internal APIs, cloud metadata.

Bypass Techniques:
  http://0x7f000001/          Hex localhost
  http://2130706433/          Decimal localhost
  http://169.254.169.254.nip.io/  DNS alias
  http://evil.com@api.github.com/ @ trick
""")

    tests = [
        ("http://169.254.169.254/latest/meta-data/",   "AWS metadata"),
        ("https://10.0.0.1/admin",                      "RFC 1918 A"),
        ("https://192.168.1.1/",                        "RFC 1918 C"),
        ("https://127.0.0.1/",                          "Loopback"),
        ("file:///etc/passwd",                           "File scheme"),
        ("https://evil.com/",                            "Not allowlisted"),
        ("https://169.254.169.254.nip.io/",             "DNS alias bypass"),
        ("http://evil.com@api.github.com/",              "@ bypass"),
        ("https://api.github.com/repos",                 "Allowlisted (OK)"),
    ]

    print("── Allowlist Validation Results ──")
    for url, desc in tests:
        ok, reason = is_safe(url)
        status = "✓ ALLOWED" if ok else "✗ BLOCKED"
        print(f"  {status}: {desc}")
        if not ok: print(f"           Reason: {reason}")

if __name__ == "__main__": main()
