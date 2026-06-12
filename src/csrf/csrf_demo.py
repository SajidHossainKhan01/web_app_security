#!/usr/bin/env python3
"""CSRF Demo — Attack mechanics + token/SameSite defence. Run: python3 csrf_demo.py"""
import hashlib, hmac, secrets, time

KEY = secrets.token_bytes(32)

def gen_token(session_id):
    ts  = str(int(time.time()))
    sig = hmac.new(KEY, f"{session_id}:{ts}".encode(), hashlib.sha256).hexdigest()
    return f"{ts}:{sig}"

def verify_token(session_id, token, max_age=3600):
    if not token or ":" not in str(token): return False
    try:
        ts_str, sig = token.split(":", 1)
        if time.time() - int(ts_str) > max_age: return False
    except: return False
    exp = hmac.new(KEY, f"{session_id}:{ts_str}".encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, exp)

def main():
    print("=" * 60)
    print("  CSRF DEMO — CSE804")
    print("=" * 60)

    print("""
CSRF ATTACK:
  evil.com embeds:
    <form action="https://bank.com/transfer" method="POST">
      <input type="hidden" name="to"     value="attacker">
      <input type="hidden" name="amount" value="1000">
    </form>
    <body onload="document.forms[0].submit()">

  Browser auto-submits with victim\'s session cookie → transfer executes!
""")

    print("── DEFENCE 1: CSRF Token ──")
    sid   = secrets.token_hex(16)
    token = gen_token(sid)
    print(f"  Token (embedded in form): {token[:40]}...")
    print(f"  Valid:          {verify_token(sid, token)}")
    print(f"  Wrong session:  {verify_token('other_session', token)}")
    print(f"  Tampered:       {verify_token(sid, token + 'x')}")
    print(f"  Expired:        {verify_token(sid, '0:' + secrets.token_hex(32))}")

    print("""
── DEFENCE 2: SameSite=Strict Cookie ──
  Set-Cookie: session=abc; SameSite=Strict; Secure; HttpOnly
  -> Cross-site form submission sends NO cookie -> server rejects

── DEFENCE 3: Double-Submit Cookie ──
  Server sets CSRF cookie (not HttpOnly); JS reads and includes as header.
  Attacker cannot read the cookie (Same-Origin Policy).

── DEFENCE 4: Custom Header (AJAX) ──
  Require: X-Requested-With: XMLHttpRequest
  Cross-site forms cannot set custom headers without CORS pre-flight.
""")

if __name__ == "__main__": main()
