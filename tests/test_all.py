#!/usr/bin/env python3
"""Complete Test Suite — CSE804 Web & App Layer Security. Run: python3 test_all.py"""
import sys, html, json, hashlib, hmac, secrets, time, ipaddress, urllib.parse, base64, sqlite3

PASS = 0; FAIL = 0

def test(name, cond, detail=""):
    global PASS, FAIL
    c = "\033[0;32m" if cond else "\033[0;31m"
    m = "+" if cond else "x"
    r = "\033[0m"
    print(f"  {c}[{m}]{r} {name}" + (f" -- {detail}" if detail else ""))
    if cond: PASS += 1
    else:    FAIL += 1

def sec(title): print(f"\n\033[0;36m-- {title} --\033[0m")

def test_sqli():
    sec("SQL Injection")
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER, username TEXT, password TEXT)")
    conn.execute("INSERT INTO users VALUES (1,'admin','secret')")
    for payload, desc in [
        ("' OR '1'='1' --",        "auth bypass"),
        ("admin'--",                "skip password"),
        ("'; DROP TABLE users;--",  "destructive"),
        ("' UNION SELECT 1,2,3--",  "union extract"),
        ("1 OR 1=1",                "boolean bypass"),
    ]:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=? AND password=?", (payload, ""))
        test(f"SQLi blocked ({desc})", cur.fetchone() is None)
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=? AND password=?", ("admin","secret"))
    test("Legitimate login works", cur.fetchone() is not None)

def test_xss():
    sec("XSS Output Encoding")
    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        '"><script>alert(1)</script>',
        "<iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
    ]
    for p in payloads:
        enc = html.escape(p, quote=True)
        test(f"HTML encoded: {p[:35]!r}", "<" not in enc)
    n1 = base64.b64encode(secrets.token_bytes(16)).decode()
    n2 = base64.b64encode(secrets.token_bytes(16)).decode()
    test("CSP nonce unique", n1 != n2)
    test("CSP nonce length >= 16", len(n1) >= 16)
    attack = "<script>document.location='evil.com'</script>"
    safe   = html.escape(attack, quote=True)
    test("Stored XSS neutralised", "<script>" not in safe and "&lt;script&gt;" in safe)

def test_csrf():
    sec("CSRF Token Validation")
    KEY = secrets.token_bytes(32)
    def gen(sid):
        ts  = str(int(time.time()))
        sig = hmac.new(KEY, f"{sid}:{ts}".encode(), hashlib.sha256).hexdigest()
        return f"{ts}:{sig}"
    def verify(sid, tok, max_age=3600):
        if not tok or not isinstance(tok, str) or ":" not in tok: return False
        try:
            ts_str, sig = tok.split(":", 1)
            if time.time() - int(ts_str) > max_age: return False
        except Exception: return False
        exp = hmac.new(KEY, f"{sid}:{ts_str}".encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, exp)
    sid = secrets.token_hex(16)
    tok = gen(sid)
    test("Valid token accepted",        verify(sid, tok))
    test("Wrong session rejected",      not verify("other", tok))
    test("Tampered token rejected",     not verify(sid, tok + "x"))
    test("Empty token rejected",        not verify(sid, ""))
    test("None token rejected",         not verify(sid, None))
    test("Expired token rejected",      not verify(sid, "0:" + secrets.token_hex(32)))
    cookie = secrets.token_hex(32)
    test("Double-submit match OK",      hmac.compare_digest(cookie, cookie))
    test("Double-submit mismatch fail", not hmac.compare_digest(cookie, "attacker"))

def test_ssrf():
    sec("SSRF Allowlist Enforcement")
    ALLOWED = {"api.github.com", "api.stripe.com", "hooks.slack.com"}
    def safe(url):
        try:
            p = urllib.parse.urlparse(url)
            if p.scheme not in {"https"}: return False, f"scheme {p.scheme!r}"
            h = p.hostname or ""
            if h not in ALLOWED: return False, f"{h!r} not allowlisted"
            for pat in ["@","0x","0177",".nip.io","localhost","sslip.io"]:
                if pat in url.lower(): return False, f"bypass {pat!r}"
            return True, "ok"
        except Exception as e: return False, str(e)
    blocked = [
        ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
        ("https://10.0.0.1/admin",                   "RFC1918 A"),
        ("https://192.168.1.1/",                     "RFC1918 C"),
        ("https://172.16.0.1/",                      "RFC1918 B"),
        ("https://127.0.0.1/",                       "Loopback"),
        ("file:///etc/passwd",                        "File scheme"),
        ("gopher://127.0.0.1:6379/",                 "Gopher scheme"),
        ("https://evil.com/",                         "Not allowlisted"),
        ("https://169.254.169.254.nip.io/",          "DNS alias"),
        ("http://evil.com@api.github.com/",           "@ bypass"),
    ]
    for url, desc in blocked:
        ok, reason = safe(url)
        test(f"SSRF blocked: {desc}", not ok, reason if not ok else "NOT BLOCKED")
    ok, _ = safe("https://api.github.com/repos")
    test("Allowlisted URL accepted", ok)

def test_jwt():
    sec("JWT Validation")
    SECRET = b"test-secret-cse804"
    ISSUER = "https://auth.example.com"
    AUDIENCE = "api.example.com"
    used_jtis: set = set()
    def make(iss=ISSUER, aud=AUDIENCE, exp_delta=3600, alg="RS256"):
        now = int(time.time())
        b64 = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
        h = b64({"alg": alg, "typ": "JWT"})
        p = b64({"iss":iss,"aud":aud,"sub":"alice","exp":now+exp_delta,
                 "iat":now,"jti":secrets.token_urlsafe(8)})
        sig = base64.urlsafe_b64encode(
            hmac.new(SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        return f"{h}.{p}.{sig}"
    def validate(token):
        try:
            parts = token.split(".")
            if len(parts) != 3: return False, "not 3 parts"
            pad = lambda x: x + "="*(4-len(x)%4)
            hdr = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
            pay = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
            if hdr.get("alg") not in {"RS256","ES256"}: return False, f"bad alg"
            if time.time() > pay.get("exp",0):          return False, "expired"
            if pay.get("iss") != ISSUER:                return False, "wrong iss"
            aud = pay.get("aud",""); al = aud if isinstance(aud,list) else [aud]
            if AUDIENCE not in al:                      return False, "wrong aud"
            jti = pay.get("jti","")
            if jti in used_jtis:                        return False, "replay"
            used_jtis.add(jti)
            si  = f"{parts[0]}.{parts[1]}".encode()
            exp = base64.urlsafe_b64encode(
                hmac.new(SECRET,si,hashlib.sha256).digest()).rstrip(b"=").decode()
            if not hmac.compare_digest(parts[2], exp):  return False, "bad sig"
            return True, "ok"
        except Exception as e: return False, str(e)
    ok,_ = validate(make()); test("Valid JWT accepted", ok)
    ok,r = validate(make(exp_delta=-100)); test("Expired JWT rejected", not ok and "expired" in r)
    ok,_ = validate(make(aud="other"));    test("Wrong audience rejected", not ok)
    ok,_ = validate(make(iss="https://evil.com")); test("Wrong issuer rejected", not ok)
    ok,_ = validate(make(alg="none"));     test("alg:none rejected", not ok)
    tok2 = make(); validate(tok2); ok,r=validate(tok2)
    test("JWT replay rejected", not ok and "replay" in r)
    verifier  = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    pkce_ok = lambda v,c: hmac.compare_digest(base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode(), c)
    test("PKCE verifier matches",     pkce_ok(verifier, challenge))
    test("PKCE wrong verifier fails", not pkce_ok("wrong", challenge))
    test("PKCE length >= 43",         len(verifier) >= 43)

def test_auth():
    sec("Password Hashing & Session Security")
    def hash_pw(pw):
        s = secrets.token_bytes(32)
        k = hashlib.pbkdf2_hmac("sha256", pw.encode(), s, 600_000, 32)
        return f"pbkdf2_sha256${s.hex()}${k.hex()}"
    def verify_pw(pw, stored):
        try:
            _, sh, hh = stored.split("$")
            k = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(sh), 600_000, 32)
            return hmac.compare_digest(k, bytes.fromhex(hh))
        except Exception: return False
    h = hash_pw("correct-horse-battery!")
    test("Password verifies correctly",  verify_pw("correct-horse-battery!", h))
    test("Wrong password rejected",      not verify_pw("wrong", h))
    test("Hash is unique (salted)",      h != hash_pw("correct-horse-battery!"))
    test("Hash includes alg prefix",     h.startswith("pbkdf2_sha256$"))
    tok = secrets.token_urlsafe(32)
    test("Session token URL-safe",       all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in tok))
    test("Session token length >= 32",   len(tok) >= 32)
    cookie = {"HttpOnly":True,"Secure":True,"SameSite":"Strict","Max-Age":3600}
    test("Cookie HttpOnly=True",         cookie["HttpOnly"] is True)
    test("Cookie Secure=True",           cookie["Secure"]   is True)
    test("Cookie SameSite=Strict",       cookie["SameSite"] == "Strict")
    capacity = 5; tokens = float(capacity); last_t = time.time()
    def consume():
        nonlocal tokens, last_t
        now = time.time(); tokens=min(capacity, tokens+(now-last_t)); last_t=now
        if tokens>=1: tokens-=1; return True
        return False
    results = [consume() for _ in range(8)]
    test("Rate limiter allows burst (5)", all(results[:5]))
    test("Rate limiter blocks excess",    not results[5])
    fails=0
    def rec(): nonlocal fails; fails+=1; return fails>=5
    for _ in range(4): rec()
    test("Not locked before threshold",  fails < 5)
    test("Locked after 5 failures",      rec())

def main():
    print("\n" + "="*65)
    print("  CSE804 -- Web & App Layer Security -- Complete Test Suite")
    print("  SQLi / XSS / CSRF / SSRF / JWT / Auth")
    print("="*65)
    test_sqli(); test_xss(); test_csrf(); test_ssrf(); test_jwt(); test_auth()
    total = PASS + FAIL
    pct   = int(PASS/total*100) if total else 0
    print("\n" + "="*65)
    print(f"  Results: \033[0;32m{PASS} passed\033[0m / \033[0;31m{FAIL} failed\033[0m / {total} total ({pct}%)")
    print("="*65 + "\n")
    sys.exit(0 if FAIL == 0 else 1)

if __name__ == "__main__": main()
