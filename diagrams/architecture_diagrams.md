# Architecture Diagrams — CSE804 Web & App Layer Security

## 1 — Defence-in-Depth Stack
```
INTERNET (Attackers)
        |
        v  HTTPS TLS 1.3
[Edge WAF / CDN]          DDoS scrubbing, bot detection, BGP anycast
        |
        v  HTTPS
[Nginx + ModSecurity]     TLS termination, security headers, WAF (OWASP CRS),
                          rate limiting, header stripping, mTLS to backend
        |
        v  HTTP/mTLS (internal)
[Application Tier]        Input validation, RBAC, CSP, CSRF tokens,
                          parameterised queries, session security
        |
        v  TLS (internal)
[Data Tier]               AES-256 at rest, least-privilege DB accounts,
                          audit logs
```

## 2 — SQLi: Vulnerable vs Safe
```
VULNERABLE:
  code:  f"SELECT * FROM users WHERE user='{username}'"
  input: username = "' OR '1'='1' --"
  SQL:   SELECT * FROM users WHERE user='' OR '1'='1' --'
                                         ^^^^^^^^^^^^
                                         always TRUE -> all users returned
  result: AUTH BYPASS

SAFE (parameterised):
  code:  cursor.execute("SELECT * FROM users WHERE user=?", (username,))
  input: username = "' OR '1'='1' --"
  SQL:   SELECT * FROM users WHERE user=?
                                         ^
                                   treated as literal data, not SQL code
  result: 0 rows -> login fails correctly
```

## 3 — XSS Types
```
STORED (Persistent) — highest impact
  Attacker stores <script>... in database
  -> Executes for EVERY visitor, no interaction needed
  Defence: output encoding at render time

REFLECTED — requires victim to click link
  /search?q=<script>alert(document.cookie)</script>
  -> Reflected in one response page
  Defence: output encoding + CSP

DOM-BASED — never reaches server
  page.html#<img onerror=alert(1)>
  -> URL fragment not sent to server -> WAF cannot see it
  Defence: textContent (not innerHTML) + CSP + Trusted Types
```

## 4 — CSRF Attack and Defence
```
ATTACK:
  evil.com -> <form action="https://bank.com/transfer">
              <input name="to" value="attacker">
              <body onload="document.forms[0].submit()">
  Browser includes victim's session cookie -> transfer succeeds!

DEFENCE 1 — CSRF Token:
  <input type="hidden" name="csrf_token" value="abc123">
  Attacker cannot read abc123 (Same-Origin Policy)

DEFENCE 2 — SameSite=Strict:
  Set-Cookie: session=x; SameSite=Strict
  Cross-site form submission -> NO cookie sent -> server rejects
```

## 5 — SSRF Attack
```
POST /api/fetch {"url": "http://169.254.169.254/latest/meta-data/iam/..."}
  Server makes request -> IAM credentials returned to attacker!

Other targets: Redis (127.0.0.1:6379), internal APIs, MongoDB (:27017)

Bypass techniques:
  http://0x7f000001/           hex localhost
  http://169.254.169.254.nip.io/  DNS alias
  http://attacker@169.254.169.254/ @ trick

Defence: allowlist + post-DNS-resolution IP check
  1. Scheme must be https
  2. Hostname must be in allowlist
  3. Resolve hostname -> verify IP not RFC 1918 / link-local
  4. Block bypass patterns (@, hex, octal, .nip.io)
```

## 6 — OAuth 2.0 + PKCE
```
[SPA Client]                [Auth Server]          [API]
     |                           |                    |
     | 1. verifier=random()      |                    |
     |    challenge=SHA256(v)    |                    |
     | GET /authorize?           |                    |
     |   code_challenge=... ---> |                    |
     |                           | 2. user logs in    |
     | <-- code=AUTH_CODE ------ |                    |
     | POST /token               |                    |
     |   code + verifier ------> |                    |
     |                           | 3. SHA256(v)==c?   |
     | <-- access_token -------- |  YES -> issue tok  |
     | GET /api/data             |                    |
     |   Authorization: Bearer ---------------------->|
```

## 7 — JWT Structure
```
header.payload.signature

header:  {"alg":"RS256","typ":"JWT"}
payload: {"iss":"https://auth.example.com",
          "aud":"api.example.com",
          "sub":"alice",
          "exp":1716901200,
          "iat":1716897600,
          "jti":"unique-replay-prevention-id"}
sig:     RSASHA256(base64url(header) + "." + base64url(payload), private_key)

Validation (ALL must pass):
  alg   -> whitelist only (never "none", never HS256 if expecting RS256)
  exp   -> must be in future
  iss   -> must match expected issuer
  aud   -> must include this service
  jti   -> must not have been seen before (replay prevention)
  sig   -> must verify with issuer public key
```
