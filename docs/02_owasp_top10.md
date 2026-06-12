# OWASP Top 10 2021 Reference — CSE804

| # | Category | Primary Defence | Code |
|---|---|---|---|
| A01 | Broken Access Control | RBAC, ownership checks, deny-by-default | `src/xxe/` |
| A02 | Cryptographic Failures | TLS 1.2+, bcrypt/Argon2id, AES-GCM | `src/auth/`, `scripts/tls/` |
| A03 | Injection (SQLi + XSS) | Parameterised queries, output encoding, CSP | `src/sqli/`, `src/xss/` |
| A04 | Insecure Design | Threat modelling, secure SDLC | `docs/` |
| A05 | Security Misconfiguration | Hardening baselines, no defaults | `configs/` |
| A06 | Vulnerable Components | pip-audit, npm audit, Dependabot | `requirements.txt` |
| A07 | Auth Failures | bcrypt, account lockout, MFA, session security | `src/auth/` |
| A08 | Software Integrity | SRI, code signing, SLSA | — |
| A09 | Logging/Monitoring Failures | SIEM, WAF logs, structured logging | `examples/` |
| A10 | SSRF | Allowlist, RFC 1918 blocking, post-DNS IP check | `src/ssrf/` |

## A01: Broken Access Control
```python
# WRONG — no ownership check
def get_order(order_id): return db.get(order_id)

# RIGHT — object-level authorization
def get_order(order_id, user_id):
    order = db.get(order_id)
    if order.user_id != user_id:
        raise PermissionError("Not found")  # same error as not-found
    return order
```

## A03: SQL Injection
```python
# WRONG — string concatenation
query = f"SELECT * FROM users WHERE user='{username}'"
# RIGHT — parameterised
cursor.execute("SELECT * FROM users WHERE user=%s", (username,))
```

## A03: XSS
```python
# WRONG — raw template render
return f"<p>{user_input}</p>"
# RIGHT — output encoding + CSP
from markupsafe import escape
return f"<p>{escape(user_input)}</p>"
```

## A10: SSRF
```python
BLOCKED = [ip_network(n) for n in ["169.254.0.0/16","10.0.0.0/8","127.0.0.0/8"]]
ALLOWED = {"api.github.com", "api.stripe.com"}

def safe_fetch(url):
    p = urlparse(url)
    if p.scheme != "https": raise ValueError("HTTPS only")
    if p.hostname not in ALLOWED: raise ValueError("Not in allowlist")
    ip = gethostbyname(p.hostname)  # resolve then check
    if any(ip_address(ip) in net for net in BLOCKED): raise ValueError("Private IP")
```
