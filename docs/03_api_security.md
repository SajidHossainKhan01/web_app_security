# API Security Reference — CSE804

## JWT Validation Checklist
```python
payload = jwt.decode(token, public_key,
    algorithms=["RS256"],        # NEVER: ["none"], ["HS256"] if expecting RS256
    audience="api.example.com",  # verify aud — token for service A ≠ service B
    issuer="https://auth.example.com",
    options={"require": ["exp","iat","jti","iss","aud"]}
)
if is_jti_used(payload["jti"]): raise ValueError("Replay attack")
```

## JWT Attack Reference
| Attack | Description | Defence |
|---|---|---|
| `alg:none` | Forged token, no signature | Whitelist algorithms |
| RS256→HS256 | Public key as HMAC secret | Explicit algorithm list |
| Missing `exp` | Token valid forever | Require exp claim |
| Missing `aud` | Wrong service accepts token | Always verify aud |
| Replay | Same token reused | Store and check jti |

## OAuth 2.0 + PKCE
```python
# Client side
verifier  = base64url(random_bytes(32))
challenge = base64url(sha256(verifier))
# Send challenge to auth server

# After receiving code, exchange:
# POST /token: code + code_verifier
# Server verifies: sha256(verifier) == stored_challenge
```
PKCE prevents auth code interception — attacker who intercepts code
cannot use it without the verifier (which never leaves the client).

## Rate Limiting
```
HTTP/1.1 429 Too Many Requests
Retry-After: 60
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
```

## API Security Checklist
- [ ] All endpoints require authentication
- [ ] JWT: alg, exp, aud, iss, jti all verified
- [ ] OAuth: PKCE for public clients
- [ ] JSON schema validation on all request bodies
- [ ] additionalProperties: false (blocks mass assignment)
- [ ] Rate limit on auth endpoints (5/min)
- [ ] HTTPS only (HSTS preload)
- [ ] No sensitive data in URL params (appears in logs)
