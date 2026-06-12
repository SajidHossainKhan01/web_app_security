# Secure Coding Practices — CSE804

## Input Validation — Allowlist
```python
import re

def validate_email(email: str) -> bool:
    if not isinstance(email, str) or len(email) > 254: return False
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email))

def validate_uuid(val: str) -> bool:
    UUID_RE = r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    return bool(re.match(UUID_RE, val, re.IGNORECASE))
```
**Never blacklist — always allowlist.** Attackers bypass blacklists with encoding.

## Context-Aware Output Encoding
```python
import html, json, urllib.parse

html.escape(value, quote=True)          # HTML body / attributes
json.dumps(value)[1:-1]                 # JavaScript string
urllib.parse.quote(value, safe='')      # URL parameter
```
Using HTML encoding in a JS context still allows XSS.

## Error Handling
```python
import uuid, logging
logger = logging.getLogger(__name__)

def handler(request):
    try:
        return process(request)
    except ValidationError as e:
        return {"error": str(e)}, 400     # safe to return
    except Exception as e:
        ref = str(uuid.uuid4())
        logger.error(f"ref={ref}", exc_info=True)
        return {"error": "ref: " + ref}, 500  # never expose stack trace
```

## Password Hashing
```python
import bcrypt
# Store
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
# Verify
ok = bcrypt.checkpw(password.encode(), hashed)

# NEVER: md5, sha1, sha256 alone — these are NOT password hashing functions
```

## Secrets Management
```python
import os
# WRONG
DB_PASSWORD = "hardcoded_secret"

# RIGHT
DB_PASSWORD = os.environ["DB_PASSWORD"]  # fails loudly if missing

# BEST: AWS Secrets Manager, HashiCorp Vault
```

## Dependency Scanning
```bash
pip install pip-audit
pip-audit -r requirements.txt    # check CVEs
npm audit                        # Node.js
```

## Security Checklist
- [ ] All user input validated against allowlist
- [ ] Output encoded in correct context (HTML/JS/URL)
- [ ] Parameterised queries — no string concatenation
- [ ] bcrypt/Argon2id for passwords (never MD5/SHA1)
- [ ] Session: 256-bit token, HttpOnly, Secure, SameSite=Strict
- [ ] Error messages never expose internals
- [ ] Secrets in env vars or secrets manager
- [ ] pip-audit / npm audit in CI pipeline
