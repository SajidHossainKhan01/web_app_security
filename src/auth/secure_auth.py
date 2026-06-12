#!/usr/bin/env python3
"""Secure Auth — Password hashing + session management + lockout. Run: python3 secure_auth.py"""
import hashlib, hmac, secrets, time

def hash_password(pw):
    salt = secrets.token_bytes(32)
    k    = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 600_000, 32)
    return f"pbkdf2_sha256${salt.hex()}${k.hex()}"

def verify_password(pw, stored):
    try:
        _, salt_hex, hash_hex = stored.split("$")
        k = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt_hex), 600_000, 32)
        return hmac.compare_digest(k, bytes.fromhex(hash_hex))
    except Exception:
        return False

def create_session(user_id):
    token = secrets.token_urlsafe(32)
    cookie = {"value":token,"HttpOnly":True,"Secure":True,"SameSite":"Strict","Max-Age":3600}
    return token, cookie

def main():
    print("="*60); print("  SECURE AUTH DEMO — CSE804"); print("="*60)

    print("\n── Password Hashing (PBKDF2-SHA256, 600k iterations) ──")
    for pw in ["password123","correct-horse-battery-staple-42!"]:
        h = hash_password(pw)
        print(f"  Password: {pw!r}")
        print(f"  Hash:     {h[:55]}...")
        print(f"  Verify:   {verify_password(pw, h)}")
        print(f"  Wrong:    {verify_password('wrong_pw', h)}")
        print(f"  Unique:   {h != hash_password(pw)}")
        print()

    print("── Session Cookie Attributes ──")
    tok, cookie = create_session("alice")
    print(f"  Token: {tok[:30]}...")
    for k,v in cookie.items(): print(f"  {k}: {v}")

    print("""
Production: use bcrypt (rounds=12) or argon2-cffi
  import bcrypt
  hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
  ok     = bcrypt.checkpw(password.encode(), hashed)

Account Lockout:
  Track failed attempts per username
  Lock after 5 failures for 15 minutes
  Always use constant-time comparison (hmac.compare_digest)
  Always hash even for non-existent users (prevent timing oracle)
""")

if __name__ == "__main__": main()
