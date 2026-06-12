#!/usr/bin/env python3
"""XXE + IDOR Demo — Attacks and defences. Run: python3 xxe_idor_demo.py"""
import secrets

USERS = {
    "usr_001": {"name":"Alice","email":"alice@example.com","ssn":"123-45-6789","role":"user"},
    "usr_002": {"name":"Bob",  "email":"bob@example.com",  "ssn":"987-65-4321","role":"user"},
}
ORDERS = {
    "ord_100": {"user_id":"usr_001","item":"Widget A","amount":9.99},
    "ord_101": {"user_id":"usr_002","item":"Gadget X","amount":99.99},
}

_opaque = {}; _reverse = {}

def opaque_id(internal):
    if internal not in _opaque:
        tok = secrets.token_urlsafe(12)
        _opaque[internal] = tok; _reverse[tok] = internal
    return _opaque[internal]

def resolve(tok): return _reverse.get(tok)

def vuln_get_order(order_id, _user):
    return ORDERS.get(order_id)  # no ownership check!

def safe_get_order(opaque_order_id, requesting_user_id):
    internal = resolve(opaque_order_id)
    if not internal: return {"error": "Not found"}
    order = ORDERS.get(internal)
    if not order: return {"error": "Not found"}
    if order["user_id"] != requesting_user_id: return {"error": "Not found"}
    return {"id": opaque_order_id, "item": order["item"], "amount": order["amount"]}

def main():
    print("=" * 60)
    print("  XXE + IDOR DEMO — CSE804")
    print("=" * 60)

    print("""
── XXE Attack Payloads ──
  <?xml version="1.0"?>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <order><item>&xxe;</item></order>
  -> Server reads /etc/passwd and returns it in response!

  Other targets: http://169.254.169.254/ (SSRF via XXE)
  DoS:  <!ENTITY lol "lol">  <!ENTITY lol9 "&lol8;&lol8;">  (Billion Laughs)

── XXE Defence ──
  import defusedxml.ElementTree as ET
  tree = ET.parse(untrusted_xml)  # blocks all XXE automatically

  Or manually: resolve_entities=False, no_network=True, load_dtd=False
  Better: use JSON instead of XML where possible.
""")

    print("── IDOR Attack ──")
    alice_opaque = opaque_id("ord_100")
    print(f"  Alice\'s opaque order ID: {alice_opaque}")
    print(f"  Bob tries Alice\'s raw ID (VULNERABLE): {vuln_get_order('ord_100', 'usr_002')}")
    print(f"  Bob tries Alice\'s opaque ID (SAFE):    {safe_get_order(alice_opaque, 'usr_002')}")
    print(f"  Alice accesses her own order (SAFE):     {safe_get_order(alice_opaque, 'usr_001')}")
    print(f"  Bob guesses raw sequential ID:           {safe_get_order('ord_100', 'usr_002')}")

    print("""
IDOR Defence Summary:
  1. Object-level authorization: server checks ownership on EVERY request
  2. Opaque IDs: UUIDs/random tokens — attacker cannot enumerate ord_1, ord_2
  3. Same error for not-found and unauthorized (no existence leak)
  4. Log all access control failures
""")

if __name__ == "__main__": main()
