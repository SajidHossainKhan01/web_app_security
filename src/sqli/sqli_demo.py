#!/usr/bin/env python3
"""SQLi Demo — All 4 types + parameterised query defence. Run: python3 sqli_demo.py"""
import sqlite3

def setup():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE users (id INTEGER, username TEXT, password TEXT, role TEXT)")
    c.execute("INSERT INTO users VALUES (1,'admin','secret','admin')")
    c.execute("INSERT INTO users VALUES (2,'alice','pass123','user')")
    c.commit(); return c

def vuln_login(conn, username, password):
    q = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    print(f"  SQL: {q}")
    try:
        return conn.execute(q).fetchone()
    except (sqlite3.OperationalError, sqlite3.ProgrammingError) as e:
        return None

def safe_login(conn, username, password):
    return conn.execute("SELECT * FROM users WHERE username=? AND password=?",
                        (username, password)).fetchone()

def main():
    print("=" * 60)
    print("  SQL INJECTION DEMO — CSE804")
    print("=" * 60)
    db = setup()

    attacks = [
        ("' OR '1'='1' --", "",  "Auth bypass — returns first user"),
        ("admin'--",         "",  "Skip password for admin"),
        ("'; DROP TABLE users;--", "", "Bobby Tables (destructive)"),
        ("' UNION SELECT 1,username,password,role FROM users--","","UNION data extract"),
    ]

    print("\n── VULNERABLE (string concatenation) ──")
    for u, p, desc in attacks:
        print(f"\n  Attack: {desc}")
        r = vuln_login(db, u, p)
        if r: print(f"  ⚠  BREACHED — logged in as: {r[1]} (role={r[3]})")
        else: print("  Login failed / SQL error")

    print("\n── SAFE (parameterised queries) ──")
    for u, p, desc in attacks:
        r = safe_login(db, u, p)
        status = "✓ Blocked" if r is None else f"⚠ Bypassed: {r[1]}"
        print(f"  {desc[:40]}: {status}")

    print("""
Defence Summary:
  PRIMARY: cursor.execute("SELECT * FROM users WHERE user=? AND pass=?", (u, p))
  NEVER:   f"SELECT ... WHERE user='{u}'"
  ALSO: Least-privilege DB accounts, WAF, error handling (never expose SQL errors)
""")

if __name__ == "__main__": main()
