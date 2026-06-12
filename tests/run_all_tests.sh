#!/usr/bin/env bash
# Run all tests — CSE804 Web & App Layer Security
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

echo ""
echo "===================================================="
echo "  CSE804 -- Web & App Security -- Test Runner"
echo "===================================================="

# Python tests
echo ""
echo "-- Python Test Suite --"
python3 tests/test_all.py

# Syntax check
echo ""
echo "-- Python Syntax Check --"
find src/ -name "*.py" | while read f; do
    python3 -m py_compile "$f" && echo "  OK: $f" || echo "  ERROR: $f"
done

# Smoke test demos
echo ""
echo "-- Smoke Tests --"
for demo in src/sqli/sqli_demo.py src/xss/xss_demo.py src/csrf/csrf_demo.py \
            src/ssrf/ssrf_demo.py src/xxe/xxe_idor_demo.py src/api/api_security.py \
            src/auth/secure_auth.py; do
    if timeout 15 python3 "$demo" > /dev/null 2>&1; then
        echo "  OK: $demo"
    else
        echo "  FAIL: $demo"
    fi
done

echo ""
echo "All checks complete."
