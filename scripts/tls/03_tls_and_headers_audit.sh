#!/usr/bin/env bash
# TLS Audit + Security Headers Check — CSE804
# Usage: ./03_tls_and_headers_audit.sh example.com [port]
#        ./03_tls_and_headers_audit.sh --headers https://example.com
set -euo pipefail
RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"; CYAN="\033[0;36m"; NC="\033[0m"
PASS=0; FAIL=0

pass() { echo -e "  ${GREEN}[+]${NC} $*"; ((PASS++)); }
fail() { echo -e "  ${RED}[-]${NC} $*"; ((FAIL++)); }
warn() { echo -e "  ${YELLOW}[!]${NC} $*"; }
h()    { echo -e "\n${CYAN}-- $* --${NC}"; }

command -v openssl >/dev/null || { echo "openssl required"; exit 1; }

tls_audit() {
    local HOST="$1" PORT="${2:-443}"
    echo ""; echo "TLS Audit: $HOST:$PORT"; echo "=========================="

    h "Deprecated TLS (should be REJECTED)"
    for v in "SSL3.0:-ssl3" "TLS1.0:-tls1" "TLS1.1:-tls1_1"; do
        NAME="${v%%:*}"; FLAG="${v##*:}"
        R=$(echo Q | timeout 5 openssl s_client -connect "$HOST:$PORT" $FLAG 2>&1 || true)
        echo "$R" | grep -q "CONNECTED" && fail "$NAME accepted (PCI-DSS violation)" || pass "$NAME rejected"
    done

    h "Required TLS (should be ACCEPTED)"
    for v in "TLS1.2:-tls1_2" "TLS1.3:-tls1_3"; do
        NAME="${v%%:*}"; FLAG="${v##*:}"
        R=$(echo Q | timeout 5 openssl s_client -connect "$HOST:$PORT" $FLAG 2>&1 || true)
        echo "$R" | grep -q "CONNECTED" && pass "$NAME accepted" || fail "$NAME not supported"
    done

    h "Certificate"
    FULL=$(echo Q | timeout 10 openssl s_client -connect "$HOST:$PORT" -tls1_2 2>&1 || true)
    VERIFY=$(echo "$FULL" | grep "Verify return code:" | cut -d: -f2-)
    CIPHER=$(echo "$FULL" | grep "Cipher    :" | awk "{print \$NF}")
    PROTO=$(echo "$FULL"  | grep "Protocol  :" | awk "{print \$NF}")
    [[ -n "$PROTO"  ]] && warn "Protocol: $PROTO"
    [[ -n "$CIPHER" ]] && warn "Cipher:   $CIPHER"
    [[ "$VERIFY" =~ "0 (ok)" ]] && pass "Certificate chain verified" || fail "Cert verify failed: $VERIFY"

    h "Summary"
    echo -e "  Passed: ${GREEN}$PASS${NC} | Failed: ${RED}$FAIL${NC}"
}

headers_check() {
    local URL="$1"
    echo ""; echo "Security Headers: $URL"; echo "=========================="
    command -v curl >/dev/null || { echo "curl required"; exit 1; }
    HEADERS=$(curl -sk -D - -o /dev/null "$URL" 2>/dev/null || true)
    [[ -z "$HEADERS" ]] && { fail "Could not connect"; return; }
    h "Required Headers"
    for hdr in "Strict-Transport-Security" "Content-Security-Policy" "X-Content-Type-Options" "X-Frame-Options" "Referrer-Policy"; do
        VAL=$(echo "$HEADERS" | grep -i "^${hdr}:" | head -1 | cut -d: -f2- | tr -d "\r")
        [[ -n "$VAL" ]] && pass "$hdr: ${VAL:0:60}" || fail "$hdr MISSING"
    done
    h "Information Disclosure"
    SERVER=$(echo "$HEADERS" | grep -i "^Server:" | head -1)
    POWERED=$(echo "$HEADERS" | grep -i "^X-Powered-By:" | head -1)
    echo "$SERVER" | grep -qiE "nginx/[0-9]|apache/[0-9]|IIS/[0-9]" && fail "Version disclosed: $SERVER" || pass "Server version hidden"
    [[ -n "$POWERED" ]] && fail "X-Powered-By: $POWERED" || pass "X-Powered-By not set"
    h "Summary"
    echo -e "  Passed: ${GREEN}$PASS${NC} | Failed: ${RED}$FAIL${NC}"
}

case "${1:-}" in
    --headers) headers_check "${2:-https://example.com}" ;;
    "")        echo "Usage: $0 <host> [port]  OR  $0 --headers <URL>"; exit 1 ;;
    *)         tls_audit "$1" "${2:-443}" ;;
esac
