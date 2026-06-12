#!/usr/bin/env bash
# WAF Log Analyzer — CSE804
# Usage: ./waf_log_analyzer.sh [--log /path] [--demo]
set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
AUDIT_LOG="${AUDIT_LOG:-/var/log/modsec_audit.log}"
DEMO=false
for a in "$@"; do [[ "$a"=="--demo" ]] && DEMO=true; [[ "$a"=="--log" ]] && { shift; AUDIT_LOG="$1"; }; done

if $DEMO; then
    AUDIT_LOG=$(mktemp)
    TS=$(date '+%d/%b/%Y:%H:%M:%S +0000')
    cat > "$AUDIT_LOG" << DEMOEOF
--a1-A--
[$TS] 203.0.113.99 10.0.1.5
--a1-B--
POST /login HTTP/1.1
User-Agent: sqlmap/1.7.2
--a1-H--
Message: Warning. [id "942100"] [msg "SQL Injection Attack"] [severity "CRITICAL"]
Anomaly Scores: incoming: 9, threshold: 5; outbound: 0, threshold: 4
--a1-Z--
--a2-A--
[$TS] 198.51.100.77 10.0.1.5
--a2-B--
GET /search?q=<script>alert(1)</script> HTTP/1.1
--a2-H--
Message: Warning. [id "941100"] [msg "XSS Attack Detected"] [severity "CRITICAL"]
Anomaly Scores: incoming: 5, threshold: 5; outbound: 0, threshold: 4
--a2-Z--
--a3-A--
[$TS] 203.0.113.99 10.0.1.5
--a3-B--
GET /api/users/../../etc/passwd HTTP/1.1
User-Agent: Nikto/2.1.6
--a3-H--
Message: Warning. [id "930110"] [msg "Path Traversal"] [severity "ERROR"]
Anomaly Scores: incoming: 4, threshold: 5; outbound: 0, threshold: 4
--a3-Z--
DEMOEOF
fi

[[ ! -f "$AUDIT_LOG" ]] && { echo "Log not found: $AUDIT_LOG (use --demo)"; exit 1; }

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  WAF Log Analyzer — CSE804                               ║"
printf "║  Log: %-51s ║\n" "$(basename "$AUDIT_LOG")"
echo "╚══════════════════════════════════════════════════════════╝"

echo -e "\n${CYAN}── Top Triggered Rules ──${NC}"
grep -oP 'id "\K[0-9]+' "$AUDIT_LOG" 2>/dev/null | sort | uniq -c | sort -rn | head 10 | \
    while read -r cnt rid; do
        case "$rid" in
            942100) d="SQL Injection" ;; 941100) d="XSS" ;; 930110) d="Path Traversal" ;;
            913100) d="Scanner/Bot"  ;; 934110) d="SSRF" ;; *) d="OWASP CRS Rule" ;;
        esac
        printf "  Rule %-8s  %4d hits  %s\n" "$rid" "$cnt" "$d"
    done

echo -e "\n${CYAN}── Top Source IPs ──${NC}"
grep -A1 '^--.*-A--$' "$AUDIT_LOG" 2>/dev/null | grep -v '^--' | grep -v '^$' | \
    awk '{print $1}' | sort | uniq -c | sort -rn | head 10 | \
    while read -r cnt ip; do printf "  %-20s  %4d requests\n" "$ip" "$cnt"; done

echo -e "\n${CYAN}── Anomaly Score Distribution ──${NC}"
declare -A B=( ["0 (clean)"]=0 ["1-4 (low)"]=0 ["5+ (blocked)"]=0 )
while IFS= read -r line; do
    s=$(echo "$line" | grep -oP 'incoming: \K\d+' || echo 0)
    if   [[ "$s" -eq 0 ]]; then B["0 (clean)"]=$((${B["0 (clean)"]}+1))
    elif [[ "$s" -le 4 ]]; then B["1-4 (low)"]=$((${B["1-4 (low)"]}+1))
    else                        B["5+ (blocked)"]=$((${B["5+ (blocked)"]}+1))
    fi
done < <(grep "Anomaly Scores:" "$AUDIT_LOG" 2>/dev/null || true)
for bucket in "0 (clean)" "1-4 (low)" "5+ (blocked)"; do
    printf "  Score %-15s %4d\n" "$bucket:" "${B[$bucket]}"
done

echo ""
HIGH=$(grep "Anomaly Scores:" "$AUDIT_LOG" 2>/dev/null | grep -oP 'incoming: \K\d+' | awk '$1>=5' | wc -l || echo 0)
SCAN=$(grep -ic "sqlmap\|nikto\|nmap\|masscan\|dirbuster" "$AUDIT_LOG" 2>/dev/null || echo 0)
[[ "$HIGH" -gt 10 ]] && echo -e "  ${RED}ALERT: $HIGH blocked requests — possible attack${NC}"
[[ "$SCAN" -gt 0  ]] && echo -e "  ${YELLOW}WARN:  Known scanner detected ($SCAN hits)${NC}"
[[ "$HIGH" -le 10 && "$SCAN" -eq 0 ]] && echo -e "  ${GREEN}OK: Normal WAF activity${NC}"
echo ""
