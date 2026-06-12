#!/usr/bin/env bash
# WAF Tuning Workflow — CSE804
AUDIT_LOG="${AUDIT_LOG:-/var/log/modsec_audit.log}"
RED="\033[0;31m"; GREEN="\033[0;32m"; CYAN="\033[0;36m"; NC="\033[0m"

echo ""
echo "WAF Tuning Workflow:"
echo "  1. DetectionOnly mode for 72h"
echo "  2. Analyse false positives"
echo "  3. Create exclusions for legitimate traffic"
echo "  4. Switch to blocking mode"
echo ""

[[ ! -f "$AUDIT_LOG" ]] && { echo "Log not found: $AUDIT_LOG"; exit 0; }

echo -e "${CYAN}Top Triggered Rules:${NC}"
grep -oP "id \"\K[0-9]+" "$AUDIT_LOG" 2>/dev/null | sort | uniq -c | sort -rn | head 10

echo -e "\n${CYAN}Top Source IPs:${NC}"
grep -A1 "^--.*-A--$" "$AUDIT_LOG" 2>/dev/null | grep -v "^--" | awk "{print \$1}" | sort | uniq -c | sort -rn | head 10

echo -e "\n${CYAN}Anomaly Scores:${NC}"
grep "Anomaly Scores:" "$AUDIT_LOG" 2>/dev/null | grep -oP "incoming: \K\d+" | sort -n | uniq -c

echo ""
echo "To switch to blocking:"
echo "  sed -i s/DetectionOnly/On/ /etc/nginx/modsecurity/main.conf && nginx -s reload"
