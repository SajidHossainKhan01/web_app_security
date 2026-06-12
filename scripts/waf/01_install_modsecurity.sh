#!/usr/bin/env bash
# Install ModSecurity + OWASP CRS — CSE804
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root."; exit 1; }
CRS_VERSION="4.3.0"; CRS_DIR="/usr/share/modsecurity-crs"
echo "Installing ModSecurity + OWASP CRS v${CRS_VERSION}..."
apt-get update -qq
apt-get install -y nginx libnginx-mod-http-modsecurity libmodsecurity3 git curl
mkdir -p "$CRS_DIR"
curl -sL "https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz" \
    | tar xz --strip-components=1 -C "$CRS_DIR"
cp "$CRS_DIR/crs-setup.conf.example" "$CRS_DIR/crs-setup.conf"
mkdir -p /etc/nginx/modsecurity
cat > /etc/nginx/modsecurity/main.conf << CONF
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecAuditEngine RelevantOnly
SecAuditLog /var/log/modsec_audit.log
SecAction "id:900001,phase:1,nolog,pass,setvar:tx.paranoia_level=2"
SecAction "id:900110,phase:1,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=5"
Include $CRS_DIR/crs-setup.conf
Include $CRS_DIR/rules/*.conf
CONF
echo "modsecurity on; modsecurity_rules_file /etc/nginx/modsecurity/main.conf;" \
    > /etc/nginx/conf.d/modsecurity_enable.conf
nginx -t && nginx -s reload
echo ""
echo "ModSecurity installed in DETECTION mode."
echo "Test: curl -i 'http://localhost/?id=1+UNION+SELECT+1,2,3--'"
echo "Logs: tail -f /var/log/modsec_audit.log"
echo "Switch to blocking after tuning: sed -i s/DetectionOnly/On/ /etc/nginx/modsecurity/main.conf"
