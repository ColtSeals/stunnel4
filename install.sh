#!/usr/bin/env bash
set -euo pipefail

echo -e "\033[1;34m>>> PMESP ULTIMATE - INSTALL (TANK MODE)\033[0m"

REPO_RAW="${REPO_RAW:-https://raw.githubusercontent.com/ColtSeals/stunnel4/main}"

apt-get update -y || true
apt-get install -y \
  jq python3 python3-pip wget curl msmtp msmtp-mta ca-certificates bc \
  screen nano net-tools lsof cron zip unzip openssl

# API deps
pip3 install fastapi uvicorn "passlib[bcrypt]" --break-system-packages 2>/dev/null \
  || pip3 install fastapi uvicorn "passlib[bcrypt]"

# Baixa manager
wget -qO /usr/local/bin/pmesp "$REPO_RAW/manager.sh"
chmod +x /usr/local/bin/pmesp

# Baixa API
mkdir -p /etc/pmesp
wget -qO /etc/pmesp/api_pmesp.py "$REPO_RAW/api_pmesp.py"

# Serviço API (auto-start)
cat > /etc/systemd/system/pmesp-api.service <<'EOF'
[Unit]
Description=API PMESP
After=network.target

[Service]
User=root
WorkingDirectory=/etc/pmesp
ExecStart=/usr/local/bin/uvicorn api_pmesp:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable pmesp-api.service
systemctl restart pmesp-api.service

echo -e "\033[1;32m>>> TUDO PRONTO! Digite 'pmesp' para abrir.\033[0m"
echo -e "\033[1;33m>>> API: http://IP_DA_VPS:8000 (veja regras/segurança no api_pmesp.py)\033[0m"
