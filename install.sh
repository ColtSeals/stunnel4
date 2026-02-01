#!/usr/bin/env bash
set -e

echo -e "\033[1;34m>>> PMESP ULTIMATE - INSTALL (V8.6 FULL)\033[0m"

REPO_RAW="${REPO_RAW:-https://raw.githubusercontent.com/ColtSeals/stunnel4/main}"

apt-get update -y || true
apt-get install -y \
  bash jq curl wget gzip ca-certificates openssl \
  net-tools lsof cron screen nano zip unzip bc \
  squid sslh stunnel4 \
  python3 python3-pip \
  msmtp msmtp-mta

python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
python3 -m pip install fastapi uvicorn "passlib[bcrypt]" >/dev/null 2>&1 || true

# Baixa manager
wget -qO /usr/local/bin/pmesp "$REPO_RAW/manager.sh"
chmod +x /usr/local/bin/pmesp
sed -i 's/\r$//' /usr/local/bin/pmesp || true

# Baixa API
mkdir -p /etc/pmesp
wget -qO /etc/pmesp/api_pmesp.py "$REPO_RAW/api_pmesp.py"
sed -i 's/\r$//' /etc/pmesp/api_pmesp.py || true

# Banco e lock
touch /etc/pmesp_users.json /etc/pmesp_tickets.json
chmod 666 /etc/pmesp_users.json /etc/pmesp_tickets.json
mkdir -p /var/lock
touch /var/lock/pmesp_db.lock
chmod 666 /var/lock/pmesp_db.lock

# Serviço API
cat > /etc/systemd/system/pmesp-api.service <<'EOF'
[Unit]
Description=PMESP API (FastAPI)
After=network.target

[Service]
User=root
WorkingDirectory=/etc/pmesp
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 -m uvicorn api_pmesp:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable pmesp-api.service >/dev/null 2>&1 || true
systemctl restart pmesp-api.service || true

echo -e "\033[1;32m>>> OK! Digite: pmesp\033[0m"
echo -e "\033[1;33m>>> API: http://IP_DA_VPS:8000/docs\033[0m"
