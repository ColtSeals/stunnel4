#!/usr/bin/env bash
set -euo pipefail

# ===========================================
# IntranetBridge - VPS Stunnel Installer
# - TLS:443 (entrada do PC empresa)
# - SOCKS local VPS:1080 (entrada da sua casa)
#
# Uso rápido:
#   curl -fsSL https://SEU_RAW/install.sh | sudo bash
#
# Massa (sem perguntas):
#   curl -fsSL https://SEU_RAW/install.sh | sudo \
#     LISTEN_TLS_PORT=443 LOCAL_SOCKS_PORT=1080 CERT_MODE=selfsigned bash
# ===========================================

# --------- Defaults (podem ser sobrescritos via env) ----------
LISTEN_TLS_PORT="${LISTEN_TLS_PORT:-443}"         # Porta TLS no servidor (VPS) que o PC empresa conecta
LOCAL_SOCKS_PORT="${LOCAL_SOCKS_PORT:-1080}"      # Porta SOCKS na VPS (entrada da sua casa)
CERT_MODE="${CERT_MODE:-selfsigned}"              # selfsigned | letsencrypt (placeholder)
CERT_PATH="${CERT_PATH:-/etc/stunnel/stunnel.pem}"
CONF_PATH="${CONF_PATH:-/etc/stunnel/stunnel.conf}"
LOG_PATH="${LOG_PATH:-/var/log/stunnel4/stunnel.log}"
SERVICE_NAME="${SERVICE_NAME:-stunnel4}"

NONINTERACTIVE="${NONINTERACTIVE:-0}"             # 1 = não pergunta nada
FORCE="${FORCE:-0}"                               # 1 = força reescrever config/cert
# -------------------------------------------------------------

RED="$(printf '\033[31m')"; GREEN="$(printf '\033[32m')"; YELLOW="$(printf '\033[33m')"; BLUE="$(printf '\033[34m')"; NC="$(printf '\033[0m')"

say()   { echo -e "${BLUE}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[x]${NC} $*"; exit 1; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    fail "Rode como root (use sudo). Ex: curl ... | sudo bash"
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

is_debian_like() {
  [[ -f /etc/debian_version ]] || [[ -f /etc/lsb-release ]] || grep -qiE 'debian|ubuntu' /etc/os-release 2>/dev/null
}

prompt() {
  local var="$1" text="$2" def="$3"
  if [[ "$NONINTERACTIVE" == "1" ]]; then
    printf -v "$var" "%s" "${!var:-$def}"
    return 0
  fi
  read -r -p "$text [$def]: " val
  if [[ -z "${val:-}" ]]; then val="$def"; fi
  printf -v "$var" "%s" "$val"
}

confirm() {
  local text="$1"
  if [[ "$NONINTERACTIVE" == "1" ]]; then
    return 0
  fi
  read -r -p "$text (y/N): " ans
  [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]]
}

preflight() {
  need_root
  if ! is_debian_like; then
    warn "Esse installer foi feito pra Debian/Ubuntu. Pode funcionar em outros, mas não garanto."
  fi
}

collect_inputs() {
  say "Modo interativo (intuitivo). Você pode automatizar via env vars também."
  prompt LISTEN_TLS_PORT "Porta TLS na VPS (PC da empresa conecta aqui)" "$LISTEN_TLS_PORT"
  prompt LOCAL_SOCKS_PORT "Porta SOCKS na VPS (sua casa conecta aqui)" "$LOCAL_SOCKS_PORT"
  prompt CERT_MODE "Certificado (selfsigned | letsencrypt) [letsencrypt = placeholder]" "$CERT_MODE"

  if [[ "$CERT_MODE" != "selfsigned" && "$CERT_MODE" != "letsencrypt" ]]; then
    warn "CERT_MODE inválido. Usando selfsigned."
    CERT_MODE="selfsigned"
  fi

  ok "Resumo:"
  echo "    - TLS (VPS): ${LISTEN_TLS_PORT}"
  echo "    - SOCKS local (VPS): ${LOCAL_SOCKS_PORT}"
  echo "    - Cert: ${CERT_MODE}"
  echo
  if [[ "$NONINTERACTIVE" != "1" ]]; then
    confirm "Continuar com essas configurações?" || fail "Cancelado pelo usuário."
  fi
}

install_packages() {
  say "Instalando pacotes..."
  if have_cmd apt; then
    apt update
    apt install -y stunnel4 openssl net-tools curl
    ok "Pacotes instalados."
  else
    fail "apt não encontrado. Instale stunnel4 e openssl manualmente."
  fi
}

setup_dirs() {
  say "Criando diretórios..."
  mkdir -p /etc/stunnel /var/run/stunnel4
  chown stunnel4:stunnel4 /var/run/stunnel4 2>/dev/null || true
  mkdir -p "$(dirname "$LOG_PATH")"
  touch "$LOG_PATH"
  ok "Diretórios ok."
}

generate_cert_selfsigned() {
  say "Gerando certificado self-signed (se necessário)..."
  if [[ -f "$CERT_PATH" && "$FORCE" != "1" ]]; then
    ok "Cert já existe em $CERT_PATH (use FORCE=1 para recriar)."
    return 0
  fi
  openssl req -new -x509 -days 3650 -nodes \
    -out "$CERT_PATH" -keyout "$CERT_PATH" \
    -subj "/C=BR/ST=SP/L=SP/O=IntranetBridge/CN=bridge.local"
  chmod 600 "$CERT_PATH"
  ok "Cert criado em $CERT_PATH"
}

generate_cert_letsencrypt_placeholder() {
  warn "CERT_MODE=letsencrypt ainda é placeholder neste install.sh."
  warn "Se você quiser a versão 'nível banco' com domínio+SNI+LE, eu te passo o install.sh 2.0."
  warn "Por enquanto, usando selfsigned."
  CERT_MODE="selfsigned"
  generate_cert_selfsigned
}

write_config() {
  say "Escrevendo config do stunnel..."
  if [[ -f "$CONF_PATH" && "$FORCE" != "1" ]]; then
    warn "Config já existe em $CONF_PATH (use FORCE=1 para sobrescrever)."
  else
    cat > "$CONF_PATH" <<EOF
; =========================
; STUNNEL SERVER (VPS)
; TLS:${LISTEN_TLS_PORT}  --->  LOCAL:${LOCAL_SOCKS_PORT}
; =========================

foreground = no
pid = /var/run/stunnel4/stunnel.pid
setuid = stunnel4
setgid = stunnel4

cert = ${CERT_PATH}

debug = 4
output = ${LOG_PATH}

options = NO_SSLv2
options = NO_SSLv3

[intranet_bridge]
accept = ${LISTEN_TLS_PORT}
connect = 127.0.0.1:${LOCAL_SOCKS_PORT}
EOF
    ok "Config escrita em $CONF_PATH"
  fi
}

enable_stunnel_default() {
  say "Habilitando stunnel4 em /etc/default/stunnel4..."
  if [[ -f /etc/default/stunnel4 ]]; then
    sed -i 's/^ENABLED=.*/ENABLED=1/' /etc/default/stunnel4 || true
    grep -q '^ENABLED=' /etc/default/stunnel4 || echo 'ENABLED=1' >> /etc/default/stunnel4
  else
    warn "/etc/default/stunnel4 não existe. Ok em algumas distros, mas vou seguir."
  fi
  ok "stunnel habilitado."
}

systemd_override_restart() {
  say "Criando override systemd (Restart=always)..."
  mkdir -p "/etc/systemd/system/${SERVICE_NAME}.service.d"
  cat > "/etc/systemd/system/${SERVICE_NAME}.service.d/override.conf" <<'EOF'
[Service]
Restart=always
RestartSec=3
EOF
  systemctl daemon-reload
  ok "Override aplicado."
}

start_service() {
  say "Iniciando serviço..."
  systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
  systemctl restart "$SERVICE_NAME"
  systemctl status "$SERVICE_NAME" --no-pager || true
  ok "Serviço reiniciado."
}

ufw_open_port() {
  if have_cmd ufw; then
    say "UFW detectado: liberando porta ${LISTEN_TLS_PORT}/tcp..."
    ufw allow "${LISTEN_TLS_PORT}/tcp" >/dev/null 2>&1 || true
    ok "UFW ok."
  else
    warn "UFW não encontrado. Se você usa firewall, libere ${LISTEN_TLS_PORT}/tcp manualmente."
  fi
}

healthcheck() {
  say "Healthcheck..."
  if have_cmd ss; then
    ss -lntp | grep -q ":${LISTEN_TLS_PORT}" && ok "VPS escutando TLS em :${LISTEN_TLS_PORT}" || warn "Não vi :${LISTEN_TLS_PORT} no ss (pode ser timing/log)."
  elif have_cmd netstat; then
    netstat -lntp | grep -q ":${LISTEN_TLS_PORT}" && ok "VPS escutando TLS em :${LISTEN_TLS_PORT}" || warn "Não vi :${LISTEN_TLS_PORT} no netstat."
  fi

  ok "Log (últimas linhas):"
  tail -n 30 "$LOG_PATH" || true
}

print_finish() {
  echo
  ok "INSTALAÇÃO FINALIZADA ✅"
  echo
  echo "🎯 O que ficou ativo na VPS:"
  echo "   - Stunnel SERVER em TLS :${LISTEN_TLS_PORT}"
  echo "   - Bridge local para SOCKS em 127.0.0.1:${LOCAL_SOCKS_PORT}"
  echo
  echo "🧪 Testes úteis:"
  echo "   - Ver porta:"
  echo "       ss -lntp | grep ':${LISTEN_TLS_PORT}'"
  echo "   - Ver log:"
  echo "       tail -n 100 ${LOG_PATH}"
  echo
  echo "🧠 Lembrete do fluxo:"
  echo "   PC Empresa (stunnel client) -> VPS:${LISTEN_TLS_PORT} -> VPS local:${LOCAL_SOCKS_PORT} (entrada da sua casa)"
  echo
  echo "🔁 Instalação em massa (exemplo):"
  echo "   ssh root@IP 'curl -fsSL https://SEU_RAW/install.sh | sudo NONINTERACTIVE=1 LISTEN_TLS_PORT=443 LOCAL_SOCKS_PORT=1080 bash'"
  echo
}

main() {
  preflight

  # Se env vars foram passadas, pode setar NONINTERACTIVE=1.
  collect_inputs

  install_packages
  setup_dirs

  if [[ "$CERT_MODE" == "selfsigned" ]]; then
    generate_cert_selfsigned
  else
    generate_cert_letsencrypt_placeholder
  fi

  write_config
  enable_stunnel_default
  systemd_override_restart
  start_service
  ufw_open_port
  healthcheck
  print_finish
}

main "$@"
