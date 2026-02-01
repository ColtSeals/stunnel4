#!/usr/bin/env bash
# ==================================================================
#   PMESP MANAGER ULTIMATE V9.2 - TÁTICO + TUNNEL ARSENAL (LOCKED)
#   - Corrige pipefail + grep
#   - File Locking Bash (flock)
#   - NDJSON: /etc/pmesp_users.json (1 JSON por linha)
# ==================================================================
set -euo pipefail

# --- ARQUIVOS DE DADOS ---
DB_PMESP="/etc/pmesp_users.json"          # NDJSON: 1 JSON por linha
DB_CHAMADOS="/etc/pmesp_tickets.json"     # NDJSON
CONFIG_SMTP="/etc/msmtprc"
LOG_MONITOR="/var/log/pmesp_monitor.log"

# LOCK GLOBAL (Bash + Python usam o mesmo)
LOCK_FILE="/var/lock/pmesp_db.lock"

# Tunnel
STUNNEL_CONF="/etc/stunnel/stunnel.conf"
STUNNEL_CERT="/etc/stunnel/stunnel.pem"
STUNNEL_LOG="/var/log/stunnel4/stunnel.log"

CHISEL_BIN="/usr/local/bin/chisel"
CHISEL_SERVICE="/etc/systemd/system/chisel.service"
CHISEL_LOG="/var/log/chisel.log"

# --- CORES ---
R="\033[1;31m"; G="\033[1;32m"; Y="\033[1;33m"; B="\033[1;34m"
P="\033[1;35m"; C="\033[1;36m"; W="\033[1;37m"; NC="\033[0m"
LINE_H="${C}═${NC}"

# --- HELPERS ---
have(){ command -v "$1" >/dev/null 2>&1; }
pause(){ read -r -p "Pressione Enter para voltar..." _; }

msg_ok(){   echo -e "${G}[✓]${NC} $*"; }
msg_warn(){ echo -e "${Y}[!]${NC} $*"; }
msg_fail(){ echo -e "${R}[X]${NC} $*"; }

need_root(){
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo -e "${R}Este script precisa rodar como root.${NC}"
    echo -e "Use: ${Y}sudo pmesp${NC}"
    exit 1
  fi
}

ensure_files(){
  mkdir -p /var/lock /var/log /etc/pmesp 2>/dev/null || true
  [ ! -f "$DB_PMESP" ] && touch "$DB_PMESP" && chmod 666 "$DB_PMESP"
  [ ! -f "$DB_CHAMADOS" ] && touch "$DB_CHAMADOS" && chmod 666 "$DB_CHAMADOS"
  [ ! -f "$LOG_MONITOR" ] && touch "$LOG_MONITOR" && chmod 644 "$LOG_MONITOR"
  [ ! -f "$LOCK_FILE" ] && :> "$LOCK_FILE" && chmod 666 "$LOCK_FILE"
}

# Execução protegida por lock (exclusivo)
with_lock(){
  (
    flock -x 200
    "$@"
  ) 200>"$LOCK_FILE"
}

# Leitura protegida por lock (compartilhado)
with_lock_read(){
  (
    flock -s 200
    "$@"
  ) 200>"$LOCK_FILE"
}

autocura_db_users_inner(){
  # mantém apenas JSON válido, unique_by(usuario), preserva NDJSON
  if have jq && [ -s "$DB_PMESP" ]; then
    local tmp_clean tmp2
    tmp_clean="$(mktemp)"
    while IFS= read -r line; do
      [[ -z "${line// }" ]] && continue
      echo "$line" | jq -e . >/dev/null 2>&1 && echo "$line" >> "$tmp_clean"
    done < "$DB_PMESP"

    tmp2="$(mktemp)"
    jq -s 'map(select(type=="object" and has("usuario"))) | unique_by(.usuario) | .[]' -c \
      "$tmp_clean" > "$tmp2" 2>/dev/null || true

    [ -s "$tmp2" ] && mv "$tmp2" "$DB_PMESP" || true
    rm -f "$tmp_clean" 2>/dev/null || true
  fi
}

autocura_db_users(){
  with_lock autocura_db_users_inner
}

get_total_users(){
  if ! have jq; then echo "0"; return; fi
  with_lock_read bash -c "jq -s 'length' '$DB_PMESP' 2>/dev/null || echo 0"
}

get_public_ip(){
  if have curl; then
    curl -fsS --max-time 2 https://ipv4.icanhazip.com 2>/dev/null | tr -d '\n' || echo "N/A"
  elif have wget; then
    wget -qO- ipv4.icanhazip.com 2>/dev/null | tr -d '\n' || echo "N/A"
  else
    echo "N/A"
  fi
}

cabecalho(){
  clear
  local _tuser _ons _ip
  _tuser="$(get_total_users)"
  # >>> CORREÇÃO DEFINITIVA: sem grep + pipefail
  _ons="$(who | awk '$1!="root"{c++} END{print c+0}')"
  _ip="$(get_public_ip)"

  echo -e "${C}╭${LINE_H}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C}╮${NC}"
  echo -e "${C}┃${P}            PMESP MANAGER V9.2 - TÁTICO INTEGRADO           ${C}┃${NC}"
  echo -e "${C}┣${LINE_H}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫${NC}"
  echo -e "${C}┃ ${Y}TOTAL: ${W}${_tuser} ${Y}| ONLINE: ${G}${_ons} ${Y}| IP: ${G}${_ip}${C}    ┃${NC}"
  echo -e "${C}┗${LINE_H}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
}

barra(){ echo -e "${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

selecionar_usuario_lista(){
  cabecalho
  echo -e "${C}>>> SELECIONE O USUÁRIO${NC}"
  barra

  if ! have jq; then
    echo -e "${R}jq não instalado.${NC} Use a opção 12 para instalar dependências."
    pause; return 1
  fi

  local users_list
  mapfile -t users_list < <(with_lock_read bash -c "jq -r 'select(type==\"object\" and has(\"usuario\")) | .usuario' '$DB_PMESP' 2>/dev/null || true")

  if [ "${#users_list[@]}" -eq 0 ]; then
    echo -e "${R}Banco vazio/ inválido.${NC}"
    pause; return 1
  fi

  local count=1
  for u in "${users_list[@]}"; do
    printf "${G}[%02d]${NC} %s\n" "$count" "$u"
    ((count++))
  done

  echo ""; barra
  read -r -p "Digite o NÚMERO do usuário: " selection
  if [[ ! "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt "${#users_list[@]}" ]; then
    echo -e "\n${R}ERRO: Seleção inválida!${NC}"
    sleep 1
    return 1
  fi

  USER_ALVO="${users_list[$((selection-1))]}"
  echo -e "${Y}Usuário selecionado: ${W}$USER_ALVO${NC}"
  sleep 1
  return 0
}

criar_usuario_inner(){
  cabecalho
  echo -e "${G}>>> NOVO CADASTRO DE POLICIAL${NC}"

  if ! have jq; then
    echo -e "${R}jq não instalado.${NC} Use a opção 12 para instalar dependências."
    pause; return
  fi

  read -r -p "Matrícula (RE): " matricula
  read -r -p "Email: " email
  read -r -p "Login: " usuario
  [ -z "${usuario:-}" ] && return

  # checa no DB
  if jq -e "select(.usuario==\"$usuario\")" "$DB_PMESP" >/dev/null 2>&1; then
    echo -e "\n${R}ERRO: O usuário '$usuario' já existe!${NC}"
    sleep 2; return
  fi

  # checa no linux
  if id "$usuario" >/dev/null 2>&1; then
    echo -e "\n${R}ERRO: Usuário já existe no Linux!${NC}"
    sleep 2; return
  fi

  read -r -p "Senha Provisória: " senha
  read -r -p "Validade (Dias): " dias
  read -r -p "Limite de Telas: " limite

  [[ "$dias" =~ ^[0-9]+$ ]] || { echo -e "${R}Dias inválidos.${NC}"; sleep 1; return; }
  [[ "$limite" =~ ^[0-9]+$ ]] || { echo -e "${R}Limite inválido.${NC}"; sleep 1; return; }

  useradd -M -s /bin/false "$usuario"
  echo "$usuario:$senha" | chpasswd
  local data_exp
  data_exp="$(date -d "+$dias days" +"%Y-%m-%d")"
  chage -E "$data_exp" "$usuario" || true

  local item
  item="$(jq -c -n --arg u "$usuario" --arg s "$senha" --arg d "$dias" --arg l "$limite" \
      --arg m "$matricula" --arg e "$email" --arg h "PENDENTE" --arg ex "$data_exp" \
      '{usuario:$u, senha:$s, dias:$d, limite:$l, matricula:$m, email:$e, hwid:$h, expiracao:$ex}')"

  echo "$item" >> "$DB_PMESP"
  autocura_db_users_inner

  echo -e "\n${G}Usuário ${W}$usuario${G} criado com sucesso!${NC}"
  sleep 2
}

criar_usuario(){
  with_lock criar_usuario_inner
}

listar_usuarios(){
  cabecalho
  echo -e "${C}>>> LISTA DE USUÁRIOS CADASTRADOS${NC}"
  barra
  printf "${W}%-12s | %-10s | %-11s | %-4s | %-10s${NC}\n" "USUÁRIO" "RE" "EXPIRA" "LIM" "HWID"
  barra

  if ! have jq; then
    echo -e "${R}jq não instalado.${NC}"
    pause; return
  fi

  with_lock_read bash -c "jq -c '.' '$DB_PMESP' 2>/dev/null" | while read -r line; do
    u=$(echo "$line" | jq -r .usuario)
    m=$(echo "$line" | jq -r .matricula)
    ex=$(echo "$line" | jq -r .expiracao)
    l=$(echo "$line" | jq -r .limite)
    h=$(echo "$line" | jq -r .hwid)
    printf "${Y}%-12s${NC} | %-10s | %-11s | %-4s | %-10s\n" "$u" "$m" "$ex" "$l" "${h:0:10}"
  done || true

  echo ""
  pause
}

remover_usuario_inner(){
  selecionar_usuario_lista || return

  echo -e "${R}ATENÇÃO: Você vai remover o usuário ${W}$USER_ALVO${R}.${NC}"
  read -r -p "Tem certeza? (s/n): " confirm
  [[ "$confirm" != "s" && "$confirm" != "S" ]] && return

  id "$USER_ALVO" >/dev/null 2>&1 && userdel -f "$USER_ALVO" || true

  if have jq; then
    local tmp
    tmp="$(mktemp)"
    jq -c "select(.usuario != \"$USER_ALVO\")" "$DB_PMESP" > "$tmp" 2>/dev/null || true
    mv "$tmp" "$DB_PMESP"
  fi

  msg_ok "Usuário removido com sucesso!"
  sleep 2
}

remover_usuario_lista(){
  with_lock remover_usuario_inner
}

alterar_validade_inner(){
  selecionar_usuario_lista || return

  cabecalho
  echo -e "${C}>>> ALTERANDO VALIDADE: ${Y}$USER_ALVO${NC}"
  read -r -p "Novos dias de validade: " novos_dias

  if [[ ! "$novos_dias" =~ ^[0-9]+$ ]]; then
    echo -e "${R}Número inválido!${NC}"; sleep 1; return
  fi

  if id "$USER_ALVO" >/dev/null 2>&1; then
    local nova_data tmp
    nova_data="$(date -d "+$novos_dias days" +"%Y-%m-%d")"
    chage -E "$nova_data" "$USER_ALVO" || true

    if have jq; then
      tmp="$(mktemp)"
      jq -c "if .usuario == \"$USER_ALVO\" then .expiracao = \"$nova_data\" | .dias = \"$novos_dias\" else . end" \
        "$DB_PMESP" > "$tmp"
      mv "$tmp" "$DB_PMESP"
    fi

    msg_ok "Sucesso! Nova data: $nova_data"
  else
    msg_fail "Usuário não encontrado no Linux."
  fi
  sleep 2
}

alterar_validade_lista(){
  with_lock alterar_validade_inner
}

alterar_limite_inner(){
  selecionar_usuario_lista || return

  cabecalho
  echo -e "${C}>>> ALTERANDO LIMITE: ${Y}$USER_ALVO${NC}"
  if ! have jq; then
    echo -e "${R}jq não instalado.${NC}"
    pause; return
  fi

  local limite_atual
  limite_atual="$(jq -r "select(.usuario==\"$USER_ALVO\") | .limite" "$DB_PMESP" 2>/dev/null || echo "N/A")"
  echo -e "Limite Atual: ${W}$limite_atual${NC}"

  read -r -p "Novo limite de conexões: " novo_limite
  if [[ ! "$novo_limite" =~ ^[0-9]+$ ]]; then
    echo -e "${R}Número inválido!${NC}"; sleep 1; return
  fi

  local tmp
  tmp="$(mktemp)"
  jq -c "if .usuario == \"$USER_ALVO\" then .limite = \"$novo_limite\" else . end" "$DB_PMESP" > "$tmp"
  mv "$tmp" "$DB_PMESP"

  msg_ok "Limite atualizado para: $novo_limite"
  sleep 2
}

alterar_limite_lista(){
  with_lock alterar_limite_inner
}

usuarios_vencidos(){
  cabecalho
  echo -e "${R}>>> USUÁRIOS VENCIDOS${NC}"
  barra

  if ! have jq; then
    echo -e "${R}jq não instalado.${NC}"
    pause; return
  fi

  local today
  today="$(date +%s)"

  with_lock_read bash -c "jq -c '.' '$DB_PMESP' 2>/dev/null" | while read -r line; do
    u=$(echo "$line" | jq -r .usuario)
    ex=$(echo "$line" | jq -r .expiracao)
    exp_sec=$(date -d "$ex" +%s 2>/dev/null || echo 0)
    if [ "$exp_sec" -lt "$today" ]; then
      echo -e "${R}$u - EXPIRADO EM $ex${NC}"
    fi
  done || true

  pause
}

mostrar_usuarios_online(){
  tput civis; trap 'tput cnorm; return' SIGINT
  while true; do
    cabecalho
    echo -e "${C}>>> MONITORAMENTO ONLINE (CTRL+C Sair)${NC}"
    barra

    if ! have jq; then
      echo -e "${R}jq não instalado.${NC}"
      sleep 2; continue
    fi

    with_lock_read bash -c "jq -s 'unique_by(.usuario) | .[]' -c '$DB_PMESP' 2>/dev/null" | while read -r line; do
      u=$(echo "$line" | jq -r .usuario)
      l=$(echo "$line" | jq -r .limite)

      # >>> CORREÇÃO DEFINITIVA: sem grep + pipefail
      s="$(who | awk -v u="$u" '$1==u{c++} END{print c+0}')"

      if [ "$s" -gt 0 ]; then
        printf "${Y}%-15s${NC} | ON: %-3s | LIM: %-3s\n" "$u" "$s" "$l"
      fi
    done || true

    sleep 2
  done
}

atualizar_hwid_inner(){
  selecionar_usuario_lista || return
  read -r -p "Novo HWID: " h

  if ! have jq; then
    echo -e "${R}jq não instalado.${NC}"
    pause; return
  fi

  local tmp
  tmp="$(mktemp)"
  jq -c "if .usuario == \"$USER_ALVO\" then .hwid = \"$h\" else . end" "$DB_PMESP" > "$tmp"
  mv "$tmp" "$DB_PMESP"

  msg_ok "HWID atualizado!"
  sleep 2
}

atualizar_hwid(){
  with_lock atualizar_hwid_inner
}

novo_chamado_inner(){
  cabecalho
  if ! have jq; then
    echo -e "${R}jq não instalado.${NC}"
    pause; return
  fi

  local ID u p
  ID=$((1000 + RANDOM % 8999))
  read -r -p "Login: " u
  read -r -p "Problema: " p

  jq -n --arg i "$ID" --arg u "$u" --arg p "$p" --arg s "ABERTO" --arg d "$(date)" \
    '{id:$i, usuario:$u, problema:$p, status:$s, data:$d}' -c >> "$DB_CHAMADOS"

  msg_ok "Chamado #$ID criado."
  sleep 2
}

novo_chamado(){
  with_lock novo_chamado_inner
}

gerenciar_chamados(){
  cabecalho
  if [ -s "$DB_CHAMADOS" ] && have jq; then
    jq -r '"ID: \(.id) | USER: \(.usuario) | STATUS: \(.status) | DATA: \(.data)"' "$DB_CHAMADOS" 2>/dev/null || true
  else
    echo -e "${Y}Sem chamados (ou jq não instalado).${NC}"
  fi
  pause
}

configurar_smtp(){
  cabecalho
  read -r -p "Gmail: " e
  read -r -p "Senha App: " s
  cat <<EOF > "$CONFIG_SMTP"
defaults
auth on
tls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
account gmail
host smtp.gmail.com
port 587
from $e
user $e
password $s
account default : gmail
EOF
  chmod 600 "$CONFIG_SMTP"
  msg_ok "SMTP Configurado!"
  sleep 2
}

install_deps(){
  cabecalho
  apt update || true
  apt install -y jq msmtp msmtp-mta net-tools wget curl openssl ca-certificates bc screen nano lsof cron zip unzip sslh squid stunnel4
  msg_ok "Dependências Instaladas!"
  sleep 2
}

install_squid(){
  cabecalho
  apt install -y squid >/dev/null
  cat > /etc/squid/squid.conf <<'EOF'
http_port 3128
acl all src 0.0.0.0/0
http_access allow all
EOF
  systemctl restart squid
  msg_ok "Squid Ativo na 3128!"
  sleep 2
}

install_sslh(){
  cabecalho
  apt install -y sslh >/dev/null
  echo 'DAEMON_OPTS="--user sslh --listen 0.0.0.0:443 --ssh 127.0.0.1:22"' > /etc/default/sslh
  systemctl restart sslh
  msg_ok "SSLH Ativo na 443!"
  sleep 2
}

configurar_cron_monitor(){
  cabecalho
  local p
  p="$(readlink -f "$0")"
  (crontab -l 2>/dev/null | grep -v "pmesp --cron-monitor" || true; echo "*/1 * * * * /bin/bash $p --cron-monitor >/dev/null 2>&1") | crontab -
  msg_ok "Monitoramento Cron Ativado!"
  sleep 2
}

# ==================================================================
# TUNNEL ARSENAL (CHISEL/STUNNEL) - VPS SIDE
# ==================================================================

download_chisel_latest(){
  apt update || true
  apt install -y curl ca-certificates gzip

  local arch asset api url tmpdir
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) asset="linux_amd64" ;;
    aarch64|arm64) asset="linux_arm64" ;;
    armv7l|armhf) asset="linux_armv7" ;;
    *) msg_fail "Arch não suportada: $arch"; return 1 ;;
  esac

  api="https://api.github.com/repos/jpillora/chisel/releases/latest"
  url="$(curl -fsSL "$api" | sed -n 's/.*"browser_download_url": "\(.*'"$asset"'.*\.gz\)".*/\1/p' | head -n1)"
  [ -n "${url:-}" ] || { msg_fail "Falha ao localizar release do chisel."; return 1; }

  tmpdir="$(mktemp -d)"
  curl -fsSL "$url" -o "$tmpdir/chisel.gz"
  gzip -d "$tmpdir/chisel.gz"
  chmod +x "$tmpdir/chisel"
  mv "$tmpdir/chisel" "$CHISEL_BIN"
  rm -rf "$tmpdir"
  msg_ok "Chisel instalado em $CHISEL_BIN"
}

install_chisel_server(){
  cabecalho
  echo -e "${G}>>> CHISEL SERVER (VPS)${NC}"
  barra
  read -r -p "Porta do Chisel (default 443): " ch_port
  read -r -p "Token/Auth (ex: PMESP@2026): " ch_auth
  ch_port="${ch_port:-443}"
  ch_auth="${ch_auth:-PMESP@2026}"

  download_chisel_latest || { pause; return; }
  mkdir -p /var/log
  touch "$CHISEL_LOG" || true

  cat > "$CHISEL_SERVICE" <<EOF
[Unit]
Description=Chisel Server (PMESP)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${CHISEL_BIN} server --port ${ch_port} --auth '${ch_auth}' --reverse
Restart=always
RestartSec=2
StandardOutput=append:${CHISEL_LOG}
StandardError=append:${CHISEL_LOG}

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable chisel >/dev/null 2>&1 || true
  systemctl restart chisel

  msg_ok "CHISEL OK - Porta: ${ch_port} | Auth: ${ch_auth}"
  msg_ok "Log: tail -n 80 ${CHISEL_LOG}"
  sleep 2
}

status_chisel(){
  cabecalho
  echo -e "${C}>>> STATUS CHISEL${NC}"
  barra
  systemctl status chisel --no-pager || true
  echo ""
  ss -lntp | egrep ':443|:1080|:8080' || true
  echo ""
  tail -n 60 "$CHISEL_LOG" 2>/dev/null || true
  pause
}

remove_chisel(){
  cabecalho
  echo -e "${R}>>> REMOVER CHISEL${NC}"
  barra
  read -r -p "Confirmar? (s/N): " c
  [[ "${c:-}" =~ ^[sS]$ ]] || return
  systemctl stop chisel 2>/dev/null || true
  systemctl disable chisel 2>/dev/null || true
  rm -f "$CHISEL_SERVICE" 2>/dev/null || true
  systemctl daemon-reload || true
  rm -f "$CHISEL_BIN" 2>/dev/null || true
  msg_ok "Chisel removido."
  sleep 2
}

install_stunnel_server(){
  cabecalho
  echo -e "${G}>>> STUNNEL SERVER (VPS)${NC}"
  barra
  read -r -p "TLS listen (default 443): " tls_port
  read -r -p "Forward para HOST (default 127.0.0.1): " fhost
  read -r -p "Forward para PORTA (default 8443): " fport
  tls_port="${tls_port:-443}"
  fhost="${fhost:-127.0.0.1}"
  fport="${fport:-8443}"

  apt update || true
  apt install -y stunnel4 openssl ca-certificates net-tools

  mkdir -p /etc/stunnel /var/run/stunnel4 /var/log/stunnel4
  touch "$STUNNEL_LOG" || true
  chown stunnel4:stunnel4 /var/run/stunnel4 2>/dev/null || true

  if [[ ! -f "$STUNNEL_CERT" ]]; then
    openssl req -new -x509 -days 3650 -nodes \
      -out "$STUNNEL_CERT" -keyout "$STUNNEL_CERT" \
      -subj "/C=BR/ST=SP/L=SP/O=PMESP/CN=pmesp.local" >/dev/null 2>&1
    chmod 600 "$STUNNEL_CERT"
  fi

  cat > "$STUNNEL_CONF" <<EOF
foreground = no
pid = /var/run/stunnel4/stunnel.pid
setuid = stunnel4
setgid = stunnel4
cert = ${STUNNEL_CERT}
debug = 4
output = ${STUNNEL_LOG}

[tcp_forward]
accept = ${tls_port}
connect = ${fhost}:${fport}
EOF

  if [[ -f /etc/default/stunnel4 ]]; then
    sed -i 's/^ENABLED=.*/ENABLED=1/' /etc/default/stunnel4 || true
    grep -q '^ENABLED=' /etc/default/stunnel4 || echo 'ENABLED=1' >> /etc/default/stunnel4
  fi

  systemctl enable stunnel4 >/dev/null 2>&1 || true
  systemctl restart stunnel4

  msg_ok "STUNNEL OK - TLS ${tls_port} -> ${fhost}:${fport}"
  sleep 2
}

status_stunnel(){
  cabecalho
  echo -e "${C}>>> STATUS STUNNEL${NC}"
  barra
  systemctl status stunnel4 --no-pager || true
  echo ""
  ss -lntp | egrep ':443|:8443' || true
  echo ""
  tail -n 60 "$STUNNEL_LOG" 2>/dev/null || true
  pause
}

remove_stunnel(){
  cabecalho
  echo -e "${R}>>> REMOVER STUNNEL${NC}"
  barra
  read -r -p "Confirmar? (s/N): " c
  [[ "${c:-}" =~ ^[sS]$ ]] || return
  systemctl stop stunnel4 2>/dev/null || true
  systemctl disable stunnel4 2>/dev/null || true
  apt purge -y stunnel4 2>/dev/null || true
  apt autoremove -y 2>/dev/null || true
  msg_ok "Stunnel removido."
  sleep 2
}

tunnel_arsenal(){
  while true; do
    cabecalho
    echo -e "${P}>>> TUNNEL ARSENAL (VPS)${NC}"
    barra
    echo -e "${C}┃ ${G}01${W} ⮞ INSTALAR CHISEL SERVER (reverse)${NC}"
    echo -e "${C}┃ ${G}02${W} ⮞ STATUS CHISEL${NC}"
    echo -e "${C}┃ ${G}03${W} ⮞ REMOVER CHISEL${NC}"
    echo -e "${C}┃ ${G}04${W} ⮞ INSTALAR STUNNEL SERVER (TCP forward)${NC}"
    echo -e "${C}┃ ${G}05${W} ⮞ STATUS STUNNEL${NC}"
    echo -e "${C}┃ ${G}06${W} ⮞ REMOVER STUNNEL${NC}"
    echo -e "${C}┃ ${R}00${W} ⮞ VOLTAR${NC}"
    barra
    read -r -p "➤ Opção: " op
    case "$op" in
      1|01) install_chisel_server ;;
      2|02) status_chisel ;;
      3|03) remove_chisel ;;
      4|04) install_stunnel_server ;;
      5|05) status_stunnel ;;
      6|06) remove_stunnel ;;
      0|00) return ;;
      *) echo -e "${R}Opção inválida!${NC}"; sleep 1 ;;
    esac
  done
}

menu(){
  while true; do
    cabecalho
    echo -e "${C}┃ ${G}01${W} ⮞ CRIAR USUÁRIO            ${C}┃ ${G}09${W} ⮞ NOVO CHAMADO${NC}"
    echo -e "${C}┃ ${G}02${W} ⮞ LISTAR USUÁRIOS          ${C}┃ ${G}10${W} ⮞ GERENCIAR CHAMADOS${NC}"
    echo -e "${C}┃ ${G}03${W} ⮞ REMOVER USUÁRIO          ${C}┃ ${G}11${W} ⮞ CONFIGURAR SMTP${NC}"
    echo -e "${C}┃ ${G}04${W} ⮞ ALTERAR VALIDADE         ${C}┃ ${G}12${W} ⮞ INSTALAR DEPS${NC}"
    echo -e "${C}┃ ${G}05${W} ⮞ ALTERAR LIMITE           ${C}┃ ${G}13${W} ⮞ INSTALAR SQUID${NC}"
    echo -e "${C}┃ ${G}06${W} ⮞ USUÁRIOS VENCIDOS        ${C}┃ ${G}14${W} ⮞ INSTALAR SSLH${NC}"
    echo -e "${C}┃ ${G}07${W} ⮞ MONITOR ONLINE           ${C}┃ ${G}15${W} ⮞ ATIVAR CRON${NC}"
    echo -e "${C}┃ ${G}08${W} ⮞ VINCULAR HWID            ${C}┃ ${G}16${W} ⮞ TUNNEL ARSENAL${NC}"
    echo -e "${C}┃ ${R}00${W} ⮞ SAIR${NC}"
    echo -e "${C}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"

    read -r -p "➤ Opção: " op
    case "$op" in
      1|01) criar_usuario ;;
      2|02) listar_usuarios ;;
      3|03) remover_usuario_lista ;;
      4|04) alterar_validade_lista ;;
      5|05) alterar_limite_lista ;;
      6|06) usuarios_vencidos ;;
      7|07) mostrar_usuarios_online ;;
      8|08) atualizar_hwid ;;
      9|09) novo_chamado ;;
      10) gerenciar_chamados ;;
      11) configurar_smtp ;;
      12) install_deps ;;
      13) install_squid ;;
      14) install_sslh ;;
      15) configurar_cron_monitor ;;
      16) tunnel_arsenal ;;
      0|00) exit 0 ;;
      *) echo -e "${R}Opção Inválida!${NC}"; sleep 1 ;;
    esac
  done
}

# --- INICIALIZAÇÃO ---
need_root
ensure_files
autocura_db_users

[ "${1:-}" == "--cron-monitor" ] && exit 0
menu
