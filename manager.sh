#!/bin/bash
# ==================================================================
#  PMESP MANAGER ULTIMATE V8.6 - FULL (V8 + TUNNEL ARSENAL)
#  - Mantém menu grande completo do V8
#  - Adiciona submenu: CHISEL + STUNNEL
#  - Mantém: DEPS, SQUID, SSLH, CRON, SMTP, CHAMADOS, MONITOR
#  - Adiciona LOCK para DB não corromper com API
# ==================================================================

# --- ARQUIVOS DE DADOS ---
DB_PMESP="/etc/pmesp_users.json"
DB_CHAMADOS="/etc/pmesp_tickets.json"
CONFIG_SMTP="/etc/msmtprc"
LOG_MONITOR="/var/log/pmesp_monitor.log"
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

need_root(){
  if [ "$(id -u)" -ne 0 ]; then
    echo -e "${R}Este script precisa rodar como root.${NC}"
    echo -e "Use: ${Y}sudo pmesp${NC}"
    exit 1
  fi
}

ensure_files(){
  [ ! -f "$DB_PMESP" ] && touch "$DB_PMESP" && chmod 666 "$DB_PMESP"
  [ ! -f "$DB_CHAMADOS" ] && touch "$DB_CHAMADOS" && chmod 666 "$DB_CHAMADOS"
  [ ! -f "$LOG_MONITOR" ] && touch "$LOG_MONITOR" && chmod 644 "$LOG_MONITOR"
  mkdir -p /var/lock
  [ ! -f "$LOCK_FILE" ] && touch "$LOCK_FILE" && chmod 666 "$LOCK_FILE"
}

with_lock(){
  # usage: with_lock "comando..."
  (
    flock -x 200
    eval "$1"
  ) 200>"$LOCK_FILE"
}

# --- AUTO-CURA DB (mantém padrão V8 e melhora estabilidade) ---
autocura_db_users(){
  have jq || return
  [ ! -s "$DB_PMESP" ] && return

  with_lock '
    tmp_clean=$(mktemp)
    while IFS= read -r line; do
      [ -z "${line// }" ] && continue
      echo "$line" | jq -e . >/dev/null 2>&1 && echo "$line" >> "$tmp_clean"
    done < "'"$DB_PMESP"'"

    tmp2=$(mktemp)
    jq -s "unique_by(.usuario) | .[]" -c "$tmp_clean" 2>/dev/null > "$tmp2" || true
    [ -s "$tmp2" ] && cat "$tmp2" > "'"$DB_PMESP"'"
    rm -f "$tmp_clean" "$tmp2" 2>/dev/null || true
  '
}

# --- VISUAL ---
cabecalho(){
  clear
  _tuser=$(have jq && jq -s 'length' "$DB_PMESP" 2>/dev/null || echo "0")
  _ons=$(who | grep -v 'root' | wc -l | tr -d ' ')
  _ip=$(wget -qO- ipv4.icanhazip.com 2>/dev/null || echo "N/A")

  echo -e "${C}╭${LINE_H}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C}╮${NC}"
  echo -e "${C}┃${P}           PMESP MANAGER V8.6 - TÁTICO INTEGRADO           ${C}┃${NC}"
  echo -e "${C}┣${LINE_H}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫${NC}"
  echo -e "${C}┃ ${Y}TOTAL: ${W}$_tuser ${Y}| ONLINE: ${G}$_ons ${Y}| IP: ${G}$_ip${C}   ┃${NC}"
  echo -e "${C}┗${LINE_H}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
}

barra(){ echo -e "${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

# ==========================
# GESTÃO DE USUÁRIOS (V8)
# ==========================
criar_usuario(){
  cabecalho
  echo -e "${G}>>> NOVO CADASTRO DE POLICIAL${NC}"

  have jq || { echo -e "${R}jq não instalado. Use a opção 12.${NC}"; pause; return; }

  read -r -p "Matrícula (RE): " matricula
  read -r -p "Email: " email
  read -r -p "Login: " usuario
  [ -z "$usuario" ] && return

  # BLOQUEIO DUPLICATA
  if with_lock "grep -q '\"usuario\"[ ]*:[ ]*\"$usuario\"' '$DB_PMESP' 2>/dev/null"; then
    echo -e "\n${R}ERRO: O usuário '$usuario' já consta no Banco de Dados!${NC}"
    echo -e "${Y}Dica: Remova (03) se quiser recriar.${NC}"
    sleep 2; return
  fi

  if id "$usuario" >/dev/null 2>&1; then
    echo -e "\n${R}ERRO: Usuário já existe no Sistema Linux!${NC}"
    sleep 2; return
  fi

  read -r -p "Senha Provisória: " senha
  read -r -p "Validade (Dias): " dias
  read -r -p "Limite de Telas: " limite

  echo "$dias" | grep -Eq '^[0-9]+$' || { echo -e "${R}Dias inválidos.${NC}"; sleep 2; return; }
  echo "$limite" | grep -Eq '^[0-9]+$' || { echo -e "${R}Limite inválido.${NC}"; sleep 2; return; }

  useradd -M -s /bin/false "$usuario"
  echo "$usuario:$senha" | chpasswd
  data_exp=$(date -d "+$dias days" +"%Y-%m-%d")
  chage -E "$data_exp" "$usuario" >/dev/null 2>&1 || true

  item=$(jq -c -n --arg u "$usuario" --arg s "$senha" --arg d "$dias" --arg l "$limite" \
    --arg m "$matricula" --arg e "$email" --arg h "PENDENTE" --arg ex "$data_exp" \
    '{usuario:$u, senha:$s, dias:$d, limite:$l, matricula:$m, email:$e, hwid:$h, expiracao:$ex}')

  with_lock "echo '$item' >> '$DB_PMESP'"
  autocura_db_users

  echo -e "\n${G}Usuário $usuario criado com sucesso!${NC}"
  sleep 2
}

listar_usuarios(){
  cabecalho
  echo -e "${C}>>> LISTA DE USUÁRIOS CADASTRADOS${NC}"
  barra
  printf "${W}%-12s | %-10s | %-11s | %-4s | %-10s${NC}\n" "USUÁRIO" "RE" "EXPIRA" "LIM" "HWID"
  barra

  have jq || { echo -e "${R}jq não instalado.${NC}"; pause; return; }

  with_lock '
    if [ -s "'"$DB_PMESP"'" ]; then
      jq -c "." "'"$DB_PMESP"'" 2>/dev/null | while read -r line; do
        u=$(echo "$line" | jq -r .usuario)
        m=$(echo "$line" | jq -r .matricula)
        ex=$(echo "$line" | jq -r .expiracao)
        l=$(echo "$line" | jq -r .limite)
        h=$(echo "$line" | jq -r .hwid)
        printf "'"${Y}%-12s${NC} | %-10s | %-11s | %-4s | %-10s\n"'" "$u" "$m" "$ex" "$l" "${h:0:10}"
      done
    else
      echo -e "'"${R}Nenhum usuário cadastrado.${NC}"'"
    fi
  '
  echo ""
  pause
}

remover_usuario_direto(){
  cabecalho
  read -r -p "Login para remover: " user_alvo
  [ -z "$user_alvo" ] && return

  id "$user_alvo" >/dev/null 2>&1 && userdel -f "$user_alvo" >/dev/null 2>&1 || true

  have jq || { echo -e "${R}jq não instalado.${NC}"; pause; return; }

  with_lock '
    tmp=$(mktemp)
    jq -c "select(.usuario != \"'"$user_alvo"'\")" "'"$DB_PMESP"'" > "$tmp" 2>/dev/null || true
    cat "$tmp" > "'"$DB_PMESP"'"
    rm -f "$tmp" 2>/dev/null || true
  '

  echo -e "${G}Usuário $user_alvo removido!${NC}"
  sleep 2
}

alterar_validade_direto(){
  cabecalho
  read -r -p "Login: " user_alvo
  read -r -p "Novos dias: " novos_dias

  echo "$novos_dias" | grep -Eq '^[0-9]+$' || { echo -e "${R}Número inválido.${NC}"; sleep 2; return; }

  if id "$user_alvo" >/dev/null 2>&1; then
    nova_data=$(date -d "+$novos_dias days" +"%Y-%m-%d")
    chage -E "$nova_data" "$user_alvo" >/dev/null 2>&1 || true

    have jq || { echo -e "${R}jq não instalado.${NC}"; pause; return; }
    with_lock '
      tmp=$(mktemp)
      jq -c "if .usuario == \"'"$user_alvo"'\" then .expiracao = \"'"$nova_data"'\" | .dias = \"'"$novos_dias"'\" else . end" "'"$DB_PMESP"'" > "$tmp" 2>/dev/null || true
      cat "$tmp" > "'"$DB_PMESP"'"
      rm -f "$tmp"
    '
    echo -e "${G}Validade: $nova_data${NC}"
  else
    echo -e "${R}Usuário não encontrado.${NC}"
  fi
  sleep 2
}

usuarios_vencidos(){
  cabecalho
  echo -e "${R}>>> USUÁRIOS VENCIDOS${NC}"
  barra

  have jq || { echo -e "${R}jq não instalado.${NC}"; pause; return; }
  today=$(date +%s)

  with_lock '
    jq -c "." "'"$DB_PMESP"'" 2>/dev/null | while read -r line; do
      u=$(echo "$line" | jq -r .usuario)
      ex=$(echo "$line" | jq -r .expiracao)
      exp_sec=$(date -d "$ex" +%s 2>/dev/null || echo 0)
      if [ "$exp_sec" -lt "'"$today"'" ]; then
        echo -e "'"${R}"'$u - EXPIRADO EM '"$ex${NC}"'"
      fi
    done
  '
  pause
}

mostrar_usuarios_online(){
  tput civis; trap 'tput cnorm; return' SIGINT
  while true; do
    cabecalho
    echo -e "${C}>>> MONITORAMENTO ONLINE (CTRL+C Sair)${NC}"
    barra
    have jq || { echo -e "${R}jq não instalado.${NC}"; sleep 2; continue; }

    with_lock '
      jq -s "unique_by(.usuario) | .[]" -c "'"$DB_PMESP"'" 2>/dev/null | while read -r line; do
        u=$(echo "$line" | jq -r .usuario)
        l=$(echo "$line" | jq -r .limite)
        s=$(who | grep -w "$u" | wc -l)
        if [ "$s" -gt 0 ]; then
          printf "'"${Y}%-15s${NC} | %-10s | %-6s\n"'" "$u" "$s" "$l"
        fi
      done
    '
    sleep 2
  done
}

recuperar_senha(){
  cabecalho
  read -r -p "Usuário: " user_alvo

  have jq || { echo -e "${R}jq não instalado.${NC}"; pause; return; }

  email_dest=$(with_lock "jq -r 'select(.usuario==\"$user_alvo\") | .email' '$DB_PMESP' 2>/dev/null | head -n1")
  if [ -n "$email_dest" ] && [ "$email_dest" != "null" ]; then
    nova=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 10)
    echo "$user_alvo:$nova" | chpasswd >/dev/null 2>&1 || true
    echo -e "Subject: Nova Senha PMESP\n\nSenha: $nova" | msmtp "$email_dest" >/dev/null 2>&1 || true
    echo -e "${G}Senha enviada!${NC}"
  else
    echo -e "${R}Email não encontrado.${NC}"
  fi
  pause
}

atualizar_hwid(){
  cabecalho
  read -r -p "Usuário: " u
  read -r -p "Novo HWID: " h

  have jq || { echo -e "${R}jq não instalado.${NC}"; pause; return; }

  with_lock '
    tmp=$(mktemp)
    jq -c "if .usuario == \"'"$u"'\" then .hwid = \"'"$h"'\" else . end" "'"$DB_PMESP"'" > "$tmp" 2>/dev/null || true
    cat "$tmp" > "'"$DB_PMESP"'"
    rm -f "$tmp"
  '
  echo -e "${G}HWID Atualizado!${NC}"
  sleep 2
}

# ==========================
# SUPORTE E SISTEMA (V8)
# ==========================
novo_chamado(){
  cabecalho
  have jq || { echo -e "${R}jq não instalado.${NC}"; pause; return; }

  ID=$((1000 + RANDOM % 8999))
  read -r -p "Login: " u
  read -r -p "Problema: " p

  with_lock "jq -n --arg i '$ID' --arg u '$u' --arg p '$p' --arg s 'ABERTO' --arg d \"$(date)\" '{id:$i, usuario:$u, problema:$p, status:$s, data:$d}' -c >> '$DB_CHAMADOS'"
  echo -e "${G}Chamado #$ID criado.${NC}"
  sleep 2
}

gerenciar_chamados(){
  cabecalho
  have jq || { echo -e "${R}jq não instalado.${NC}"; pause; return; }

  if [ -s "$DB_CHAMADOS" ]; then
    with_lock "jq -r '\"ID: \\(.id) | USER: \\(.usuario) | STATUS: \\(.status) | DATA: \\(.data)\"' '$DB_CHAMADOS' 2>/dev/null || true"
  else
    echo -e "${Y}Sem chamados.${NC}"
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
  echo -e "${G}SMTP Configurado!${NC}"
  sleep 2
}

install_deps(){
  cabecalho
  apt-get update -y || true
  apt-get install -y \
    jq wget curl gzip ca-certificates openssl \
    msmtp msmtp-mta net-tools lsof cron screen nano zip unzip bc \
    squid sslh stunnel4 || true
  echo -e "${G}Dependências Instaladas!${NC}"
  sleep 2
}

install_squid(){
  cabecalho
  apt-get install -y squid >/dev/null 2>&1 || true
  cat > /etc/squid/squid.conf <<'EOF'
http_port 3128
acl all src 0.0.0.0/0
http_access allow all
EOF
  systemctl restart squid >/dev/null 2>&1 || true
  echo -e "${G}Squid Ativo na 3128!${NC}"
  sleep 2
}

# SSLH (mantém seu padrão)
install_sslh(){
  cabecalho
  apt-get install -y sslh >/dev/null 2>&1 || true

  # menu do debconf: você pode escolher standalone (recomendado)
  # depois garantimos a config que você usa
  echo 'DAEMON_OPTS="--user sslh --listen 0.0.0.0:443 --ssh 127.0.0.1:22"' > /etc/default/sslh

  systemctl enable sslh >/dev/null 2>&1 || true
  systemctl restart sslh >/dev/null 2>&1 || true

  echo -e "${G}SSLH Ativo na 443!${NC}"
  sleep 2
}

configurar_cron_monitor(){
  cabecalho
  p=$(readlink -f "$0")
  (crontab -l 2>/dev/null | grep -v "pmesp --cron-monitor" || true; echo "*/1 * * * * /bin/bash $p --cron-monitor >/dev/null 2>&1") | crontab -
  echo -e "${G}Monitoramento Cron Ativado!${NC}"
  sleep 2
}

status_api(){
  cabecalho
  echo -e "${P}>>> STATUS API (PMESP)${NC}"
  barra
  systemctl is-active --quiet pmesp-api && echo -e "Service: ${G}ONLINE${NC}" || echo -e "Service: ${R}OFFLINE${NC}"
  echo ""
  echo -e "Teste local: http://127.0.0.1:8000/docs"
  curl -s --max-time 2 http://127.0.0.1:8000/docs >/dev/null 2>&1 && echo -e "HTTP: ${G}OK${NC}" || echo -e "HTTP: ${R}FALHA${NC}"
  echo ""
  pause
}

# ==================================================================
# TUNNEL ARSENAL (CHISEL + STUNNEL)
# ==================================================================
download_chisel_latest(){
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y curl gzip ca-certificates >/dev/null 2>&1 || true

  local arch asset api url tmpdir
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) asset="linux_amd64" ;;
    aarch64|arm64) asset="linux_arm64" ;;
    armv7l|armhf) asset="linux_armv7" ;;
    *) echo -e "${R}Arch não suportada: $arch${NC}"; return 1 ;;
  esac

  api="https://api.github.com/repos/jpillora/chisel/releases/latest"
  url="$(curl -fsSL "$api" | sed -n 's/.*"browser_download_url": "\(.*'"$asset"'.*\.gz\)".*/\1/p' | head -n1)"
  [ -n "${url:-}" ] || { echo -e "${R}Falha ao localizar release do chisel.${NC}"; return 1; }

  tmpdir="$(mktemp -d)"
  curl -fsSL "$url" -o "$tmpdir/chisel.gz" || return 1
  gzip -d "$tmpdir/chisel.gz" || return 1
  chmod +x "$tmpdir/chisel"
  mv "$tmpdir/chisel" "$CHISEL_BIN"
  rm -rf "$tmpdir"
  return 0
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
  touch "$CHISEL_LOG" >/dev/null 2>&1 || true

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
  systemctl restart chisel >/dev/null 2>&1 || true

  echo -e "${G}CHISEL OK.${NC}"
  echo -e "${Y}Porta:${NC} ${W}${ch_port}${NC}"
  echo -e "${Y}Auth :${NC} ${W}${ch_auth}${NC}"
  echo -e "${Y}Log  :${NC} ${W}tail -n 80 ${CHISEL_LOG}${NC}"
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
  echo -e "${G}Chisel removido.${NC}"
  sleep 2
}

install_stunnel_server(){
  cabecalho
  echo -e "${G}>>> STUNNEL SERVER (TCP forward)${NC}"
  barra
  read -r -p "TLS listen (default 443): " tls_port
  read -r -p "Forward para HOST (default 127.0.0.1): " fhost
  read -r -p "Forward para PORTA (default 22): " fport
  tls_port="${tls_port:-443}"
  fhost="${fhost:-127.0.0.1}"
  fport="${fport:-22}"

  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y stunnel4 openssl ca-certificates net-tools >/dev/null 2>&1 || true

  mkdir -p /etc/stunnel /var/run/stunnel4 /var/log/stunnel4
  touch "$STUNNEL_LOG" >/dev/null 2>&1 || true

  if [[ ! -f "$STUNNEL_CERT" ]]; then
    openssl req -new -x509 -days 3650 -nodes \
      -out "$STUNNEL_CERT" -keyout "$STUNNEL_CERT" \
      -subj "/C=BR/ST=SP/L=SP/O=PMESP-Tank/CN=tank.local" >/dev/null 2>&1
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
    sed -i 's/^ENABLED=.*/ENABLED=1/' /etc/default/stunnel4 >/dev/null 2>&1 || true
    grep -q '^ENABLED=' /etc/default/stunnel4 || echo 'ENABLED=1' >> /etc/default/stunnel4
  fi

  systemctl enable stunnel4 >/dev/null 2>&1 || true
  systemctl restart stunnel4 >/dev/null 2>&1 || true

  echo -e "${G}STUNNEL OK.${NC}"
  echo -e "${Y}TLS:${NC} ${W}${tls_port}${NC}  ->  ${W}${fhost}:${fport}${NC}"
  sleep 2
}

status_stunnel(){
  cabecalho
  echo -e "${C}>>> STATUS STUNNEL${NC}"
  barra
  systemctl status stunnel4 --no-pager || true
  echo ""
  ss -lntp | egrep ':443|:22|:8443' || true
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
  apt-get purge -y stunnel4 >/dev/null 2>&1 || true
  apt-get autoremove -y >/dev/null 2>&1 || true
  echo -e "${G}Stunnel removido.${NC}"
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

# ==========================
# MENU FULL (igual V8 + extras)
# ==========================
menu(){
  while true; do
    cabecalho
    echo -e "${C}┃ ${G}01${W} ⮞ CRIAR USUÁRIO           ${C}┃ ${G}09${W} ⮞ NOVO CHAMADO${NC}"
    echo -e "${C}┃ ${G}02${W} ⮞ LISTAR USUÁRIOS          ${C}┃ ${G}10${W} ⮞ GERENCIAR CHAMADOS${NC}"
    echo -e "${C}┃ ${G}03${W} ⮞ REMOVER USUÁRIO          ${C}┃ ${G}11${W} ⮞ CONFIGURAR SMTP${NC}"
    echo -e "${C}┃ ${G}04${W} ⮞ ALTERAR VALIDADE         ${C}┃ ${G}12${W} ⮞ INSTALAR DEPS${NC}"
    echo -e "${C}┃ ${G}05${W} ⮞ USUÁRIOS VENCIDOS        ${C}┃ ${G}13${W} ⮞ INSTALAR SQUID${NC}"
    echo -e "${C}┃ ${G}06${W} ⮞ MONITOR ONLINE           ${C}┃ ${G}14${W} ⮞ INSTALAR SSLH${NC}"
    echo -e "${C}┃ ${G}07${W} ⮞ RESET SENHA (EMAIL)      ${C}┃ ${G}15${W} ⮞ ATIVAR CRON${NC}"
    echo -e "${C}┃ ${G}08${W} ⮞ VINCULAR HWID            ${C}┃ ${G}16${W} ⮞ TUNNEL ARSENAL${NC}"
    echo -e "${C}┃ ${G}17${W} ⮞ STATUS API               ${C}┃ ${R}00${W} ⮞ SAIR${NC}"
    echo -e "${C}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    read -r -p "➤ Opção: " op
    case "$op" in
      1|01) criar_usuario ;;
      2|02) listar_usuarios ;;
      3|03) remover_usuario_direto ;;
      4|04) alterar_validade_direto ;;
      5|05) usuarios_vencidos ;;
      6|06) mostrar_usuarios_online ;;
      7|07) recuperar_senha ;;
      8|08) atualizar_hwid ;;
      9|09) novo_chamado ;;
      10) gerenciar_chamados ;;
      11) configurar_smtp ;;
      12) install_deps ;;
      13) install_squid ;;
      14) install_sslh ;;
      15) configurar_cron_monitor ;;
      16) tunnel_arsenal ;;
      17) status_api ;;
      0|00) exit 0 ;;
      *) echo -e "${R}Opção inválida!${NC}"; sleep 1 ;;
    esac
  done
}

# --- INICIALIZAÇÃO ---
need_root
ensure_files
autocura_db_users

[ "${1:-}" = "--cron-monitor" ] && exit 0
menu
