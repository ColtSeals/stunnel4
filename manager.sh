#!/usr/bin/env bash
# ==================================================================
#   PMESP MANAGER ULTIMATE V9.2 - TÁTICO + TUNNEL ARSENAL (LOCKED)
#   DB: NDJSON (1 JSON por linha) + FILE LOCK + ATOMIC WRITE
# ==================================================================
set -euo pipefail

# --- ARQUIVOS DE DADOS ---
DB_PMESP="/etc/pmesp_users.json"          # NDJSON: 1 JSON por linha
DB_CHAMADOS="/etc/pmesp_tickets.json"     # NDJSON
CONFIG_SMTP="/etc/msmtprc"
LOG_MONITOR="/var/log/pmesp_monitor.log"

# LOCK (compartilhado Bash + API)
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
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo -e "${R}Este script precisa rodar como root.${NC}"
    echo -e "Use: ${Y}sudo pmesp${NC}"
    exit 1
  fi
}

ensure_files(){
  mkdir -p /var/lock
  [ ! -f "$LOCK_FILE" ] && : > "$LOCK_FILE" && chmod 600 "$LOCK_FILE" || true

  [ ! -f "$DB_PMESP" ] && touch "$DB_PMESP" && chmod 666 "$DB_PMESP"
  [ ! -f "$DB_CHAMADOS" ] && touch "$DB_CHAMADOS" && chmod 666 "$DB_CHAMADOS"
  [ ! -f "$LOG_MONITOR" ] && touch "$LOG_MONITOR" && chmod 644 "$LOG_MONITOR"
}

# ------------------------------------------------------------
# LOCK PRIMITIVES (Bash) - shared lock p/ leitura, exclusive p/ escrita
# ------------------------------------------------------------
with_db_lock(){
  # uso: with_db_lock -s <cmd...>   (shared/read)
  #      with_db_lock -x <cmd...>   (exclusive/write)
  local mode="$1"; shift
  (
    flock "$mode" 200
    "$@"
  ) 200>"$LOCK_FILE"
}

db_snapshot(){
  # cria cópia consistente do DB sob shared lock
  local tmp
  tmp="$(mktemp)"
  with_db_lock -s bash -c 'cat "$1" > "$2" 2>/dev/null || true' _ "$DB_PMESP" "$tmp"
  echo "$tmp"
}

db_append_line(){
  # append consistente sob exclusive lock
  local line="$1"
  with_db_lock -x bash -c 'printf "%s\n" "$1" >> "$2"' _ "$line" "$DB_PMESP"
}

db_replace_atomic(){
  # replace atômico sob exclusive lock (mv dentro do lock)
  local src="$1"
  with_db_lock -x bash -c 'mv -f "$1" "$2"' _ "$src" "$DB_PMESP"
}

# ------------------------------------------------------------
# AUTO-CURA (sob lock + atomic replace)
# ------------------------------------------------------------
autocura_db_users(){
  have jq || return 0

  # snapshot consistente
  local snap clean tmp_out
  snap="$(db_snapshot)"
  [ ! -s "$snap" ] && { rm -f "$snap" || true; return 0; }

  clean="$(mktemp)"
  while IFS= read -r line; do
    [[ -z "${line// }" ]] && continue
    echo "$line" | jq -e . >/dev/null 2>&1 && echo "$line" >> "$clean"
  done < "$snap"

  tmp_out="$(mktemp)"
  jq -s 'map(select(type=="object" and has("usuario"))) | unique_by(.usuario) | .[]' -c \
    "$clean" 2>/dev/null > "$tmp_out" || true

  rm -f "$snap" "$clean" 2>/dev/null || true
  [ -s "$tmp_out" ] && db_replace_atomic "$tmp_out" || rm -f "$tmp_out" || true
}

cabecalho(){
  clear
  local _tuser _ons _ip
  _tuser="$(
    if have jq; then
      local snap
      snap="$(db_snapshot)"
      jq -s 'length' "$snap" 2>/dev/null || echo "0"
      rm -f "$snap" 2>/dev/null || true
    else
      echo "0"
    fi
  )"
  _ons=$(who | grep -v 'root' | wc -l | tr -d ' ')
  _ip=$(wget -qO- ipv4.icanhazip.com 2>/dev/null || echo "N/A")

  echo -e "${C}╭${LINE_H}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C}╮${NC}"
  echo -e "${C}┃${P}            PMESP MANAGER V9.2 - TÁTICO INTEGRADO           ${C}┃${NC}"
  echo -e "${C}┣${LINE_H}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫${NC}"
  echo -e "${C}┃ ${Y}TOTAL: ${W}$_tuser ${Y}| ONLINE: ${G}$_ons ${Y}| IP: ${G}$_ip${C}    ┃${NC}"
  echo -e "${C}┗${LINE_H}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
}

barra(){ echo -e "${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

# ------------------------------------------------------------
# STATUS API (diagnóstico real + systemd)
# ------------------------------------------------------------
status_api_tatica(){
  cabecalho
  echo -e "${P}>>> STATUS DA INTELIGÊNCIA (API)${NC}"
  barra

  if systemctl is-active --quiet pmesp-api.service; then
    echo -e "Serviço: ${G}ONLINE${NC} (systemd)"
  else
    echo -e "Serviço: ${R}OFFLINE${NC}"
  fi

  echo -e "Teste interno: ${W}http://127.0.0.1:8000/health${NC}"
  if curl -fsS --max-time 2 http://127.0.0.1:8000/health >/dev/null 2>&1; then
    echo -e "API: ${G}OK${NC}"
  else
    echo -e "API: ${R}FALHA${NC} (timeout/erro)"
    echo -e "${Y}Dica:${NC} systemctl status pmesp-api.service"
  fi
  pause
}

# --- FUNÇÃO DE SELEÇÃO INTELIGENTE ---
selecionar_usuario_lista(){
  cabecalho
  echo -e "${C}>>> SELECIONE O USUÁRIO${NC}"
  barra

  if ! have jq; then
    echo -e "${R}jq não instalado.${NC} Use a opção 12 para instalar dependências."
    pause; return 1
  fi

  local snap
  snap="$(db_snapshot)"
  if [ ! -s "$snap" ]; then
    echo -e "${R}Nenhum usuário cadastrado.${NC}"
    rm -f "$snap" 2>/dev/null || true
    pause; return 1
  fi

  mapfile -t users_list < <(jq -r 'select(type=="object" and has("usuario")) | .usuario' "$snap" 2>/dev/null || true)
  rm -f "$snap" 2>/dev/null || true

  if [ ${#users_list[@]} -eq 0 ]; then
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

# ------------------------------------------------------------
# GESTÃO DE USUÁRIOS
# ------------------------------------------------------------
criar_usuario(){
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

  # Checagem de duplicidade consistente (snapshot)
  local snap
  snap="$(db_snapshot)"
  if grep -q "\"usuario\"[ ]*:[ ]*\"$usuario\"" "$snap" 2>/dev/null; then
    rm -f "$snap" 2>/dev/null || true
    echo -e "\n${R}ERRO: O usuário '$usuario' já existe!${NC}"
    sleep 2; return
  fi
  rm -f "$snap" 2>/dev/null || true

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
  data_exp=$(date -d "+$dias days" +"%Y-%m-%d")
  chage -E "$data_exp" "$usuario" || true

  item=$(jq -c -n --arg u "$usuario" --arg s "$senha" --arg d "$dias" --arg l "$limite" \
    --arg m "$matricula" --arg e "$email" --arg h "PENDENTE" --arg ex "$data_exp" \
    '{usuario:$u, senha:$s, dias:$d, limite:$l, matricula:$m, email:$e, hwid:$h, expiracao:$ex}')

  db_append_line "$item"
  autocura_db_users

  echo -e "\n${G}Usuário ${W}$usuario${G} criado com sucesso!${NC}"
  sleep 2
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

  local snap
  snap="$(db_snapshot)"
  if [ -s "$snap" ]; then
    jq -c '.' "$snap" 2>/dev/null | while read -r line; do
      u=$(echo "$line" | jq -r .usuario); m=$(echo "$line" | jq -r .matricula)
      ex=$(echo "$line" | jq -r .expiracao); l=$(echo "$line" | jq -r .limite)
      h=$(echo "$line" | jq -r .hwid)
      printf "${Y}%-12s${NC} | %-10s | %-11s | %-4s | %-10s\n" "$u" "$m" "$ex" "$l" "${h:0:10}"
    done
  else
    echo -e "${R}Nenhum usuário.${NC}"
  fi
  rm -f "$snap" 2>/dev/null || true
  echo ""
  pause
}

remover_usuario_lista(){
  selecionar_usuario_lista || return

  echo -e "${R}ATENÇÃO: Você vai remover o usuário ${W}$USER_ALVO${R}.${NC}"
  read -r -p "Tem certeza? (s/n): " confirm
  [[ "$confirm" != "s" && "$confirm" != "S" ]] && return

  id "$USER_ALVO" >/dev/null 2>&1 && userdel -f "$USER_ALVO" || true

  have jq || { echo -e "${R}jq não instalado.${NC}"; pause; return; }

  local snap tmp
  snap="$(db_snapshot)"
  tmp="$(mktemp)"
  jq -c "select(.usuario != \"$USER_ALVO\")" "$snap" > "$tmp" 2>/dev/null || true
  rm -f "$snap" 2>/dev/null || true

  db_replace_atomic "$tmp"
  autocura_db_users

  echo -e "${G}Usuário removido com sucesso!${NC}"
  sleep 2
}

alterar_validade_lista(){
  selecionar_usuario_lista || return

  cabecalho
  echo -e "${C}>>> ALTERANDO VALIDADE: ${Y}$USER_ALVO${NC}"
  read -r -p "Novos dias de validade: " novos_dias

  [[ "$novos_dias" =~ ^[0-9]+$ ]] || { echo -e "${R}Número inválido!${NC}"; sleep 1; return; }

  if id "$USER_ALVO" >/dev/null 2>&1; then
    local nova_data snap tmp
    nova_data=$(date -d "+$novos_dias days" +"%Y-%m-%d")
    chage -E "$nova_data" "$USER_ALVO" || true

    have jq || { echo -e "${R}jq não instalado.${NC}"; pause; return; }

    snap="$(db_snapshot)"
    tmp="$(mktemp)"
    jq -c "if .usuario == \"$USER_ALVO\" then .expiracao = \"$nova_data\" | .dias = \"$novos_dias\" else . end" \
      "$snap" > "$tmp" 2>/dev/null || true
    rm -f "$snap" 2>/dev/null || true

    db_replace_atomic "$tmp"
    autocura_db_users

    echo -e "${G}Sucesso! Nova data: ${W}$nova_data${NC}"
  else
    echo -e "${R}Erro: Usuário não encontrado no Linux.${NC}"
  fi
  sleep 2
}

alterar_limite_lista(){
  selecionar_usuario_lista || return

  cabecalho
  echo -e "${C}>>> ALTERANDO LIMITE: ${Y}$USER_ALVO${NC}"

  have jq || { echo -e "${R}jq não instalado.${NC}"; pause; return; }

  local snap limite_atual
  snap="$(db_snapshot)"
  limite_atual=$(jq -r "select(.usuario==\"$USER_ALVO\") | .limite" "$snap" 2>/dev/null || echo "N/A")
  rm -f "$snap" 2>/dev/null || true
  echo -e "Limite Atual: ${W}$limite_atual${NC}"

  read -r -p "Novo limite de conexões: " novo_limite
  [[ "$novo_limite" =~ ^[0-9]+$ ]] || { echo -e "${R}Número inválido!${NC}"; sleep 1; return; }

  snap="$(db_snapshot)"
  local tmp
  tmp="$(mktemp)"
  jq -c "if .usuario == \"$USER_ALVO\" then .limite = \"$novo_limite\" else . end" "$snap" > "$tmp" 2>/dev/null || true
  rm -f "$snap" 2>/dev/null || true

  db_replace_atomic "$tmp"
  autocura_db_users

  echo -e "${G}Limite atualizado para: ${W}$novo_limite${NC}"
  sleep 2
}

usuarios_vencidos(){
  cabecalho
  echo -e "${R}>>> USUÁRIOS VENCIDOS${NC}"
  barra

  have jq || { echo -e "${R}jq não instalado.${NC}"; pause; return; }

  local today snap
  today=$(date +%s)
  snap="$(db_snapshot)"

  jq -c '.' "$snap" 2>/dev/null | while read -r line; do
    u=$(echo "$line" | jq -r .usuario); ex=$(echo "$line" | jq -r .expiracao)
    exp_sec=$(date -d "$ex" +%s 2>/dev/null || echo 0)
    if [ "$exp_sec" -lt "$today" ]; then
      echo -e "${R}$u - EXPIRADO EM $ex${NC}"
    fi
  done

  rm -f "$snap" 2>/dev/null || true
  pause
}

mostrar_usuarios_online(){
  tput civis; trap 'tput cnorm; return' SIGINT
  while true; do
    cabecalho
    echo -e "${C}>>> MONITORAMENTO ONLINE (CTRL+C Sair)${NC}"
    barra
    have jq || { echo -e "${R}jq não instalado.${NC}"; sleep 2; continue; }

    local snap
    snap="$(db_snapshot)"
    jq -s 'unique_by(.usuario) | .[]' -c "$snap" 2>/dev/null | while read -r line; do
      u=$(echo "$line" | jq -r .usuario)
      l=$(echo "$line" | jq -r .limite)
      s=$(who | grep -w "$u" | wc -l)
      if [ "$s" -gt 0 ]; then
        printf "${Y}%-15s${NC} | ON: %-3s | LIM: %-3s\n" "$u" "$s" "$l"
      fi
    done
    rm -f "$snap" 2>/dev/null || true
    sleep 2
  done
}

recuperar_senha(){
  cabecalho
  read -r -p "Usuário (Login): " user_alvo
  have jq || { echo -e "${R}jq não instalado.${NC}"; pause; return; }

  local snap email_dest
  snap="$(db_snapshot)"
  email_dest=$(jq -r "select(.usuario==\"$user_alvo\") | .email" "$snap" 2>/dev/null || echo "")
  rm -f "$snap" 2>/dev/null || true

  if [ -n "$email_dest" ] && [ "$email_dest" != "null" ]; then
    nova=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 10)
    echo "$user_alvo:$nova" | chpasswd

    # Atualiza DB (senha plain para compat) sob lock + atomic
    snap="$(db_snapshot)"
    local tmp
    tmp="$(mktemp)"
    jq -c "if .usuario==\"$user_alvo\" then .senha=\"$nova\" else . end" "$snap" > "$tmp" 2>/dev/null || true
    rm -f "$snap" 2>/dev/null || true
    db_replace_atomic "$tmp"
    autocura_db_users

    echo -e "Subject: Nova Senha PMESP\n\nSenha: $nova" | msmtp "$email_dest" || true
    echo -e "${G}Senha enviada!${NC}"
  else
    echo -e "${R}Email não encontrado ou usuário inválido.${NC}"
  fi
  pause
}

atualizar_hwid(){
  selecionar_usuario_lista || return
  read -r -p "Novo HWID: " h
  have jq || { echo -e "${R}jq não instalado.${NC}"; pause; return; }

  local snap tmp
  snap="$(db_snapshot)"
  tmp="$(mktemp)"
  jq -c "if .usuario == \"$USER_ALVO\" then .hwid = \"$h\" else . end" "$snap" > "$tmp" 2>/dev/null || true
  rm -f "$snap" 2>/dev/null || true

  db_replace_atomic "$tmp"
  autocura_db_users

  echo -e "${G}HWID atualizado!${NC}"
  sleep 2
}

# ------------------------------------------------------------
# SUPORTE E SISTEMA
# ------------------------------------------------------------
novo_chamado(){
  cabecalho
  have jq || { echo -e "${R}jq não instalado.${NC}"; pause; return; }

  local ID u p
  ID=$((1000 + RANDOM % 8999))
  read -r -p "Login: " u
  read -r -p "Problema: " p

  jq -n --arg i "$ID" --arg u "$u" --arg p "$p" --arg s "ABERTO" --arg d "$(date)" \
    '{id:$i, usuario:$u, problema:$p, status:$s, data:$d}' -c >> "$DB_CHAMADOS"

  echo -e "${G}Chamado #$ID criado.${NC}"
  sleep 2
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
  echo -e "${G}SMTP Configurado!${NC}"
  sleep 2
}

install_deps(){
  cabecalho
  apt update || true
  apt install -y jq msmtp msmtp-mta net-tools wget curl openssl ca-certificates bc screen nano lsof cron zip unzip
  echo -e "${G}Dependências Instaladas!${NC}"
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
  echo -e "${G}Squid Ativo na 3128!${NC}"
  sleep 2
}

install_sslh(){
  cabecalho
  apt install -y sslh >/dev/null
  echo 'DAEMON_OPTS="--user sslh --listen 0.0.0.0:443 --ssh 127.0.0.1:22"' > /etc/default/sslh
  systemctl restart sslh
  echo -e "${G}SSLH Ativo na 443!${NC}"
  sleep 2
}

configurar_cron_monitor(){
  cabecalho
  local p
  p=$(readlink -f "$0")
  (crontab -l 2>/dev/null | grep -v "pmesp --cron-monitor" || true; echo "*/1 * * * * /bin/bash $p --cron-monitor >/dev/null 2>&1") | crontab -
  echo -e "${G}Monitoramento Cron Ativado!${NC}"
  sleep 2
}

# ==================================================================
# TUNNEL ARSENAL (CHISEL/STUNNEL) - VPS SIDE
# ==================================================================

download_chisel_latest(){
  apt update || true
  apt install -y curl ca-certificates

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
  curl -fsSL "$url" -o "$tmpdir/chisel.gz"
  gzip -d "$tmpdir/chisel.gz"
  chmod +x "$tmpdir/chisel"
  mv "$tmpdir/chisel" "$CHISEL_BIN"
  rm -rf "$tmpdir"
  echo -e "${G}Chisel instalado em ${W}$CHISEL_BIN${NC}"
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
Description=Chisel Server (PMESP Tank Mode)
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
  ss -lntp | egrep ':443|:1080' || true
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
      -subj "/C=BR/ST=SP/L=SP/O=PMESP-Tank/CN=tank.local"
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

  mkdir -p /etc/systemd/system/stunnel4.service.d
  cat > /etc/systemd/system/stunnel4.service.d/override.conf <<'EOF'
[Service]
Restart=always
RestartSec=3
EOF

  systemctl daemon-reload
  systemctl enable stunnel4 >/dev/null 2>&1 || true
  systemctl restart stunnel4

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
  ss -lntp | egrep ':443|:1080|:8443' || true
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
  rm -rf /etc/systemd/system/stunnel4.service.d 2>/dev/null || true
  systemctl daemon-reload || true
  apt purge -y stunnel4 2>/dev/null || true
  apt autoremove -y 2>/dev/null || true
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

# --- MENU ---
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
    echo -e "${C}┃ ${G}17${W} ⮞ STATUS API TÁTICA         ${C}┃ ${R}00${W} ⮞ SAIR${NC}"
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
      17) status_api_tatica ;;
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
