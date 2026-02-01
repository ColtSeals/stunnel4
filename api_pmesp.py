from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from passlib.hash import bcrypt
import json
import os
import subprocess
import fcntl
from typing import Optional, List, Dict, Any

app = FastAPI(title="PMESP API")

DB_PATH = "/etc/pmesp_users.json"
LOCK_PATH = "/var/lock/pmesp_db.lock"

API_KEY = os.getenv("PMESP_API_KEY", "").strip()

class TrocaSenha(BaseModel):
    usuario: str
    senha_atual: str
    nova_senha: str

def require_api_key(x_api_key: Optional[str]):
    if API_KEY:
        if not x_api_key or x_api_key.strip() != API_KEY:
            raise HTTPException(status_code=401, detail="API key inválida")

def _lock_exclusive():
    os.makedirs(os.path.dirname(LOCK_PATH), exist_ok=True)
    lf = open(LOCK_PATH, "w")
    fcntl.flock(lf, fcntl.LOCK_EX)
    return lf

def carregar_db() -> List[Dict[str, Any]]:
    users: List[Dict[str, Any]] = []
    if os.path.exists(DB_PATH):
        with open(DB_PATH, "r", encoding="utf-8") as f:
            for linha in f:
                linha = linha.strip()
                if not linha:
                    continue
                try:
                    obj = json.loads(linha)
                    if isinstance(obj, dict) and "usuario" in obj:
                        users.append(obj)
                except Exception:
                    continue
    return users

def salvar_db(users: List[Dict[str, Any]]):
    # escrita atômica com lock
    lockf = _lock_exclusive()
    try:
        tmp_path = DB_PATH + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            for u in users:
                f.write(json.dumps(u, ensure_ascii=False) + "\n")
        os.replace(tmp_path, DB_PATH)
    finally:
        fcntl.flock(lockf, fcntl.LOCK_UN)
        lockf.close()

def validar_senha(user: Dict[str, Any], senha_informada: str) -> bool:
    senha_hash = user.get("senha_hash")
    if senha_hash:
        try:
            return bcrypt.verify(senha_informada, senha_hash)
        except Exception:
            return False
    senha_plain = user.get("senha")
    if senha_plain:
        return senha_plain == senha_informada
    return False

def set_senha_linux(usuario: str, nova_senha: str):
    p = subprocess.run(
        ["chpasswd"],
        input=f"{usuario}:{nova_senha}\n".encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    if p.returncode != 0:
        raise HTTPException(status_code=500, detail="Falha ao alterar senha no Linux")

@app.get("/me/{username}")
async def ver_meus_dados(username: str, x_api_key: Optional[str] = Header(default=None)):
    require_api_key(x_api_key)

    lockf = _lock_exclusive()
    try:
        users = carregar_db()
    finally:
        fcntl.flock(lockf, fcntl.LOCK_UN)
        lockf.close()

    u = next((user for user in users if user.get("usuario") == username), None)
    if not u:
        raise HTTPException(status_code=404, detail="Não encontrado")

    return {
        "usuario": u.get("usuario"),
        "re": u.get("matricula"),
        "expira_em": u.get("expiracao", "N/A"),
        "limite": u.get("limite"),
        "hwid": u.get("hwid"),
    }

@app.post("/alterar-senha")
async def mudar_senha(d: TrocaSenha, x_api_key: Optional[str] = Header(default=None)):
    require_api_key(x_api_key)

    if len(d.nova_senha) < 8:
        raise HTTPException(status_code=400, detail="Nova senha fraca (mínimo 8 caracteres)")

    lockf = _lock_exclusive()
    try:
        users = carregar_db()

        for u in users:
            if u.get("usuario") == d.usuario:
                if not validar_senha(u, d.senha_atual):
                    raise HTTPException(status_code=403, detail="Senha atual incorreta")

                set_senha_linux(d.usuario, d.nova_senha)

                u["senha_hash"] = bcrypt.hash(d.nova_senha)
                u["senha"] = d.nova_senha  # se quiser mais segurança, remova depois

                salvar_db(users)
                return {"status": "sucesso"}

        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    finally:
        fcntl.flock(lockf, fcntl.LOCK_UN)
        lockf.close()
