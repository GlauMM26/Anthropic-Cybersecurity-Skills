"""Autenticação, sessões e CSRF.

Conceitos (Nível 4 — IAM / criptografia aplicada):
- Senha nunca é armazenada: guardamos scrypt(salt, senha). scrypt é lento de
  propósito, o que encarece ataques de força bruta offline.
- Comparação em tempo constante (hmac.compare_digest) evita timing attacks.
- Sessão = ID aleatório de 256 bits guardado no servidor; cookie HttpOnly.
- CSRF: padrão "synchronizer token" — o token fica na sessão e o frontend
  precisa devolvê-lo no header X-CSRF-Token em toda requisição que altera estado.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

SESSION_TTL = timedelta(hours=8)
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[a-zA-Z]{2,}$")
MIN_PASSWORD_LEN = 10
MAX_PASSWORD_LEN = 128

# Parâmetros scrypt (OWASP recomenda N=2^17, r=8, p=1 como ponto de partida).
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1  # menor N para o laboratório rodar rápido


class AuthError(Exception):
    """Erro de validação/credencial. A mensagem é segura para mostrar ao usuário."""


# ---------- senha ----------

def validate_email(email: str) -> str:
    email = (email or "").strip().lower()
    if not EMAIL_RE.match(email):
        raise AuthError("E-mail inválido.")
    return email


def validate_password(password: str) -> str:
    if not isinstance(password, str) or not (MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN):
        raise AuthError(f"A senha deve ter entre {MIN_PASSWORD_LEN} e {MAX_PASSWORD_LEN} caracteres.")
    return password


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${b64(salt)}${b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_b64, digest_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.scrypt(password.encode(), salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


# Hash "fantasma" usado quando o e-mail não existe, para que login com usuário
# inexistente demore o mesmo que login com senha errada (evita enumeração por tempo).
_DUMMY_HASH = hash_password("senha-fantasma-para-tempo-constante")


# ---------- usuários ----------

def register(conn: sqlite3.Connection, email: str, password: str) -> int:
    email = validate_email(email)
    password = validate_password(password)
    try:
        cur = conn.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (email, hash_password(password)),
        )
    except sqlite3.IntegrityError:
        # Mensagem genérica: não confirmamos se o e-mail já existe (anti-enumeração).
        raise AuthError("Não foi possível criar a conta com esses dados.")
    return int(cur.lastrowid)


def authenticate(conn: sqlite3.Connection, email: str, password: str) -> sqlite3.Row:
    email = (email or "").strip().lower()
    row = conn.execute("SELECT id, email, role, password_hash FROM users WHERE email = ?", (email,)).fetchone()
    stored = row["password_hash"] if row else _DUMMY_HASH
    ok = verify_password(password or "", stored)
    if not row or not ok:
        raise AuthError("E-mail ou senha incorretos.")
    return row


# ---------- sessões ----------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_session(conn: sqlite3.Connection, user_id: int) -> tuple[str, str]:
    session_id = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    expires = (_now() + SESSION_TTL).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO sessions (id, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)",
        (session_id, user_id, csrf_token, expires),
    )
    return session_id, csrf_token


def get_session(conn: sqlite3.Connection, session_id: str | None) -> sqlite3.Row | None:
    if not session_id:
        return None
    return conn.execute(
        """SELECT s.id AS session_id, s.csrf_token, s.expires_at,
                  u.id AS user_id, u.email, u.role
             FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.id = ? AND s.expires_at > datetime('now')""",
        (session_id,),
    ).fetchone()


def destroy_session(conn: sqlite3.Connection, session_id: str | None) -> None:
    if session_id:
        conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))


def purge_expired_sessions(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM sessions WHERE expires_at <= datetime('now')")


def csrf_ok(session: sqlite3.Row | None, header_token: str | None) -> bool:
    if session is None or not header_token:
        return False
    return hmac.compare_digest(session["csrf_token"], header_token)
