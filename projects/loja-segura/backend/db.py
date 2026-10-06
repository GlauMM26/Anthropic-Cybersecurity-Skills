"""Camada de acesso ao banco (SQLite).

Regra de ouro: TODA consulta usa parâmetros (?) em vez de concatenar strings.
É isso que impede SQL Injection. Veja tests/test_api.py::test_login_sql_injection.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_DB_PATH = os.environ.get("LOJA_DB_PATH", str(HERE / "loja.db"))


def connect(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row          # permite acessar colunas por nome
    conn.execute("PRAGMA foreign_keys = ON")  # SQLite exige ligar por conexão
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db(conn: sqlite3.Connection, seed: bool = True) -> None:
    conn.executescript((HERE / "schema.sql").read_text(encoding="utf-8"))
    if seed:
        conn.executescript((HERE / "seed.sql").read_text(encoding="utf-8"))


def audit(conn: sqlite3.Connection, event: str, *, user_id: int | None = None,
          ip: str | None = None, detail: str | None = None) -> None:
    """Registra um evento de segurança/negócio. Nunca grave senhas ou tokens aqui."""
    conn.execute(
        "INSERT INTO audit_log (user_id, ip, event, detail) VALUES (?, ?, ?, ?)",
        (user_id, ip, event, detail),
    )
