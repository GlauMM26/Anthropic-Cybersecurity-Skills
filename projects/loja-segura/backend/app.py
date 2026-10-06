"""Loja Segura — servidor HTTP (apenas biblioteca padrão).

Por que sem framework? Para você ver o que Flask/Django fazem por baixo:
parse de requisição, roteamento, cookies, cabeçalhos, JSON e tratamento de erros.

Rotas:
  GET  /                      -> frontend (arquivos estáticos)
  GET  /api/products          -> catálogo
  GET  /api/products/<id>     -> um produto
  POST /api/auth/register     -> {email, password}
  POST /api/auth/login        -> {email, password}  (define cookie de sessão)
  POST /api/auth/logout
  GET  /api/me                -> usuário atual + csrf_token
  POST /api/orders            -> {items: [{product_id, quantity}]}  (requer login + CSRF)
  GET  /api/orders            -> pedidos do usuário logado

Execute:  python3 backend/app.py   e abra http://127.0.0.1:8000
"""
from __future__ import annotations

import json
import logging
import mimetypes
import os
import re
import sqlite3
import sys
import threading
import time
from collections import defaultdict, deque
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import auth  # noqa: E402
import db    # noqa: E402

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
MAX_BODY_BYTES = 64 * 1024          # corpo JSON máximo (defesa contra abuso de memória)
MAX_ITEMS_PER_ORDER = 50
MAX_QTY_PER_ITEM = 99
LOGIN_WINDOW_SECONDS = 300          # rate limit: 10 tentativas / 5 min / IP
LOGIN_MAX_ATTEMPTS = 10

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("loja")


class ApiError(Exception):
    def __init__(self, status: HTTPStatus, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class RateLimiter:
    """Janela deslizante em memória. Em produção, use Redis ou o WAF/proxy."""

    def __init__(self, max_events: int, window_seconds: int):
        self.max_events = max_events
        self.window = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._events[key]
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.max_events:
                return False
            q.append(now)
            return True


login_limiter = RateLimiter(LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_SECONDS)
_db_lock = threading.Lock()


def make_handler(conn: sqlite3.Connection, secure_cookies: bool):
    class Handler(BaseHTTPRequestHandler):
        server_version = "LojaSegura/0.1"
        sys_version = ""  # não anuncia a versão do Python (menos informação ao atacante)

        # ---------- utilidades de resposta ----------

        def _security_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
                "base-uri 'none'; form-action 'self'",
            )

        def _send_json(self, status: HTTPStatus, payload: dict, cookies: list[str] | None = None) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self._security_headers()
            for c in cookies or []:
                self.send_header("Set-Cookie", c)
            self.end_headers()
            self.wfile.write(body)

        def _session_cookie(self, value: str, max_age: int) -> str:
            parts = [f"session={value}", "Path=/", "HttpOnly", "SameSite=Strict", f"Max-Age={max_age}"]
            if secure_cookies:
                parts.append("Secure")
            return "; ".join(parts)

        # ---------- utilidades de requisição ----------

        def _client_ip(self) -> str:
            # Atrás de um proxy reverso confiável, leia X-Forwarded-For AQUI e
            # só aqui. Nunca confie nesse header vindo direto da internet.
            return self.client_address[0]

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY_BYTES:
                raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Corpo muito grande.")
            ctype = self.headers.get("Content-Type", "")
            if not ctype.startswith("application/json"):
                raise ApiError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Envie application/json.")
            raw = self.rfile.read(length) if length else b""
            try:
                data = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                raise ApiError(HTTPStatus.BAD_REQUEST, "JSON inválido.")
            if not isinstance(data, dict):
                raise ApiError(HTTPStatus.BAD_REQUEST, "Esperado um objeto JSON.")
            return data

        def _session(self) -> sqlite3.Row | None:
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            sid = cookie["session"].value if "session" in cookie else None
            return auth.get_session(conn, sid)

        def _require_user(self) -> sqlite3.Row:
            session = self._session()
            if session is None:
                raise ApiError(HTTPStatus.UNAUTHORIZED, "Faça login para continuar.")
            if not auth.csrf_ok(session, self.headers.get("X-CSRF-Token")):
                db.audit(conn, "csrf_rejected", user_id=session["user_id"], ip=self._client_ip())
                raise ApiError(HTTPStatus.FORBIDDEN, "Token CSRF ausente ou inválido.")
            return session

        # ---------- roteamento ----------

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch("POST")

        def _dispatch(self, method: str) -> None:
            path = urlsplit(self.path).path
            try:
                with _db_lock:
                    if path.startswith("/api/"):
                        self._route_api(method, path)
                    elif method == "GET":
                        self._serve_static(path)
                    else:
                        raise ApiError(HTTPStatus.METHOD_NOT_ALLOWED, "Método não permitido.")
            except ApiError as e:
                self._send_json(e.status, {"error": e.message})
            except Exception:  # noqa: BLE001
                # Nunca vaze stack trace ao cliente; registre no servidor.
                log.exception("erro interno em %s %s", method, path)
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Erro interno."})

        def _route_api(self, method: str, path: str) -> None:
            routes = {
                ("GET", "/api/products"): self.api_list_products,
                ("POST", "/api/auth/register"): self.api_register,
                ("POST", "/api/auth/login"): self.api_login,
                ("POST", "/api/auth/logout"): self.api_logout,
                ("GET", "/api/me"): self.api_me,
                ("POST", "/api/orders"): self.api_create_order,
                ("GET", "/api/orders"): self.api_list_orders,
            }
            handler = routes.get((method, path))
            if handler:
                return handler()
            m = re.fullmatch(r"/api/products/(\d{1,9})", path)
            if m and method == "GET":
                return self.api_get_product(int(m.group(1)))
            raise ApiError(HTTPStatus.NOT_FOUND, "Rota não encontrada.")

        # ---------- arquivos estáticos ----------

        def _serve_static(self, path: str) -> None:
            if path == "/":
                path = "/index.html"
            # Defesa contra path traversal: resolvemos o caminho real e exigimos
            # que ele continue DENTRO de FRONTEND_DIR.
            target = (FRONTEND_DIR / path.lstrip("/")).resolve()
            if FRONTEND_DIR.resolve() not in target.parents or not target.is_file():
                raise ApiError(HTTPStatus.NOT_FOUND, "Arquivo não encontrado.")
            ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
            body = target.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", f"{ctype}; charset=utf-8" if ctype.startswith("text/") or ctype.endswith("javascript") else ctype)
            self.send_header("Content-Length", str(len(body)))
            self._security_headers()
            self.end_headers()
            self.wfile.write(body)

        # ---------- handlers da API ----------

        def api_list_products(self) -> None:
            rows = conn.execute(
                "SELECT id, sku, name, description, price_cents, stock FROM products WHERE active = 1 ORDER BY name"
            ).fetchall()
            self._send_json(HTTPStatus.OK, {"products": [dict(r) for r in rows]})

        def api_get_product(self, product_id: int) -> None:
            row = conn.execute(
                "SELECT id, sku, name, description, price_cents, stock FROM products WHERE id = ? AND active = 1",
                (product_id,),
            ).fetchone()
            if not row:
                raise ApiError(HTTPStatus.NOT_FOUND, "Produto não encontrado.")
            self._send_json(HTTPStatus.OK, {"product": dict(row)})

        def api_register(self) -> None:
            data = self._read_json()
            try:
                user_id = auth.register(conn, str(data.get("email", "")), data.get("password", ""))
            except auth.AuthError as e:
                db.audit(conn, "register_failed", ip=self._client_ip(), detail=str(e))
                raise ApiError(HTTPStatus.BAD_REQUEST, str(e))
            db.audit(conn, "register_ok", user_id=user_id, ip=self._client_ip())
            self._send_json(HTTPStatus.CREATED, {"ok": True})

        def api_login(self) -> None:
            ip = self._client_ip()
            if not login_limiter.allow(ip):
                db.audit(conn, "login_rate_limited", ip=ip)
                raise ApiError(HTTPStatus.TOO_MANY_REQUESTS, "Muitas tentativas. Tente novamente em alguns minutos.")
            data = self._read_json()
            try:
                user = auth.authenticate(conn, str(data.get("email", "")), data.get("password", ""))
            except auth.AuthError as e:
                db.audit(conn, "login_failed", ip=ip, detail=str(data.get("email", ""))[:120])
                raise ApiError(HTTPStatus.UNAUTHORIZED, str(e))
            # Rotação de sessão no login previne session fixation.
            auth.destroy_session(conn, self._cookie_session_id())
            sid, csrf = auth.create_session(conn, user["id"])
            db.audit(conn, "login_ok", user_id=user["id"], ip=ip)
            self._send_json(
                HTTPStatus.OK,
                {"user": {"id": user["id"], "email": user["email"], "role": user["role"]}, "csrf_token": csrf},
                cookies=[self._session_cookie(sid, int(auth.SESSION_TTL.total_seconds()))],
            )

        def _cookie_session_id(self) -> str | None:
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            return cookie["session"].value if "session" in cookie else None

        def api_logout(self) -> None:
            session = self._session()
            if session is not None:
                auth.destroy_session(conn, session["session_id"])
                db.audit(conn, "logout", user_id=session["user_id"], ip=self._client_ip())
            self._send_json(HTTPStatus.OK, {"ok": True}, cookies=[self._session_cookie("", 0)])

        def api_me(self) -> None:
            session = self._session()
            if session is None:
                self._send_json(HTTPStatus.OK, {"user": None})
                return
            self._send_json(
                HTTPStatus.OK,
                {"user": {"id": session["user_id"], "email": session["email"], "role": session["role"]},
                 "csrf_token": session["csrf_token"]},
            )

        def api_create_order(self) -> None:
            session = self._require_user()
            data = self._read_json()
            items = data.get("items")
            if not isinstance(items, list) or not (1 <= len(items) <= MAX_ITEMS_PER_ORDER):
                raise ApiError(HTTPStatus.BAD_REQUEST, f"Envie de 1 a {MAX_ITEMS_PER_ORDER} itens.")

            # Validação estrita de tipos: bool é subclasse de int em Python, por isso o teste explícito.
            normalized: dict[int, int] = {}
            for it in items:
                if not isinstance(it, dict):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "Item inválido.")
                pid, qty = it.get("product_id"), it.get("quantity")
                if (not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0
                        or not isinstance(qty, int) or isinstance(qty, bool) or not (1 <= qty <= MAX_QTY_PER_ITEM)):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "product_id e quantity devem ser inteiros válidos.")
                normalized[pid] = normalized.get(pid, 0) + qty

            # Transação: ou o pedido inteiro é gravado e o estoque baixado, ou nada acontece.
            try:
                conn.execute("BEGIN IMMEDIATE")
                total = 0
                lines: list[tuple[int, int, int]] = []
                for pid, qty in normalized.items():
                    # O PREÇO VEM DO BANCO, nunca do cliente (evita manipulação de preço).
                    row = conn.execute(
                        "SELECT id, name, price_cents, stock FROM products WHERE id = ? AND active = 1", (pid,)
                    ).fetchone()
                    if not row:
                        raise ApiError(HTTPStatus.BAD_REQUEST, f"Produto {pid} indisponível.")
                    if row["stock"] < qty:
                        raise ApiError(HTTPStatus.CONFLICT, f"Estoque insuficiente para '{row['name']}'.")
                    total += row["price_cents"] * qty
                    lines.append((pid, qty, row["price_cents"]))

                cur = conn.execute(
                    "INSERT INTO orders (user_id, total_cents) VALUES (?, ?)", (session["user_id"], total)
                )
                order_id = int(cur.lastrowid)
                for pid, qty, unit in lines:
                    conn.execute(
                        "INSERT INTO order_items (order_id, product_id, quantity, unit_price_cents) VALUES (?, ?, ?, ?)",
                        (order_id, pid, qty, unit),
                    )
                    # Baixa de estoque com guarda no WHERE: protege contra condição de corrida.
                    updated = conn.execute(
                        "UPDATE products SET stock = stock - ? WHERE id = ? AND stock >= ?", (qty, pid, qty)
                    ).rowcount
                    if updated != 1:
                        raise ApiError(HTTPStatus.CONFLICT, "Estoque alterado durante a compra. Tente novamente.")
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

            db.audit(conn, "order_created", user_id=session["user_id"], ip=self._client_ip(),
                     detail=f"order_id={order_id} total_cents={total}")
            self._send_json(HTTPStatus.CREATED, {"order": {"id": order_id, "total_cents": total, "status": "pending"}})

        def api_list_orders(self) -> None:
            session = self._session()
            if session is None:
                raise ApiError(HTTPStatus.UNAUTHORIZED, "Faça login para continuar.")
            # Autorização: filtramos SEMPRE por user_id. Esquecer esse WHERE é a
            # vulnerabilidade mais comum em APIs (IDOR / Broken Object Level Authorization).
            orders = conn.execute(
                "SELECT id, status, total_cents, created_at FROM orders WHERE user_id = ? ORDER BY id DESC",
                (session["user_id"],),
            ).fetchall()
            result = []
            for o in orders:
                items = conn.execute(
                    """SELECT oi.product_id, p.name, oi.quantity, oi.unit_price_cents
                         FROM order_items oi JOIN products p ON p.id = oi.product_id
                        WHERE oi.order_id = ?""",
                    (o["id"],),
                ).fetchall()
                result.append({**dict(o), "items": [dict(i) for i in items]})
            self._send_json(HTTPStatus.OK, {"orders": result})

        # Log de acesso enxuto, sem query string (pode conter dados sensíveis).
        def log_message(self, fmt: str, *args) -> None:  # noqa: D401
            log.info("%s %s %s", self._client_ip(), self.command, urlsplit(self.path).path)

    return Handler


def create_server(host: str = "127.0.0.1", port: int = 8000, db_path: str = db.DEFAULT_DB_PATH,
                  secure_cookies: bool | None = None) -> ThreadingHTTPServer:
    conn = db.connect(db_path)
    db.init_db(conn)
    auth.purge_expired_sessions(conn)
    if secure_cookies is None:
        secure_cookies = os.environ.get("LOJA_SECURE_COOKIES", "0") == "1"
    server = ThreadingHTTPServer((host, port), make_handler(conn, secure_cookies))
    server.conn = conn  # type: ignore[attr-defined]
    return server


if __name__ == "__main__":
    host = os.environ.get("LOJA_HOST", "127.0.0.1")
    port = int(os.environ.get("LOJA_PORT", "8000"))
    srv = create_server(host, port)
    log.info("Loja Segura em http://%s:%d (Ctrl+C para parar)", host, port)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
