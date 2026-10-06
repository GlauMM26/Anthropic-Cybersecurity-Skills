"""Testes de integração da API (unittest, sem dependências externas).

Cada teste sobe o servidor real em uma thread com um banco SQLite temporário.
Os testes de segurança documentam o ataque e provam que a defesa funciona.

Execute na raiz do projeto:  python3 -m unittest discover -s backend/tests -v
"""
from __future__ import annotations

import http.client
import json
import os
import sys
import tempfile
import threading
import unittest
from http.cookies import SimpleCookie
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as loja_app  # noqa: E402


class Client:
    """Cliente HTTP mínimo que guarda cookies e o token CSRF, como um browser."""

    def __init__(self, host: str, port: int):
        self.host, self.port = host, port
        self.cookies: dict[str, str] = {}
        self.csrf: str | None = None

    def request(self, method: str, path: str, body=None, headers=None, send_csrf=True):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
        hdrs = dict(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            hdrs.setdefault("Content-Type", "application/json")
        if self.cookies:
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if send_csrf and self.csrf and method != "GET":
            hdrs.setdefault("X-CSRF-Token", self.csrf)
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read()
        for sc in resp.msg.get_all("Set-Cookie") or []:
            c = SimpleCookie(sc)
            for k, m in c.items():
                if m["max-age"] == "0":
                    self.cookies.pop(k, None)
                else:
                    self.cookies[k] = m.value
        try:
            payload = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            payload = raw
        conn.close()
        return resp, payload

    def register(self, email, password):
        return self.request("POST", "/api/auth/register", {"email": email, "password": password})

    def login(self, email, password):
        resp, data = self.request("POST", "/api/auth/login", {"email": email, "password": password})
        if resp.status == 200:
            self.csrf = data["csrf_token"]
        return resp, data


class LojaTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        db_path = os.path.join(cls.tmp.name, "test.db")
        cls.server = loja_app.create_server("127.0.0.1", 0, db_path=db_path, secure_cookies=False)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        self.c = Client("127.0.0.1", self.port)
        # Limpa o rate limiter entre testes para que um não contamine o outro.
        loja_app.login_limiter._events.clear()

    # ---------- funcionalidade básica ----------

    def test_catalog_lists_seeded_products(self):
        resp, data = self.c.request("GET", "/api/products")
        self.assertEqual(resp.status, 200)
        self.assertGreaterEqual(len(data["products"]), 6)
        self.assertNotIn("active", data["products"][0])  # só expomos colunas necessárias

    def test_register_login_logout_flow(self):
        resp, _ = self.c.register("ana@example.com", "senha-muito-forte-1")
        self.assertEqual(resp.status, 201)
        resp, data = self.c.login("ana@example.com", "senha-muito-forte-1")
        self.assertEqual(resp.status, 200)
        self.assertEqual(data["user"]["email"], "ana@example.com")
        self.assertIn("session", self.c.cookies)
        resp, data = self.c.request("GET", "/api/me")
        self.assertEqual(data["user"]["email"], "ana@example.com")
        resp, _ = self.c.request("POST", "/api/auth/logout")
        self.assertEqual(resp.status, 200)
        self.assertNotIn("session", self.c.cookies)
        _, data = self.c.request("GET", "/api/me")
        self.assertIsNone(data["user"])

    def test_order_decrements_stock_and_uses_server_price(self):
        self.c.register("bob@example.com", "outra-senha-forte-2")
        self.c.login("bob@example.com", "outra-senha-forte-2")
        _, cat = self.c.request("GET", "/api/products")
        product = cat["products"][0]
        # Cliente malicioso tenta enviar preço zero: o servidor ignora o campo.
        resp, data = self.c.request("POST", "/api/orders", {
            "items": [{"product_id": product["id"], "quantity": 2, "price_cents": 0}]
        })
        self.assertEqual(resp.status, 201, data)
        self.assertEqual(data["order"]["total_cents"], product["price_cents"] * 2)
        _, after = self.c.request("GET", f"/api/products/{product['id']}")
        self.assertEqual(after["product"]["stock"], product["stock"] - 2)
        _, orders = self.c.request("GET", "/api/orders")
        self.assertEqual(orders["orders"][0]["items"][0]["quantity"], 2)

    def test_order_rejects_insufficient_stock(self):
        self.c.register("carla@example.com", "senha-forte-numero-3")
        self.c.login("carla@example.com", "senha-forte-numero-3")
        _, cat = self.c.request("GET", "/api/products")
        p = cat["products"][0]
        resp, data = self.c.request("POST", "/api/orders", {"items": [{"product_id": p["id"], "quantity": 99}]})
        self.assertEqual(resp.status, 409)
        _, after = self.c.request("GET", f"/api/products/{p['id']}")
        self.assertEqual(after["product"]["stock"], p["stock"])  # rollback preservou o estoque

    # ---------- segurança ----------

    def test_login_sql_injection_is_harmless(self):
        """Payload clássico: ' OR '1'='1' --  . Com prepared statements vira só texto."""
        self.c.register("dave@example.com", "senha-forte-numero-4")
        payloads = ["' OR '1'='1' --", "dave@example.com' --", "\" OR 1=1 --"]
        for p in payloads:
            resp, _ = self.c.login(p, "qualquer")
            self.assertEqual(resp.status, 401, p)
            resp, _ = self.c.login("dave@example.com", p)
            self.assertEqual(resp.status, 401, p)
        # O banco continua íntegro.
        resp, _ = self.c.request("GET", "/api/products")
        self.assertEqual(resp.status, 200)

    def test_passwords_are_hashed_with_scrypt(self):
        self.c.register("eva@example.com", "minha-senha-secreta-5")
        row = self.server.conn.execute("SELECT password_hash FROM users WHERE email = ?", ("eva@example.com",)).fetchone()
        self.assertTrue(row["password_hash"].startswith("scrypt$"))
        self.assertNotIn("minha-senha-secreta-5", row["password_hash"])

    def test_weak_password_rejected(self):
        resp, data = self.c.register("fred@example.com", "curta")
        self.assertEqual(resp.status, 400)
        self.assertIn("senha", data["error"].lower())

    def test_duplicate_email_does_not_leak_existence(self):
        self.c.register("gil@example.com", "senha-forte-numero-6")
        resp, data = self.c.register("GIL@example.com", "senha-forte-numero-7")
        self.assertEqual(resp.status, 400)
        self.assertNotIn("já existe", data["error"].lower())

    def test_csrf_token_required_for_state_change(self):
        self.c.register("hugo@example.com", "senha-forte-numero-8")
        self.c.login("hugo@example.com", "senha-forte-numero-8")
        _, cat = self.c.request("GET", "/api/products")
        body = {"items": [{"product_id": cat["products"][0]["id"], "quantity": 1}]}
        resp, _ = self.c.request("POST", "/api/orders", body, send_csrf=False)
        self.assertEqual(resp.status, 403)
        resp, _ = self.c.request("POST", "/api/orders", body, headers={"X-CSRF-Token": "errado"}, send_csrf=False)
        self.assertEqual(resp.status, 403)
        resp, _ = self.c.request("POST", "/api/orders", body)
        self.assertEqual(resp.status, 201)

    def test_session_cookie_flags(self):
        self.c.register("iris@example.com", "senha-forte-numero-9")
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("POST", "/api/auth/login", body=json.dumps({"email": "iris@example.com", "password": "senha-forte-numero-9"}),
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse(); resp.read()
        cookie = resp.getheader("Set-Cookie")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)

    def test_security_headers_present(self):
        resp, _ = self.c.request("GET", "/")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.getheader("X-Frame-Options"), "DENY")
        self.assertIn("default-src 'self'", resp.getheader("Content-Security-Policy"))
        self.assertNotIn("Python", resp.getheader("Server") or "")

    def test_path_traversal_blocked(self):
        for path in ["/../backend/app.py", "/..%2F..%2Fetc%2Fpasswd", "/%2e%2e/%2e%2e/etc/passwd", "/../../etc/passwd"]:
            resp, _ = self.c.request("GET", path)
            self.assertEqual(resp.status, 404, path)

    def test_orders_require_login(self):
        resp, _ = self.c.request("GET", "/api/orders")
        self.assertEqual(resp.status, 401)
        resp, _ = self.c.request("POST", "/api/orders", {"items": []})
        self.assertEqual(resp.status, 401)

    def test_users_cannot_see_each_others_orders(self):
        a, b = Client("127.0.0.1", self.port), Client("127.0.0.1", self.port)
        a.register("joao@example.com", "senha-forte-numero-10"); a.login("joao@example.com", "senha-forte-numero-10")
        b.register("kate@example.com", "senha-forte-numero-11"); b.login("kate@example.com", "senha-forte-numero-11")
        _, cat = a.request("GET", "/api/products")
        a.request("POST", "/api/orders", {"items": [{"product_id": cat["products"][1]["id"], "quantity": 1}]})
        _, orders_b = b.request("GET", "/api/orders")
        self.assertEqual(orders_b["orders"], [])

    def test_order_input_validation(self):
        self.c.register("lia@example.com", "senha-forte-numero-12")
        self.c.login("lia@example.com", "senha-forte-numero-12")
        bad = [
            {"items": []},
            {"items": [{"product_id": "1", "quantity": 1}]},
            {"items": [{"product_id": 1, "quantity": 0}]},
            {"items": [{"product_id": 1, "quantity": -5}]},
            {"items": [{"product_id": True, "quantity": 1}]},
            {"items": [{"product_id": 999999, "quantity": 1}]},
            {"items": "nao-e-lista"},
        ]
        for body in bad:
            resp, _ = self.c.request("POST", "/api/orders", body)
            self.assertIn(resp.status, (400, 409), body)

    def test_login_rate_limit(self):
        for _ in range(loja_app.LOGIN_MAX_ATTEMPTS):
            resp, _ = self.c.login("nao-existe@example.com", "senha-errada-xyz")
            self.assertEqual(resp.status, 401)
        resp, _ = self.c.login("nao-existe@example.com", "senha-errada-xyz")
        self.assertEqual(resp.status, 429)

    def test_audit_log_records_security_events(self):
        self.c.login("ninguem@example.com", "senha-errada-xyz")
        events = {r["event"] for r in self.server.conn.execute("SELECT event FROM audit_log").fetchall()}
        self.assertIn("login_failed", events)


if __name__ == "__main__":
    unittest.main()
