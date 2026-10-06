-- Esquema do banco da Loja Segura (SQLite)
-- Nível 2 (SQL) + Nível 4 (Segurança): constraints, chaves estrangeiras e índices
-- são a primeira linha de defesa contra dados inválidos.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    -- Nunca guardamos a senha. Guardamos salt + hash scrypt (ver auth.py).
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'customer'
                          CHECK (role IN ('customer', 'admin')),
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sku         TEXT    NOT NULL UNIQUE,
    name        TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    description TEXT    NOT NULL DEFAULT '',
    -- Preço em centavos (inteiro). Evita erros de ponto flutuante em dinheiro.
    price_cents INTEGER NOT NULL CHECK (price_cents >= 0),
    stock       INTEGER NOT NULL DEFAULT 0 CHECK (stock >= 0),
    active      INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
);

CREATE TABLE IF NOT EXISTS orders (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    status      TEXT    NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'paid', 'shipped', 'cancelled')),
    total_cents INTEGER NOT NULL CHECK (total_cents >= 0),
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS order_items (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id        INTEGER NOT NULL REFERENCES orders(id)   ON DELETE CASCADE,
    product_id      INTEGER NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    quantity        INTEGER NOT NULL CHECK (quantity > 0),
    -- Preço "congelado" no momento da compra: se o produto mudar de preço
    -- depois, o histórico do pedido continua correto.
    unit_price_cents INTEGER NOT NULL CHECK (unit_price_cents >= 0)
);

-- Sessões no servidor: o cookie carrega só um identificador aleatório,
-- nunca dados do usuário (evita adulteração do lado do cliente).
CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT    NOT NULL
);

-- Trilha de auditoria: quem fez o quê e quando (base para SOC/DFIR, Nível 6).
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         TEXT    NOT NULL DEFAULT (datetime('now')),
    user_id    INTEGER,
    ip         TEXT,
    event      TEXT    NOT NULL,
    detail     TEXT
);

CREATE INDEX IF NOT EXISTS idx_orders_user       ON orders(user_id);
CREATE INDEX IF NOT EXISTS idx_order_items_order ON order_items(order_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires  ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_event       ON audit_log(event, at);
