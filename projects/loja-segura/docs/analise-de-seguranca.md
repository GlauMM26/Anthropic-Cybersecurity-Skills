# Análise de segurança da Loja Segura

Modelo mental: **STRIDE** por componente + checklist **OWASP Top 10 (2021)**.
Para cada ameaça: o controle implementado, onde está, e o teste que o prova.

## Superfície de ataque

```
Browser ──HTTP──▶ app.py (rotas) ──▶ auth.py ──▶ SQLite (loja.db)
   │                 │
   │                 └──▶ frontend/ (arquivos estáticos)
   └── localStorage (carrinho, dado NÃO confiável)
```

Entradas não confiáveis: URL, cabeçalhos, cookies, corpo JSON, localStorage.

## OWASP Top 10 × controles

| # | Categoria | Ameaça concreta aqui | Controle | Teste |
|---|---|---|---|---|
| A01 | Broken Access Control | ver pedidos de outro usuário (IDOR) | `WHERE user_id = ?` em todas as consultas de pedidos | `test_users_cannot_see_each_others_orders` |
| A01 | Broken Access Control | path traversal em arquivos estáticos | `Path.resolve()` + verificação de `parents` | `test_path_traversal_blocked` |
| A01 | CSRF | site malicioso cria pedido com o cookie da vítima | token sincronizado no header `X-CSRF-Token` + `SameSite=Strict` | `test_csrf_token_required_for_state_change` |
| A02 | Cryptographic Failures | vazamento do banco expõe senhas | scrypt com salt aleatório, comparação em tempo constante | `test_passwords_are_hashed_with_scrypt` |
| A02 | Cryptographic Failures | roubo de cookie via JS | `HttpOnly`; `Secure` quando `LOJA_SECURE_COOKIES=1` | `test_session_cookie_flags` |
| A03 | Injection (SQL) | `' OR '1'='1' --` no login | parâmetros `?` em 100 % das consultas | `test_login_sql_injection_is_harmless` |
| A03 | Injection (XSS) | nome de produto com `<script>` | DOM via `textContent`/`createElement`; CSP sem `unsafe-inline` | `test_security_headers_present` |
| A04 | Insecure Design | cliente envia preço 0 | preço lido do banco na transação; campo do cliente ignorado | `test_order_decrements_stock_and_uses_server_price` |
| A04 | Insecure Design | condição de corrida no estoque | `BEGIN IMMEDIATE` + `UPDATE ... WHERE stock >= ?` | `test_order_rejects_insufficient_stock` |
| A05 | Security Misconfiguration | clickjacking, MIME sniffing, banner | `X-Frame-Options`, `nosniff`, `Server` sem versão | `test_security_headers_present` |
| A07 | Identification & Auth Failures | força bruta no login | rate limit por IP (10 / 5 min) | `test_login_rate_limit` |
| A07 | Identification & Auth Failures | enumeração de usuários | mensagens genéricas + hash fantasma para tempo constante | `test_duplicate_email_does_not_leak_existence` |
| A07 | Identification & Auth Failures | session fixation | sessão antiga destruída e nova criada no login | (exercício: escreva o teste) |
| A08 | Software & Data Integrity | dependência comprometida | zero dependências externas; CSP bloqueia scripts de terceiros | n/a |
| A09 | Logging & Monitoring Failures | ataque passa despercebido | `audit_log` com `login_failed`, `csrf_rejected`, `login_rate_limited` | `test_audit_log_records_security_events` |
| A10 | SSRF | n/a | o servidor não faz requisições de saída | n/a |

## Validação de entrada (defesa em profundidade)

1. **Browser:** `type="email"`, `minlength`, `maxlength` (apenas usabilidade, atacante ignora).
2. **Servidor:** `Content-Type` obrigatório, corpo ≤ 64 KB, JSON precisa ser objeto, tipos estritos (`bool` não é `int`), limites de quantidade.
3. **Banco:** `CHECK`, `NOT NULL`, `UNIQUE`, chaves estrangeiras.

Se uma camada falhar, a próxima segura.

## O que ainda falta (riscos aceitos no laboratório)

| Risco | Por que ainda não | Como fechar |
|---|---|---|
| Sem HTTPS | servidor de estudo em `127.0.0.1` | proxy reverso (nginx/Caddy) com TLS; `LOJA_SECURE_COOKIES=1`; HSTS |
| Rate limit em memória | único processo | Redis ou WAF; limitar também por conta, não só por IP |
| Sem verificação de e-mail / 2FA | escopo inicial | token de uso único; TOTP ou WebAuthn (há até um produto FIDO2 no catálogo) |
| Sem papel admin em uso | escopo inicial | rotas `/api/admin/*` com checagem de `role` e testes negativos |
| Sem pagamento | escopo inicial | gateway externo; nunca armazenar dados de cartão (PCI DSS) |
| Senha sem checagem contra vazamentos | sem rede de saída | API Have I Been Pwned com k-anonymity |
| SQLite + lock global | simplicidade | PostgreSQL com pool; remover `_db_lock` |
| Logs em texto | laboratório | JSON estruturado → SIEM; regra Sigma para brute force |

## Como atacar este projeto (laboratório)

Use só contra a sua própria instância local.

```bash
# SQL injection no login
curl -s -X POST http://127.0.0.1:8000/api/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"'"'"' OR 1=1 --","password":"x"}'

# CSRF: POST com cookie mas sem token
curl -s -X POST http://127.0.0.1:8000/api/orders -H 'Content-Type: application/json' \
  -b 'session=COLE_AQUI' -d '{"items":[{"product_id":1,"quantity":1}]}'

# Path traversal
curl -s --path-as-is http://127.0.0.1:8000/../backend/app.py

# Força bruta (deve retornar 429 após 10 tentativas)
for i in $(seq 1 12); do curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  http://127.0.0.1:8000/api/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"a@b.co","password":"errada-errada"}'; done
```

Depois, abra `loja.db` com `sqlite3` e leia `audit_log`: cada ataque deixou rastro.
