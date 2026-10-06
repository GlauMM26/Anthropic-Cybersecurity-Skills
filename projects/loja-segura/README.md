# Loja Segura — começo de um site de vendas

Projeto integrador do plano de estudos: um e-commerce mínimo, construído do zero,
com **segurança desde a primeira linha**. Sem frameworks e sem dependências
externas: só Python 3.10+, SQLite, HTML, CSS e JavaScript.

```
Algoritmos → Python → SQL → HTML → JavaScript → HTTP → Segurança
```

## O que já funciona

| Área | Funcionalidade |
|---|---|
| Catálogo | Listagem de produtos com preço e estoque (`GET /api/products`) |
| Conta | Cadastro, login, logout e sessão (`/api/auth/*`, `/api/me`) |
| Carrinho | Carrinho no navegador (localStorage) com validação defensiva |
| Pedido | Checkout transacional com baixa de estoque (`POST /api/orders`) |
| Histórico | Pedidos do usuário logado (`GET /api/orders`) |
| Auditoria | Tabela `audit_log` com eventos de segurança |

## Como rodar

```bash
cd projects/loja-segura
python3 backend/app.py
# abra http://127.0.0.1:8000
```

Variáveis opcionais: `LOJA_HOST`, `LOJA_PORT`, `LOJA_DB_PATH`,
`LOJA_SECURE_COOKIES=1` (ative quando estiver atrás de HTTPS).

Testes (17 casos, incluindo ataques simulados):

```bash
python3 -m unittest discover -s backend/tests -v
```

## Estrutura

```
loja-segura/
├── backend/
│   ├── app.py        # servidor HTTP, rotas, cabeçalhos de segurança, rate limit
│   ├── auth.py       # scrypt, sessões, CSRF, validação de e-mail/senha
│   ├── db.py         # conexão SQLite, init, auditoria
│   ├── schema.sql    # tabelas, constraints, índices
│   ├── seed.sql      # produtos de exemplo
│   └── tests/        # testes de integração (unittest)
├── frontend/
│   ├── index.html    # estrutura semântica, formulários
│   ├── styles.css    # tema claro/escuro, responsivo
│   └── app.js        # fetch, DOM seguro (sem innerHTML), carrinho
└── docs/
    └── analise-de-seguranca.md   # ameaças, controles e o que falta
```

## Mapa pedagógico (Conceito → Sintaxe → Algoritmo → Implementação → Debugging → Projeto → Segurança)

| Etapa | Onde ver no código | O que estudar |
|---|---|---|
| **Algoritmos** | `RateLimiter.allow` em `app.py` | janela deslizante com `deque`: O(1) amortizado por evento |
| **Estruturas de dados** | `normalized: dict[int, int]` em `api_create_order` | agrupar itens repetidos com dicionário em vez de lista O(n²) |
| **Python** | `auth.py` | módulos, exceções próprias, `hashlib`, `hmac`, `secrets`, regex, type hints |
| **SQL** | `schema.sql`, consultas em `app.py` | constraints, FK, índices, JOIN, transação `BEGIN IMMEDIATE`/`COMMIT`/`ROLLBACK` |
| **HTML** | `index.html` | formulários, `autocomplete`, `minlength`, semântica, `aria-live` |
| **JavaScript** | `app.js` | `fetch`, `async/await`, `FormData`, criação de DOM sem `innerHTML`, `localStorage` |
| **HTTP** | `make_handler` em `app.py` | métodos, status codes, cabeçalhos, cookies, `Content-Type` |
| **Debugging** | `log.exception` + `audit_log` | ler logs do servidor e consultar `SELECT * FROM audit_log` |
| **Testes** | `backend/tests/test_api.py` | subir servidor em thread, cliente HTTP com cookies, asserções |

## Exercícios sugeridos (próximos passos)

1. **Algoritmo:** troque a busca linear `state.products.find(...)` em `app.js` por um `Map`; meça a diferença com 10 000 produtos.
2. **SQL:** crie uma `VIEW` com o faturamento por dia e um índice que a acelere. Use `EXPLAIN QUERY PLAN`.
3. **Python:** mova o `RateLimiter` para um módulo próprio e escreva testes unitários isolados (sem servidor).
4. **Segurança:** implemente verificação de e-mail e redefinição de senha com token de uso único e expiração.
5. **Autorização:** adicione a rota `GET /api/admin/orders` só para `role = 'admin'` e escreva o teste que prova que `customer` recebe 403.
6. **Pagamento:** modele a tabela `payments` e a transição de estado `pending → paid` de forma idempotente.
7. **Observabilidade:** envie `audit_log` em JSON para um arquivo e crie uma regra de detecção para “5 `login_failed` do mesmo IP em 1 minuto”.
8. **Pentest em laboratório:** rode OWASP ZAP contra `http://127.0.0.1:8000` e compare o relatório com `docs/analise-de-seguranca.md`.

## Comparação: mesma funcionalidade em outras linguagens

Quando avançar no plano, reimplemente **apenas o backend** e compare:

| | Python (este projeto) | Java (Spring Boot) | JavaScript (Node/Express) |
|---|---|---|---|
| Paradigma | multi, scripts rápidos | OO forte, tipagem estática | event loop, assíncrono |
| Memória | GC, sem controle manual | JVM, GC configurável | V8, GC |
| SQL seguro | `?` do `sqlite3` | `PreparedStatement`/JPA | `?` do `better-sqlite3`, ORM |
| Hash de senha | `hashlib.scrypt` | `BCryptPasswordEncoder`/Argon2 | `argon2`/`bcrypt` |
| Risco típico | deserialização `pickle`, `eval` | desserialização, XXE, Log4Shell | prototype pollution, `eval`, deps NPM |
| Uso ideal | automação, prototipagem, DFIR | sistemas corporativos | APIs e frontends web |
