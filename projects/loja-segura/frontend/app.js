/* Loja Segura — frontend (vanilla JS).
 *
 * Princípios de segurança aplicados aqui:
 * 1. Nunca usamos innerHTML com dados vindos do servidor ou do usuário.
 *    Tudo é inserido com textContent/createElement -> sem XSS no DOM.
 * 2. O carrinho fica no localStorage apenas como conveniência. O PREÇO e o
 *    ESTOQUE reais são decididos pelo servidor na hora do pedido.
 * 3. Toda requisição que altera estado envia o header X-CSRF-Token.
 * 4. O cookie de sessão é HttpOnly: este script não consegue lê-lo (de propósito).
 */
"use strict";

const state = {
  products: [],
  cart: loadCart(),          // { [productId]: quantity }
  user: null,
  csrfToken: null,
};

// ---------- utilidades ----------

const $ = (sel) => document.querySelector(sel);

function brl(cents) {
  return (cents / 100).toLocaleString("pt-BR", { style: "currency", currency: "BRL" });
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children) node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return node;
}

function flash(message, kind = "ok") {
  const box = $("#flash");
  box.textContent = message;
  box.className = `flash ${kind}`;
  box.hidden = false;
  clearTimeout(flash._t);
  flash._t = setTimeout(() => (box.hidden = true), 5000);
}

async function api(path, { method = "GET", body } = {}) {
  const headers = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && state.csrfToken) headers["X-CSRF-Token"] = state.csrfToken;
  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Erro HTTP ${res.status}`);
  return data;
}

function loadCart() {
  try {
    const parsed = JSON.parse(localStorage.getItem("cart") || "{}");
    // Validação defensiva: só aceitamos inteiros positivos.
    const clean = {};
    for (const [k, v] of Object.entries(parsed)) {
      const id = Number(k), qty = Number(v);
      if (Number.isInteger(id) && id > 0 && Number.isInteger(qty) && qty > 0) clean[id] = Math.min(qty, 99);
    }
    return clean;
  } catch { return {}; }
}

function saveCart() {
  try { localStorage.setItem("cart", JSON.stringify(state.cart)); } catch { /* modo privado etc. */ }
  $("#cart-count").textContent = Object.values(state.cart).reduce((a, b) => a + b, 0);
}

// ---------- navegação ----------

function show(view) {
  for (const id of ["catalog", "cart", "orders", "auth"]) $(`#view-${id}`).hidden = id !== view;
  if (view === "cart") renderCart();
  if (view === "orders") loadOrders();
}

// ---------- catálogo ----------

async function loadProducts() {
  const { products } = await api("/api/products");
  state.products = products;
  const grid = $("#product-grid");
  grid.replaceChildren(...products.map((p) =>
    el("article", { class: "card" },
      el("h3", {}, p.name),
      el("p", {}, p.description),
      el("div", { class: "price" }, brl(p.price_cents)),
      el("div", { class: "stock" }, p.stock > 0 ? `${p.stock} em estoque` : "Esgotado"),
      el("button", { type: "button", class: "primary", disabled: p.stock <= 0,
                     onclick: () => addToCart(p.id) }, "Adicionar"),
    )
  ));
}

function addToCart(id) {
  state.cart[id] = Math.min((state.cart[id] || 0) + 1, 99);
  saveCart();
  flash("Produto adicionado ao carrinho.");
}

// ---------- carrinho ----------

function renderCart() {
  const rows = $("#cart-rows");
  let total = 0;
  const lines = [];
  for (const [idStr, qty] of Object.entries(state.cart)) {
    const p = state.products.find((x) => x.id === Number(idStr));
    if (!p) continue;
    const subtotal = p.price_cents * qty;
    total += subtotal;
    lines.push(el("tr", {},
      el("td", {}, p.name),
      el("td", {}, qty),
      el("td", {}, brl(p.price_cents)),
      el("td", {}, brl(subtotal)),
      el("td", {}, el("button", { type: "button", class: "danger", onclick: () => { delete state.cart[p.id]; saveCart(); renderCart(); } }, "Remover")),
    ));
  }
  rows.replaceChildren(...lines);
  $("#cart-total").textContent = brl(total);
  $("#btn-checkout").disabled = lines.length === 0;
}

async function checkout() {
  if (!state.user) { flash("Entre na sua conta para finalizar a compra.", "error"); show("auth"); return; }
  const items = Object.entries(state.cart).map(([id, qty]) => ({ product_id: Number(id), quantity: qty }));
  try {
    const { order } = await api("/api/orders", { method: "POST", body: { items } });
    state.cart = {}; saveCart();
    flash(`Pedido #${order.id} criado: ${brl(order.total_cents)}.`);
    await loadProducts();
    show("orders");
  } catch (e) { flash(e.message, "error"); }
}

// ---------- pedidos ----------

async function loadOrders() {
  try {
    const { orders } = await api("/api/orders");
    $("#orders-list").replaceChildren(...(orders.length ? orders.map((o) =>
      el("article", { class: "card order" },
        el("h3", {}, `Pedido #${o.id} · ${o.status} · ${brl(o.total_cents)}`),
        el("small", {}, o.created_at + " UTC"),
        el("ul", {}, ...o.items.map((i) => el("li", {}, `${i.quantity}× ${i.name} (${brl(i.unit_price_cents)})`))),
      )) : [el("p", {}, "Você ainda não fez pedidos.")]));
  } catch (e) { flash(e.message, "error"); }
}

// ---------- autenticação ----------

function renderUser() {
  const box = $("#user-box");
  $("#nav-orders").hidden = !state.user;
  if (state.user) {
    box.replaceChildren(
      el("span", {}, state.user.email + " "),
      el("button", { type: "button", class: "link", onclick: logout }, "Sair"),
    );
  } else {
    box.replaceChildren(el("button", { type: "button", class: "link", onclick: () => show("auth") }, "Entrar / Cadastrar"));
  }
}

async function refreshSession() {
  const data = await api("/api/me");
  state.user = data.user;
  state.csrfToken = data.csrf_token || null;
  renderUser();
}

async function login(form) {
  const fd = new FormData(form);
  try {
    const data = await api("/api/auth/login", { method: "POST", body: { email: fd.get("email"), password: fd.get("password") } });
    state.user = data.user; state.csrfToken = data.csrf_token;
    form.reset(); renderUser(); flash("Login realizado."); show("catalog");
  } catch (e) { flash(e.message, "error"); }
}

async function register(form) {
  const fd = new FormData(form);
  try {
    await api("/api/auth/register", { method: "POST", body: { email: fd.get("email"), password: fd.get("password") } });
    form.reset(); flash("Conta criada. Agora faça login.");
  } catch (e) { flash(e.message, "error"); }
}

async function logout() {
  try { await api("/api/auth/logout", { method: "POST" }); } catch { /* sessão já expirada */ }
  state.user = null; state.csrfToken = null;
  renderUser(); flash("Você saiu."); show("catalog");
}

// ---------- inicialização ----------

document.addEventListener("DOMContentLoaded", async () => {
  $("#nav-catalog").addEventListener("click", () => show("catalog"));
  $("#nav-orders").addEventListener("click", () => show("orders"));
  $("#btn-cart").addEventListener("click", () => show("cart"));
  $("#btn-checkout").addEventListener("click", checkout);
  $("#form-login").addEventListener("submit", (e) => { e.preventDefault(); login(e.target); });
  $("#form-register").addEventListener("submit", (e) => { e.preventDefault(); register(e.target); });
  saveCart();
  try {
    await Promise.all([loadProducts(), refreshSession()]);
  } catch (e) { flash(e.message, "error"); }
});
