const state = {
  me: null,
  products: [],
  selectedProduct: null,
  toastTimer: null,
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

document.addEventListener('DOMContentLoaded', init);

async function init() {
  bindEvents();
  try {
    const [me, shop] = await Promise.all([api('/api/me'), api('/api/shop')]);
    state.products = shop.products || [];
    state.me = me;
    await reconcileCachedWallet();
    enterApp();
  } catch (error) {
    if (error.status !== 401) showAuthError(error.message);
    showAuth();
  }
}

function bindEvents() {
  $$('[data-auth-view]').forEach((button) => button.addEventListener('click', () => switchAuth(button.dataset.authView)));
  $('#login-form').addEventListener('submit', (event) => submitCredentials(event, '/api/login'));
  $('#register-form').addEventListener('submit', (event) => submitCredentials(event, '/api/register'));
  $$('.nav-item').forEach((button) => button.addEventListener('click', () => switchScreen(button.dataset.screen)));
  $$('[data-go-shop]').forEach((button) => button.addEventListener('click', () => switchScreen('shop')));
  $('#earn-button').addEventListener('click', earnCoins);
  $('#buy-confirm').addEventListener('click', confirmPurchase);
  $('#settings-open').addEventListener('click', openSettings);
  $('#settings-close').addEventListener('click', () => $('#settings-dialog').close());
  $('#logout-button').addEventListener('click', logout);
  $('#delete-reveal').addEventListener('click', revealDeleteForm);
  $('#delete-cancel').addEventListener('click', hideDeleteForm);
  $('#delete-form').addEventListener('submit', deleteAccount);
  $('#settings-dialog').addEventListener('close', hideDeleteForm);
  window.setInterval(updateCooldown, 250);
}

function switchAuth(view) {
  const login = view === 'login';
  $('#login-form').hidden = !login;
  $('#register-form').hidden = login;
  $('#login-tab').classList.toggle('active', login);
  $('#register-tab').classList.toggle('active', !login);
  $('#login-tab').setAttribute('aria-selected', String(login));
  $('#register-tab').setAttribute('aria-selected', String(!login));
  $('#auth-error').hidden = true;
  const input = $(`#${view}-form input`);
  if (input) input.focus();
}

async function submitCredentials(event, endpoint) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = $('button[type="submit"]', form);
  const data = new FormData(form);
  button.disabled = true;
  $('#auth-error').hidden = true;
  try {
    state.me = await api(endpoint, {
      method: 'POST',
      body: JSON.stringify({ username: data.get('username'), password: data.get('password') }),
    });
    if (!state.products.length) {
      const shop = await api('/api/shop');
      state.products = shop.products || [];
    }
    rememberBalance();
    enterApp();
    form.reset();
  } catch (error) {
    showAuthError(error.message);
  } finally {
    button.disabled = false;
  }
}

function showAuth() {
  $('#app-shell').hidden = true;
  $('#auth-shell').hidden = false;
}

function enterApp() {
  $('#auth-shell').hidden = true;
  $('#app-shell').hidden = false;
  renderAll();
}

function renderAll() {
  if (!state.me) return;
  $('#balance-value').textContent = formatCoins(state.me.balance);
  $('#profile-name').textContent = state.me.username;
  $('#settings-name').textContent = state.me.username;
  const initial = [...state.me.username][0]?.toUpperCase() || 'P';
  $('#avatar').textContent = initial;
  $('#settings-avatar').textContent = initial;
  $('#earn-reward').textContent = `${state.me.earn_reward} монет`;
  $('#earn-button b').textContent = `+${state.me.earn_reward}`;
  renderProducts();
  renderInventory();
  updateCooldown();
  rememberBalance();
}

function renderProducts() {
  const grid = $('#product-grid');
  grid.replaceChildren();
  state.products.forEach((product, index) => {
    const card = document.createElement('article');
    card.className = 'product-card';
    card.dataset.index = String(index + 1).padStart(2, '0');

    const meta = document.createElement('div');
    meta.className = 'product-meta';
    meta.append(textNode(`ITEM / ${String(product.id).padStart(3, '0')}`), textNode(product.rarity));

    const art = createProductArt(product);
    const name = document.createElement('h2');
    name.textContent = product.name;
    const description = document.createElement('p');
    description.textContent = product.description;

    const footer = document.createElement('div');
    footer.className = 'product-footer';
    const price = document.createElement('span');
    price.className = 'price';
    price.append(coinNode(), textNode(formatCoins(product.price)));
    const buy = document.createElement('button');
    buy.type = 'button';
    buy.className = 'buy-button';
    const affordable = state.me.balance >= product.price;
    buy.classList.toggle('cannot-afford', !affordable);
    buy.textContent = affordable ? 'Купить' : 'Не хватает';
    buy.addEventListener('click', () => openPurchase(product));
    footer.append(price, buy);
    card.append(meta, art, name, description, footer);
    grid.append(card);
  });
}

function renderInventory() {
  const grid = $('#inventory-grid');
  const empty = $('#inventory-empty');
  grid.replaceChildren();
  const inventory = state.me.inventory || [];
  empty.hidden = inventory.length > 0;
  grid.hidden = inventory.length === 0;
  inventory.forEach((entry) => {
    const card = document.createElement('article');
    card.className = 'inventory-card';
    const copy = document.createElement('div');
    const name = document.createElement('h2');
    name.textContent = entry.product.name;
    const meta = document.createElement('p');
    meta.textContent = `${entry.product.rarity} · item ${String(entry.product.id).padStart(3, '0')}`;
    copy.append(name, meta);
    const count = document.createElement('span');
    count.className = 'inventory-count';
    count.textContent = `×${entry.count}`;
    card.append(createProductArt(entry.product), copy, count);
    grid.append(card);
  });
}

function createProductArt(product) {
  const art = document.createElement('div');
  art.className = 'product-art';
  art.dataset.art = product.art;
  art.setAttribute('aria-hidden', 'true');
  art.append(document.createElement('i'), document.createElement('b'), document.createElement('span'));
  return art;
}

function openPurchase(product) {
  state.selectedProduct = product;
  $('#buy-name').textContent = product.name;
  $('#buy-description').textContent = product.description;
  $('#buy-price').textContent = formatCoins(product.price);
  $('#buy-art').dataset.art = product.art;
  const confirm = $('#buy-confirm');
  confirm.disabled = state.me.balance < product.price;
  $('span', confirm).textContent = confirm.disabled ? 'Недостаточно монет' : 'Подтвердить';
  $('#buy-dialog').showModal();
}

async function confirmPurchase() {
  if (!state.selectedProduct) return;
  const button = $('#buy-confirm');
  button.disabled = true;
  try {
    state.me = await api('/api/buy', {
      method: 'POST',
      body: JSON.stringify({ item_id: state.selectedProduct.id }),
    });
    $('#buy-dialog').close();
    showToast(`${state.selectedProduct.name} добавлен в инвентарь.`);
    renderAll();
  } catch (error) {
    showToast(error.message, true);
  } finally {
    button.disabled = false;
  }
}

async function earnCoins() {
  const button = $('#earn-button');
  button.disabled = true;
  try {
    state.me = await api('/api/earn', { method: 'POST', body: '{}' });
    showToast(`Начислено ${state.me.earn_reward} монет.`);
    renderAll();
  } catch (error) {
    if (error.payload?.next_earn_at) state.me.next_earn_at = error.payload.next_earn_at;
    showToast(error.message, true);
    updateCooldown();
  }
}

function updateCooldown() {
  if (!state.me) return;
  const now = Date.now() / 1000;
  const remaining = Math.max(0, state.me.next_earn_at - now);
  const cooldown = Math.max(1, state.me.earn_cooldown_seconds || 5);
  const ready = remaining <= 0;
  const button = $('#earn-button');
  button.disabled = !ready;
  $('#cooldown-label').textContent = ready ? 'Узел готов' : `Перезарядка: ${remaining.toFixed(1)} сек.`;
  $('#cooldown-progress').style.transform = `scaleX(${Math.max(0, Math.min(1, 1 - remaining / cooldown))})`;
}

function switchScreen(screen) {
  $$('.screen').forEach((section) => {
    const active = section.id === `screen-${screen}`;
    section.hidden = !active;
    section.classList.toggle('active-screen', active);
  });
  $$('.nav-item').forEach((button) => button.classList.toggle('active', button.dataset.screen === screen));
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function openSettings() {
  $('#settings-error').hidden = true;
  $('#settings-dialog').showModal();
}

async function logout() {
  try {
    await api('/api/logout', { method: 'POST', body: '{}' }, true);
  } finally {
    state.me = null;
    localStorage.removeItem('coinLabCachedBalance');
    $('#settings-dialog').close();
    showAuth();
    showToast('Вы вышли из аккаунта.');
  }
}

function revealDeleteForm() {
  $('#delete-reveal').hidden = true;
  $('#delete-form').hidden = false;
  $('#delete-form input').focus();
}

function hideDeleteForm() {
  $('#delete-reveal').hidden = false;
  $('#delete-form').hidden = true;
  $('#delete-form').reset();
  $('#settings-error').hidden = true;
}

async function deleteAccount(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const password = new FormData(form).get('password');
  const submit = $('button[type="submit"]', form);
  submit.disabled = true;
  try {
    await api('/api/account', { method: 'DELETE', body: JSON.stringify({ password }) }, true);
    state.me = null;
    localStorage.removeItem('coinLabCachedBalance');
    $('#settings-dialog').close();
    showAuth();
    switchAuth('register');
    showToast('Аккаунт и его данные удалены.');
  } catch (error) {
    const target = $('#settings-error');
    target.textContent = error.message;
    target.hidden = false;
  } finally {
    submit.disabled = false;
  }
}

async function reconcileCachedWallet() {
  const cached = Number(localStorage.getItem('coinLabCachedBalance'));
  if (!Number.isSafeInteger(cached) || cached < 0 || cached > 1_000_000) return;
  try {
    state.me = await api('/api/wallet/reconcile', {
      method: 'POST',
      body: JSON.stringify({ reported_balance: cached }),
    });
  } catch (_) {
    // The compatibility sync is best-effort and must not block the shop UI.
  }
}

function rememberBalance() {
  if (state.me) localStorage.setItem('coinLabCachedBalance', String(state.me.balance));
}

async function api(path, options = {}, allowEmpty = false) {
  const response = await fetch(path, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  let payload = null;
  if (response.status !== 204) {
    try { payload = await response.json(); } catch (_) { payload = null; }
  }
  if (!response.ok) {
    const error = new Error(payload?.message || 'Сервер отклонил запрос.');
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return allowEmpty ? payload : payload;
}

function showAuthError(message) {
  const target = $('#auth-error');
  target.textContent = message;
  target.hidden = false;
}

function showToast(message, error = false) {
  const toast = $('#toast');
  window.clearTimeout(state.toastTimer);
  toast.textContent = message;
  toast.classList.toggle('error', error);
  toast.hidden = false;
  state.toastTimer = window.setTimeout(() => { toast.hidden = true; }, 3200);
}

function coinNode() {
  const coin = document.createElement('i');
  coin.className = 'coin-dot';
  coin.setAttribute('aria-hidden', 'true');
  return coin;
}

function textNode(value) {
  const span = document.createElement('span');
  span.textContent = value;
  return span;
}

function formatCoins(value) {
  return new Intl.NumberFormat('ru-RU').format(value || 0);
}
