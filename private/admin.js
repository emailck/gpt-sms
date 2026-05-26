const I18N = {
  zh: { adminTitle: 'GPTSMS 管理后台', adminSub: '配置上游、生成 CDK、查看号码和会话。', front: '前台', token: '管理员 Token', load: '加载后台', config: '配置', accounts: '号码', sessions: '会话', audit: '审计日志', save: '保存', create: '生成', saved: '已保存', created: '已生成' },
  en: { adminTitle: 'GPTSMS Admin', adminSub: 'Configure upstream, generate CDKs, inspect numbers and sessions.', front: 'Home', token: 'Admin Token', load: 'Load Admin', config: 'Config', accounts: 'Numbers', sessions: 'Sessions', audit: 'Audit Logs', save: 'Save', create: 'Create', saved: 'Saved', created: 'Created' },
};

let lang = localStorage.lang || 'zh';
let state = null;
let countries = [];
let presenceHandle = null;
const pageState = {
  cdks: { page: 1, pageSize: 20 },
  accounts: { page: 1, pageSize: 20 },
  audit: { page: 1, pageSize: 20 },
};
const $ = id => document.getElementById(id);

function t(k) { return I18N[lang][k] || k; }
function applyLang() { document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en'; document.querySelectorAll('[data-i18n]').forEach(e => e.textContent = t(e.dataset.i18n)); $('langBtn').textContent = lang === 'zh' ? 'English' : '中文'; }
function toast(msg, bad = false) { const el = $('toast'); el.textContent = msg; el.classList.remove('hidden'); el.style.borderColor = bad ? '#ef4444' : '#334155'; setTimeout(() => el.classList.add('hidden'), 3500); }
async function req(url, opts = {}) { const r = await fetch(url, { credentials: 'same-origin', ...opts, headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) } }); const j = await r.json().catch(() => ({ success: 0, message: 'Bad JSON' })); if (!r.ok || !j.success) throw new Error(j.message || 'Request failed'); return j; }

function normalizeCountryValue(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  const aliases = { IND: 'IN', USA: 'US', UK: 'GB', GBR: 'GB', IDN: 'ID' };
  const aliased = aliases[raw.toUpperCase()];
  if (aliased) return aliased;
  const lower = raw.toLowerCase();
  const hit = countries.find(c => String(c.shortName || '').toLowerCase() === lower || String(c.id || '').toLowerCase() === lower || String(c.name || '').toLowerCase() === lower || `${c.name} ${c.shortName} ${c.id}`.toLowerCase() === lower);
  return hit ? String(hit.shortName || hit.id) : raw;
}

function renderCountryOptions() {
  const dl = $('countryList');
  if (!dl) return;
  dl.innerHTML = countries.map(c => `<option value="${escapeHtml(c.shortName || c.id)}" label="${escapeHtml(`${c.name} (${c.shortName || '-'} / ID ${c.id}${c.cc ? ', +' + c.cc : ''})`)}"></option>`).join('');
  const meta = $('countryMeta');
  const current = normalizeCountryValue($('country')?.value || state?.config?.country || '');
  const hit = countries.find(c => String(c.shortName || c.id).toLowerCase() === String(current).toLowerCase() || String(c.id) === String(current));
  if (meta) meta.textContent = hit ? `${hit.name} / ${hit.shortName} / ID ${hit.id}${hit.cc ? ' / +' + hit.cc : ''}` : (countries.length ? `已缓存 ${countries.length} 个国家，可输入国家名搜索` : '输入国家代码或 ID');
}

async function loadCountries(force = false) {
  try {
    const j = await req(`/api/catalog/countries${force ? '?force=1' : ''}`);
    countries = Array.isArray(j.data) ? j.data : [];
    renderCountryOptions();
    if (force) toast(`国家列表已刷新：${countries.length} 个${j.cached ? '（使用缓存）' : ''}`);
  } catch (e) {
    if (force) toast(e.message, true);
  }
}

async function load(opts = {}) {
  try {
    if ($('token').value) {
      const lr = await fetch('/api/admin/login', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ adminToken: $('token').value }) });
      const lj = await lr.json().catch(() => ({ success: 0, message: 'Login failed' }));
      if (!lr.ok || !lj.success) throw new Error(lj.message || 'Login failed');
      sessionStorage.adminOk = '1';
    }
    state = await req('/api/admin/overview');
    $('main').classList.remove('hidden');
    $('token').value = '';
    render();
    await loadCountries(false);
    startPresenceRefresh();
  } catch (e) {
    if (!opts.silent) toast(e.message, true);
    throw e;
  }
}

async function restoreLogin() { try { await load({ silent: true }); } catch { sessionStorage.removeItem('adminOk'); } }
async function refreshData() { try { await load({ silent: true }); toast('已刷新'); } catch (e) { toast(e.message, true); } }

function renderPresence() {
  const el = $('frontOnline');
  if (el) el.textContent = state?.presence?.frontendOnline ?? 0;
}

async function refreshPresence() {
  try {
    const j = await req('/api/admin/overview');
    state = { ...(state || {}), presence: j.presence };
    renderPresence();
  } catch {}
}

function startPresenceRefresh() {
  clearInterval(presenceHandle);
  presenceHandle = setInterval(refreshPresence, 30000);
}

function render() {
  if (!state) return;
  const c = state.config;
  renderPresence();
  $('balance').textContent = JSON.stringify(state.balance);
  ['country', 'service', 'pool', 'maxPrice', 'pricingOption', 'maxAccountUses', 'successfulReuseThreshold', 'reuseUsedNumbersEnabled', 'timeoutSeconds', 'changeNumberAfterSeconds', 'pollIntervalSeconds', 'resendCooldownSeconds', 'refundRetrySeconds', 'mockMode', 'mockReceiveAfterChecks', 'purchaseEnabled', 'purchaseUrl', 'purchaseTextZh', 'purchaseTextEn'].forEach(k => { $(k).value = c[k] ?? ''; });
  $('apiKey').value = '';
  renderCountryOptions();
  renderStats();
  renderPagedTable('cdks', state.cdks || [], 'cdkRows', x => `<tr><td>${escapeHtml(x.code)}</td><td>${escapeHtml(x.status)}</td><td>${escapeHtml(x.createdAt || '')}</td><td>${escapeHtml(x.usedAt || x.redeemedAt || '')}</td><td>${escapeHtml(x.note || '')}</td><td><button class="secondary" data-redeem="${escapeHtml(x.code)}">核销</button></td></tr>`);
  document.querySelectorAll('[data-redeem]').forEach(b => b.onclick = () => redeemCdks(b.dataset.redeem));
  renderAccountFilter();
  const accountStatus = $('accountStatusFilter')?.value || '';
  const accounts = accountStatus ? state.accounts.filter(x => String(x.status || '') === accountStatus) : state.accounts;
  renderPagedTable('accounts', accounts || [], 'accountRows', x => `<tr><td>${escapeHtml(x.phone || '-')}</td><td>${x.useCount}/${x.maxUses}</td><td>${escapeHtml(x.status)}</td><td>${escapeHtml(x.orderid)}</td><td>${escapeHtml(x.updatedAt || '')}</td></tr>`);
  $('sessionRows').innerHTML = state.sessions.map(x => `<tr><td>${escapeHtml(x.id)}</td><td>${escapeHtml(x.phone || '-')}</td><td>${escapeHtml(x.status)}</td><td>${x.message ? escapeHtml(x.message.text || JSON.stringify(x.message.raw)) : ''}</td><td>${escapeHtml(x.deadlineAt || '')}</td></tr>`).join('');
  $('clientRows').innerHTML = (state.clients || []).map(c => `<tr><td>${escapeHtml(c.name)}</td><td>${escapeHtml(c.apiKeyPrefix || '')}</td><td>${c.balance}</td><td>${c.pricePerSuccess}</td><td>${escapeHtml(c.status)}</td><td><button class="secondary" data-recharge="${escapeHtml(c.id)}">充值</button> <button class="secondary" data-reset-key="${escapeHtml(c.id)}">重置Key</button> <button class="danger" data-toggle-client="${escapeHtml(c.id)}" data-status="${escapeHtml(c.status)}">${c.status === 'active' ? '禁用' : '启用'}</button></td></tr>`).join('');
  document.querySelectorAll('[data-recharge]').forEach(b => b.onclick = () => rechargeClient(b.dataset.recharge));
  document.querySelectorAll('[data-reset-key]').forEach(b => b.onclick = () => resetClientKey(b.dataset.resetKey));
  document.querySelectorAll('[data-toggle-client]').forEach(b => b.onclick = () => toggleClient(b.dataset.toggleClient, b.dataset.status));
  $('billingRows').innerHTML = (state.billingLogs || []).map(x => `<tr><td>${escapeHtml(x.createdAt || '')}</td><td>${escapeHtml(x.clientId || '')}</td><td>${escapeHtml(x.type || '')}</td><td>${escapeHtml(x.amount || '')}</td><td>${escapeHtml((x.balanceBefore ?? '') + ' → ' + (x.balanceAfter ?? ''))}</td><td>${escapeHtml(x.sessionId || '')}</td></tr>`).join('');
  renderPagedTable('audit', state.auditLogs || [], 'auditRows', x => `<tr><td>${escapeHtml(x.createdAt || '')}</td><td>${escapeHtml(x.event || '')}</td><td>${escapeHtml(x.ip || '')}</td><td>${escapeHtml(x.userAgent || '')}</td><td><code>${escapeHtml(JSON.stringify(x.data || {}))}</code></td></tr>`);
}

function renderPagedTable(key, items, tbodyId, rowHtml) {
  const ps = pageState[key];
  if (!ps) return;
  const total = items.length;
  const totalPages = Math.max(1, Math.ceil(total / ps.pageSize));
  ps.page = Math.min(Math.max(Number(ps.page || 1), 1), totalPages);
  const start = (ps.page - 1) * ps.pageSize;
  const pageItems = items.slice(start, start + ps.pageSize);
  $(tbodyId).innerHTML = pageItems.length
    ? pageItems.map(rowHtml).join('')
    : `<tr><td colspan="12" class="muted">暂无数据</td></tr>`;
  renderPager(key, total, totalPages, start, pageItems.length);
}

function renderPager(key, total, totalPages, start, count) {
  const el = $(`${key}Pager`);
  const ps = pageState[key];
  if (!el || !ps) return;
  const from = total ? start + 1 : 0;
  const to = total ? start + count : 0;
  el.innerHTML = `
    <div class="pager-info">第 ${ps.page} / ${totalPages} 页，显示 ${from}-${to}，共 ${total} 条</div>
    <div class="row">
      <select class="pager-size" data-page-size="${key}">
        ${[10, 20, 50, 100].map(n => `<option value="${n}" ${Number(ps.pageSize) === n ? 'selected' : ''}>每页 ${n}</option>`).join('')}
      </select>
      <button class="secondary" data-page="${key}" data-dir="first" ${ps.page <= 1 ? 'disabled' : ''}>首页</button>
      <button class="secondary" data-page="${key}" data-dir="prev" ${ps.page <= 1 ? 'disabled' : ''}>上一页</button>
      <button class="secondary" data-page="${key}" data-dir="next" ${ps.page >= totalPages ? 'disabled' : ''}>下一页</button>
      <button class="secondary" data-page="${key}" data-dir="last" ${ps.page >= totalPages ? 'disabled' : ''}>末页</button>
    </div>`;
  el.querySelectorAll('[data-page]').forEach(b => b.onclick = () => {
    const dir = b.dataset.dir;
    if (dir === 'first') ps.page = 1;
    else if (dir === 'prev') ps.page -= 1;
    else if (dir === 'next') ps.page += 1;
    else if (dir === 'last') ps.page = totalPages;
    render();
  });
  el.querySelectorAll('[data-page-size]').forEach(sel => sel.onchange = () => {
    ps.pageSize = Number(sel.value || 20);
    ps.page = 1;
    render();
  });
}

function renderStats() {
  const stats = state?.stats;
  const daily = Array.isArray(stats?.daily) ? stats.daily : [];
  const totals = stats?.totals || {};
  if (!$('statsRows')) return;
  $('statSessions').textContent = totals.sessions || 0;
  $('statSuccess').textContent = totals.success || 0;
  $('statRate').textContent = `${totals.successRate || 0}%`;
  $('statCharged').textContent = totals.smsCharged || 0;
  $('statsRows').innerHTML = [...daily].reverse().map(x => `<tr><td>${escapeHtml(x.date)}</td><td>${x.sessions}</td><td>${x.success}</td><td>${x.successRate}%</td><td>${x.timeout}</td><td>${x.changed}</td><td>${x.waiting}</td><td>${x.newSessions}</td><td>${x.reusedSessions}</td><td>${x.apiSessions}</td><td>${x.cdkSessions}</td><td>${x.smsCharged}</td></tr>`).join('');
  drawDailyChart(daily);
}

function drawDailyChart(daily) {
  const canvas = $('dailyChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const cssWidth = canvas.clientWidth || 980;
  const cssHeight = 340;
  if (canvas.width !== Math.round(cssWidth * dpr) || canvas.height !== Math.round(cssHeight * dpr)) {
    canvas.width = Math.round(cssWidth * dpr);
    canvas.height = Math.round(cssHeight * dpr);
  }
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, cssWidth, cssHeight);
  const pad = { l: 44, r: 18, t: 18, b: 44 };
  const w = cssWidth - pad.l - pad.r;
  const h = cssHeight - pad.t - pad.b;
  ctx.fillStyle = '#020617';
  ctx.fillRect(0, 0, cssWidth, cssHeight);
  ctx.strokeStyle = '#334155';
  ctx.lineWidth = 1;
  ctx.font = '12px system-ui, -apple-system, Segoe UI, Arial';
  ctx.fillStyle = '#94a3b8';
  const maxCount = Math.max(1, ...daily.flatMap(x => [x.sessions, x.success, x.timeout]));
  const maxMoney = Math.max(1, ...daily.map(x => Math.abs(Number(x.smsCharged || 0))));
  for (let i = 0; i <= 4; i++) {
    const y = pad.t + h - (h * i / 4);
    ctx.beginPath();
    ctx.moveTo(pad.l, y);
    ctx.lineTo(pad.l + w, y);
    ctx.stroke();
    ctx.fillText(String(Math.round(maxCount * i / 4)), 8, y + 4);
  }
  if (!daily.length) {
    ctx.fillText('暂无历史数据', pad.l + 12, pad.t + 24);
    return;
  }
  const step = w / daily.length;
  const barW = Math.max(3, Math.min(18, step * 0.24));
  const yCount = v => pad.t + h - (Number(v || 0) / maxCount) * h;
  const yMoney = v => pad.t + h - (Math.abs(Number(v || 0)) / maxMoney) * h;
  daily.forEach((x, i) => {
    const baseX = pad.l + i * step + step / 2;
    const bars = [
      { v: x.sessions, c: '#38bdf8', off: -barW * 1.1 },
      { v: x.success, c: '#22c55e', off: 0 },
      { v: x.timeout, c: '#ef4444', off: barW * 1.1 },
    ];
    for (const b of bars) {
      const y = yCount(b.v);
      ctx.fillStyle = b.c;
      ctx.fillRect(baseX + b.off - barW / 2, y, barW, pad.t + h - y);
    }
    const my = yMoney(x.smsCharged);
    ctx.fillStyle = '#f59e0b';
    ctx.beginPath();
    ctx.arc(baseX, my, 2.5, 0, Math.PI * 2);
    ctx.fill();
    if (daily.length <= 31 || i % Math.ceil(daily.length / 12) === 0) {
      ctx.fillStyle = '#94a3b8';
      ctx.save();
      ctx.translate(baseX - 8, pad.t + h + 34);
      ctx.rotate(-Math.PI / 5);
      ctx.fillText(String(x.date).slice(5), 0, 0);
      ctx.restore();
    }
  });
  ctx.strokeStyle = '#f59e0b';
  ctx.beginPath();
  daily.forEach((x, i) => {
    const px = pad.l + i * step + step / 2;
    const py = yMoney(x.smsCharged);
    if (i === 0) ctx.moveTo(px, py);
    else ctx.lineTo(px, py);
  });
  ctx.stroke();
}

async function loadStats() {
  try {
    const days = $('statsDays')?.value || 30;
    const j = await req(`/api/admin/stats/daily?days=${encodeURIComponent(days)}`);
    state.stats = j.stats;
    renderStats();
  } catch (e) { toast(e.message, true); }
}

function renderAccountFilter() {
  const sel = $('accountStatusFilter');
  if (!sel || !state) return;
  const current = sel.value || '';
  const statuses = [...new Set((state.accounts || []).map(x => String(x.status || '')).filter(Boolean))].sort();
  sel.innerHTML = '<option value="">全部状态</option>' + statuses.map(s => `<option value="${escapeHtml(s)}">${escapeHtml(s)}</option>`).join('');
  sel.value = statuses.includes(current) ? current : '';
}

function escapeHtml(s) { return String(s).replace(/[&<>"]/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[m])); }

async function saveConfig() {
  try {
    const body = {};
    ['apiKey', 'country', 'service', 'pool', 'maxPrice', 'pricingOption', 'maxAccountUses', 'successfulReuseThreshold', 'reuseUsedNumbersEnabled', 'timeoutSeconds', 'changeNumberAfterSeconds', 'pollIntervalSeconds', 'resendCooldownSeconds', 'refundRetrySeconds', 'mockMode', 'mockReceiveAfterChecks', 'purchaseEnabled', 'purchaseUrl', 'purchaseTextZh', 'purchaseTextEn'].forEach(k => { if (k === 'apiKey' && !$(k).value) return; body[k] = k === 'country' ? normalizeCountryValue($(k).value) : $(k).value; });
    await req('/api/admin/config', { method: 'POST', body: JSON.stringify(body) });
    toast(t('saved'));
    await load();
  } catch (e) { toast(e.message, true); }
}

async function createCdk() { try { const j = await req('/api/admin/cdks', { method: 'POST', body: JSON.stringify({ count: $('cdkCount').value, note: $('cdkNote').value }) }); $('newCdks').textContent = j.cdks.map(x => x.code).join('\n'); toast(t('created')); await load(); } catch (e) { toast(e.message, true); } }
async function createClient() { try { const j = await req('/api/admin/clients', { method: 'POST', body: JSON.stringify({ name: $('clientName').value, balance: $('clientBalance').value, pricePerSuccess: $('clientPrice').value }) }); $('newClientKey').textContent = 'API Key（只显示一次）：\n' + j.client.apiKey; toast('已创建客户'); await load(); } catch (e) { toast(e.message, true); } }
async function rechargeClient(id) { try { const amount = prompt('充值数量，可为负数调整', '10'); if (amount === null) return; await req(`/api/admin/client/${id}/recharge`, { method: 'POST', body: JSON.stringify({ amount }) }); toast('已充值'); await load(); } catch (e) { toast(e.message, true); } }
async function resetClientKey(id) { try { if (!confirm('确定重置 API Key？旧 Key 会立即失效，新 Key 只显示一次。')) return; const j = await req(`/api/admin/client/${id}/reset-key`, { method: 'POST', body: JSON.stringify({}) }); $('newClientKey').textContent = '新 API Key（只显示一次）：\n' + j.client.apiKey; toast('已重置 API Key'); await load(); } catch (e) { toast(e.message, true); } }
async function toggleClient(id, status) { try { await req(`/api/admin/client/${id}/update`, { method: 'POST', body: JSON.stringify({ status: status === 'active' ? 'disabled' : 'active' }) }); toast('已更新'); await load(); } catch (e) { toast(e.message, true); } }
async function redeemCdks(code) { try { const codes = code || $('redeemCdks').value; if (!codes) throw new Error('请输入 CDK'); const j = await req('/api/admin/cdks/redeem', { method: 'POST', body: JSON.stringify({ codes }) }); $('newCdks').textContent = `核销 ${j.redeemed}/${j.requested}，跳过 ${j.skipped}，不存在 ${j.missing}`; if (!code) $('redeemCdks').value = ''; toast('已核销'); await load(); } catch (e) { toast(e.message, true); } }

document.querySelectorAll('.tab').forEach(b => b.onclick = () => { document.querySelectorAll('.tab').forEach(x => x.classList.remove('active')); b.classList.add('active'); document.querySelectorAll('.panel').forEach(p => p.classList.add('hidden')); $('panel-' + b.dataset.tab).classList.remove('hidden'); });
$('loadBtn').onclick = load;
$('refreshBtn').onclick = refreshData;
$('saveConfig').onclick = saveConfig;
$('createCdk').onclick = createCdk;
$('redeemCdkBtn').onclick = () => redeemCdks();
$('createClient').onclick = createClient;
$('refreshCountries').onclick = () => loadCountries(true);
$('country').addEventListener('change', renderCountryOptions);
$('country').addEventListener('input', renderCountryOptions);
$('accountStatusFilter').onchange = () => { pageState.accounts.page = 1; render(); };
$('statsDays').onchange = loadStats;
$('langBtn').onclick = () => { lang = lang === 'zh' ? 'en' : 'zh'; localStorage.lang = lang; applyLang(); };
window.addEventListener('resize', () => { if (state?.stats) drawDailyChart(state.stats.daily || []); });
applyLang();
restoreLogin();
