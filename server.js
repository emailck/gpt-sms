import express from 'express';
import path from 'node:path';
import fs from 'node:fs';
import { createHash, createHmac, timingSafeEqual, randomBytes } from 'node:crypto';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import { transact, readDb, writeDb, makeId, makeCdk, nowIso, addSecondsIso, safeConfig, getRuntimeConfig, storeApiKey } from './src/db.js';
import { getBalance, listCountries, listServices, listPools, getPrice, getStock, purchaseSms, checkSms, cancelSms, resendSms, retrieveValidPools, SmsPoolError } from './src/smspool.js';
import { encryptSecret, decryptSecret } from './src/crypto.js';

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const IS_PROD = process.env.NODE_ENV === 'production';
const HOST = process.env.HOST || '127.0.0.1';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || (IS_PROD ? '' : 'change-this-admin-token');
const APP_SECRET = process.env.APP_SECRET || (IS_PROD ? '' : ADMIN_TOKEN);
if (IS_PROD) {
  const weakSecrets = new Set(['', 'change-this-admin-token', 'change-this-app-secret', 'dev-secret-change-me']);
  if (weakSecrets.has(ADMIN_TOKEN) || weakSecrets.has(APP_SECRET) || ADMIN_TOKEN === APP_SECRET) {
    throw new Error('Production requires strong, distinct ADMIN_TOKEN and APP_SECRET values');
  }
}
const ADMIN_PATH = process.env.ADMIN_PATH || '/manage-' + createHash('sha256').update(ADMIN_TOKEN).digest('hex').slice(0, 12);

app.disable('x-powered-by');
if (process.env.TRUST_PROXY || IS_PROD) {
  app.set('trust proxy', process.env.TRUST_PROXY ? Number(process.env.TRUST_PROXY) || process.env.TRUST_PROXY : 1);
}
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], objectSrc: ["'none'"], baseUri: ["'self'"] } } }));
app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: true, limit: '64kb' }));
app.use(cookieParser());
app.use('/api/cdk', rateLimit({ windowMs: 60_000, limit: 10, standardHeaders: true, legacyHeaders: false }));
app.use('/api/session', rateLimit({ windowMs: 60_000, limit: 90, standardHeaders: true, legacyHeaders: false }));
app.use('/api/v1', rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false }));
app.use('/api/admin/login', rateLimit({ windowMs: 15 * 60_000, limit: 8, standardHeaders: true, legacyHeaders: false }));
app.use('/api/admin', rateLimit({ windowMs: 60_000, limit: 60, standardHeaders: true, legacyHeaders: false }));
app.use(express.static(path.resolve('public'), { dotfiles: 'deny', index: 'index.html', extensions: ['html'] }));
app.use('/api', (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });

const COUNTRY_CACHE_PATH = path.resolve(process.env.COUNTRY_CACHE_PATH || './data/catalog-countries.json');
const COUNTRY_CACHE_TTL_MS = Number(process.env.COUNTRY_CACHE_TTL_SECONDS || 24 * 60 * 60) * 1000;

function normalizeCountries(raw) {
  const arr = Array.isArray(raw) ? raw : (Array.isArray(raw?.data) ? raw.data : []);
  return arr.map(x => ({
    id: x.ID ?? x.id ?? x.country_id ?? '',
    name: String(x.name ?? x.country ?? '').trim(),
    shortName: String(x.short_name ?? x.shortName ?? x.iso ?? '').trim(),
    cc: String(x.cc ?? x.phone_code ?? '').trim(),
    region: String(x.region ?? '').trim(),
  })).filter(x => x.id !== '' && x.name);
}

function readCountryCache() {
  try {
    if (!fs.existsSync(COUNTRY_CACHE_PATH)) return null;
    const cache = JSON.parse(fs.readFileSync(COUNTRY_CACHE_PATH, 'utf8'));
    if (!Array.isArray(cache.data)) return null;
    return cache;
  } catch { return null; }
}

function writeCountryCache(data) {
  fs.mkdirSync(path.dirname(COUNTRY_CACHE_PATH), { recursive: true });
  const tmp = `${COUNTRY_CACHE_PATH}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ updatedAt: nowIso(), data }, null, 2));
  fs.renameSync(tmp, COUNTRY_CACHE_PATH);
}

async function getCachedCountries(config, { force = false } = {}) {
  const cache = readCountryCache();
  const fresh = cache?.updatedAt && (Date.now() - Date.parse(cache.updatedAt) < COUNTRY_CACHE_TTL_MS);
  if (!force && cache?.data?.length && fresh) return { data: cache.data, cached: true, updatedAt: cache.updatedAt };
  try {
    const data = normalizeCountries(await listCountries(config));
    if (data.length) {
      const updatedAt = nowIso();
      fs.mkdirSync(path.dirname(COUNTRY_CACHE_PATH), { recursive: true });
      const tmp = `${COUNTRY_CACHE_PATH}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify({ updatedAt, data }, null, 2));
      fs.renameSync(tmp, COUNTRY_CACHE_PATH);
      return { data, cached: false, updatedAt };
    }
    throw new Error('上游国家列表为空');
  } catch (e) {
    if (cache?.data?.length) return { data: cache.data, cached: true, stale: true, updatedAt: cache.updatedAt, warning: e.message };
    throw e;
  }
}

function hashApiKey(key) {
  return createHash('sha256').update(String(key || '')).digest('hex');
}

function makeApiKey() {
  return `gptsms_live_${randomBytes(24).toString('base64url')}`;
}

function publicClient(client, { revealKey = false } = {}) {
  return {
    id: client.id,
    name: client.name || '',
    apiKeyPrefix: client.apiKeyPrefix || '',
    apiKey: revealKey ? client.apiKey : undefined,
    status: client.status || 'active',
    balance: Number(client.balance || 0),
    pricePerSuccess: Number(client.pricePerSuccess || 1),
    createdAt: client.createdAt,
    updatedAt: client.updatedAt,
  };
}

function clientFromAuth(req) {
  const auth = String(req.get('authorization') || '');
  const m = auth.match(/^Bearer\s+(.+)$/i);
  const key = m ? m[1].trim() : '';
  if (!key) return null;
  const keyHash = hashApiKey(key);
  const db = readDb();
  const client = (db.clients || []).find(c => c.apiKeyHash === keyHash);
  return client ? { db, client } : null;
}

function auditApi(req, event, data = {}) {
  try { transact(db => audit(db, req, event, { path: req.path, method: req.method, clientId: req.apiClient?.id, ...data })); } catch {}
}

function requireApiClient(req, res, next) {
  const found = clientFromAuth(req);
  if (!found) {
    const auth = String(req.get('authorization') || '');
    auditApi(req, 'api.auth_failed', { hasAuthorization: !!auth, keyPrefix: auth.replace(/^Bearer\s+/i, '').slice(0, 22) || '' });
    return res.status(401).json({ success: 0, code: 'INVALID_AUTH', message: '认证失败' });
  }
  if ((found.client.status || 'active') !== 'active') {
    req.apiClient = found.client;
    auditApi(req, 'api.client_disabled', { status: found.client.status || 'disabled' });
    return res.status(403).json({ success: 0, code: 'CLIENT_DISABLED', message: '客户已禁用' });
  }
  req.apiClient = found.client;
  next();
}

function ensureClientBalance(client) {
  if (Number(client.balance || 0) < Number(client.pricePerSuccess || 1)) {
    const err = new Error('余额不足');
    err.status = 402;
    err.code = 'INSUFFICIENT_BALANCE';
    err.publicMessage = true;
    throw err;
  }
}

function apiSessionPayload(session, account, client = null) {
  const cfg = readDb().config;
  const payload = frontendSessionPayload(session, account, cfg);
  const msg = session?.message?.text || '';
  const code = msg.match(/\b\d{4,8}\b/)?.[0] || '';
  return {
    sessionId: session.id,
    sessionToken: undefined,
    phone: account?.phone || session.phone || '',
    status: payload.session.status,
    received: payload.session.status === 'received' || !!session.counted,
    reused: !!session.reused,
    expiresAt: payload.session.deadlineAt,
    canChangeAt: payload.session.canChangeAt,
    canChange: payload.session.canChange,
    externalId: session.externalId || '',
    message: msg || undefined,
    code: code || undefined,
    receivedAt: session.receivedAt || session.message?.receivedAt || undefined,
    billing: client ? billingPayload(client, session) : undefined,
  };
}

function billingPayload(client, session) {
  return {
    charged: false,
    alreadyCharged: !!session.billed,
    amount: Number(session.billAmount || client.pricePerSuccess || 1),
    balance: Number(client.balance || 0),
    billingId: session.billingId || null,
  };
}

function chargeClientForSession(db, session, account) {
  if (!session.clientId || session.billed) return null;
  const client = (db.clients || []).find(c => c.id === session.clientId);
  if (!client || (client.status || 'active') !== 'active') return null;
  const amount = Number(client.pricePerSuccess || 1);
  const before = Number(client.balance || 0);
  if (before < amount) {
    session.billingError = 'INSUFFICIENT_BALANCE';
    return null;
  }
  const bill = {
    id: makeId('bill'),
    clientId: client.id,
    sessionId: session.id,
    externalId: session.externalId || '',
    phone: account?.phone || session.phone || '',
    type: 'sms_success',
    amount: -amount,
    balanceBefore: before,
    balanceAfter: before - amount,
    createdAt: nowIso(),
  };
  client.balance = before - amount;
  client.updatedAt = bill.createdAt;
  session.billed = true;
  session.billingId = bill.id;
  session.billAmount = amount;
  db.billingLogs.unshift(bill);
  return { bill, client };
}

function randomToken() {
  return makeId('tok');
}

function hashToken(token) {
  return createHmac('sha256', APP_SECRET).update(String(token)).digest('hex');
}

function sessionTokenFromSession(session) {
  try {
    const token = decryptSecret(session?.sessionTokenEncrypted || '');
    return token && hashToken(token) === session?.sessionTokenHash ? token : '';
  } catch { return ''; }
}

function recoverOrRotateSessionToken(sessionId, req = null) {
  const snapshot = readDb();
  const existing = snapshot.sessions.find(s => s.id === sessionId);
  const recovered = sessionTokenFromSession(existing);
  if (recovered) return recovered;
  const sessionToken = randomToken();
  transact(db => {
    const s = db.sessions.find(x => x.id === sessionId);
    if (!s) return;
    s.sessionTokenHash = hashToken(sessionToken);
    s.sessionTokenEncrypted = encryptSecret(sessionToken);
    s.updatedAt = nowIso();
    audit(db, req, 'api.session_token_rotated', { clientId: s.clientId || null, sessionId: s.id, externalId: s.externalId || '' });
  });
  return sessionToken;
}

function verifySessionAccess(req, session) {
  const token = req.get('x-session-token');
  return !!token && !!session?.sessionTokenHash && hashToken(token) === session.sessionTokenHash;
}

function maskPhone(phone = '') {
  const s = String(phone || '');
  if (s.length <= 4) return s ? '****' : '';
  return `${s.slice(0, 3)}****${s.slice(-4)}`;
}

function maskOrderId(orderid = '') {
  const s = String(orderid || '');
  if (s.length <= 6) return s ? '***' : '';
  return `${s.slice(0, 3)}***${s.slice(-3)}`;
}

function scrubSensitive(value) {
  if (Array.isArray(value)) return value.map(scrubSensitive);
  if (!value || typeof value !== 'object') return value;
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (/key|token|secret|password/i.test(k)) out[k] = '********';
    else if (/phone|number|msisdn|phonenumber|full_number/i.test(k)) out[k] = maskPhone(v);
    else if (/order/i.test(k)) out[k] = maskOrderId(v);
    else out[k] = scrubSensitive(v);
  }
  return out;
}


function sameOrigin(req) {
  const origin = req.get('origin');
  if (!origin) return true;
  const host = req.get('host');
  try { return new URL(origin).host === host; } catch { return false; }
}

function requireSameOrigin(req, res, next) {
  if (sameOrigin(req)) return next();
  transact(db => audit(db, req, 'security.bad_origin', { path: req.path, origin: req.get('origin') || '' }));
  return res.status(403).json({ success: 0, message: '请求无效，请刷新页面后重试' });
}

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}

function signAdminToken(ts) {
  return createHmac('sha256', APP_SECRET).update(String(ts)).digest('hex');
}

function makeAdminCookie() {
  const ts = Date.now();
  return `${ts}.${signAdminToken(ts)}`;
}

function verifyAdminCookie(value) {
  if (!value) return false;
  const [ts, sig] = String(value).split('.');
  if (!ts || !sig) return false;
  if (Date.now() - Number(ts) > 12 * 60 * 60 * 1000) return false;
  return safeEqual(sig, signAdminToken(ts));
}

function requireAdmin(req, res, next) {
  if (verifyAdminCookie(req.cookies?.admin_session)) return next();
  return res.status(401).json({ success: 0, message: '认证失败' });
}

function requireFields(body, fields) {
  for (const f of fields) {
    if (body[f] === undefined || body[f] === null || String(body[f]).trim() === '') {
      const err = new Error(`缺少参数: ${f}`);
      err.status = 400;
      throw err;
    }
  }
}

function maskCdk(code = '') {
  return code.length > 10 ? `${code.slice(0, 8)}...${code.slice(-4)}` : code;
}

function publicCdk(cdk, { admin = false } = {}) {
  return {
    code: admin ? cdk.code : maskCdk(cdk.code),
    status: cdk.status || 'active',
    createdAt: cdk.createdAt,
    usedAt: cdk.usedAt || null,
    usedSessionId: admin ? (cdk.usedSessionId || null) : null,
    note: cdk.note || '',
  };
}

function publicAccount(account, { admin = false, revealPhone = false } = {}) {
  return {
    id: admin ? account.id : undefined,
    orderid: admin ? account.orderid : undefined,
    phone: admin || revealPhone ? account.phone : maskPhone(account.phone),
    country: admin ? account.country : undefined,
    service: admin ? account.service : undefined,
    pool: admin ? (account.pool || '') : undefined,
    useCount: admin ? Number(account.useCount || 0) : undefined,
    maxUses: admin ? Number(account.maxUses || 3) : undefined,
    status: account.status,
    source: admin ? (account.source || 'new') : undefined,
    resendCooldownUntil: admin ? (account.resendCooldownUntil || null) : undefined,
    resendError: admin ? (account.resendError || null) : undefined,
    lastMessageAt: account.lastMessageAt || null,
    createdAt: admin ? account.createdAt : undefined,
    updatedAt: admin ? account.updatedAt : undefined,
  };
}

function publicSession(session, account, { admin = false, revealPhone = false } = {}) {
  return {
    id: session.id,
    cdk: admin ? (session.clientId ? '' : session.cdk) : maskCdk(session.cdk),
    accountId: admin ? session.accountId : undefined,
    orderid: admin ? (account?.orderid || session.orderid || '') : undefined,
    phone: admin || revealPhone ? (account?.phone || session.phone || '') : maskPhone(account?.phone || session.phone || ''),
    country: admin ? (account?.country || session.country) : undefined,
    service: admin ? (account?.service || session.service) : undefined,
    pool: admin ? (account?.pool || session.pool || '') : undefined,
    status: session.status,
    message: session.message
      ? (admin
        ? { ...session.message, raw: session.message.raw }
        : { text: session.message.text || '', receivedAt: session.message.receivedAt || session.receivedAt || null })
      : null,
    counted: !!session.counted,
    deadlineAt: session.deadlineAt,
    createdAt: session.createdAt,
    updatedAt: session.updatedAt,
    reused: admin ? !!session.reused : undefined,
    refundStatus: admin ? (session.refundStatus || null) : undefined,
    clientId: admin ? (session.clientId || null) : undefined,
    externalId: admin ? (session.externalId || '') : undefined,
    billed: admin ? !!session.billed : undefined,
    billingId: admin ? (session.billingId || null) : undefined,
  };
}

function addSecondsIsoFrom(iso, seconds) {
  return new Date(new Date(iso).getTime() + Number(seconds) * 1000).toISOString();
}

function frontendAccount(account) {
  return {
    phone: account?.phone || '',
  };
}

function frontendSession(session, config = readDb().config) {
  return {
    id: session.id,
    status: session.status,
    deadlineAt: session.deadlineAt,
    canChangeAt: addSecondsIsoFrom(session.createdAt, config.changeNumberAfterSeconds || 120),
    canChange: canChangeSession(session, config),
    message: session.message ? { text: session.message.text || '' } : null,
  };
}

function canChangeSession(session, config) {
  if (!session || session.status !== 'waiting' || session.counted) return false;
  const seconds = Number(config.changeNumberAfterSeconds || 120);
  return Date.now() >= new Date(session.createdAt).getTime() + seconds * 1000;
}

function frontendRecord(session, account) {
  return {
    phone: account?.phone || session.phone || '',
    status: session.status,
    messageText: session.message?.text || '',
    receivedAt: session.receivedAt || session.message?.receivedAt || '',
  };
}

function frontendSessionPayload(session, account, config = readDb().config) {
  return {
    account: frontendAccount(account),
    session: frontendSession(session, config),
    reused: !!session?.reused,
  };
}


function clientIp(req) {
  return req.ip || req.socket?.remoteAddress || '';
}

function userAgent(req) {
  return String(req.get('user-agent') || '').slice(0, 240);
}

function audit(db, req, event, data = {}) {
  db.auditLogs ||= [];
  db.auditLogs.unshift({
    id: makeId('audit'),
    event,
    ip: req ? clientIp(req) : '',
    userAgent: req ? userAgent(req) : '',
    data: scrubSensitive(data),
    createdAt: nowIso(),
  });
  db.auditLogs = db.auditLogs.slice(0, 5000);
}

function extractOrderId(upstream) {
  return upstream?.order_id || upstream?.orderid || upstream?.order_code || upstream?.id || upstream?.order || upstream?.request_id || '';
}

function extractPhone(upstream) {
  return upstream?.phonenumber || upstream?.phone || upstream?.number || upstream?.msisdn || upstream?.full_number || '';
}

function isSuccessFlagFalse(data) {
  return data && typeof data === 'object' && (data.success === 0 || data.success === false) && !extractMessage(data);
}

function extractMessage(data) {
  if (!data || typeof data !== 'object') return null;

  const status = Number(data.status);
  const genericMessage = String(data.message || '');
  const systemLike = /refund|refunded|cancel|cancelled|wait|waiting|pending|not received|no sms|not.*ready|expired|timeout|error|failed/i;

  // SMSPool may return operational text in `message` (for example refunded/cancelled).
  // Never count those as a received SMS.
  if (status && [0, 1, 2, 4, 5, 6, 7, 8, 9].includes(status) && systemLike.test(genericMessage)) return null;
  if (systemLike.test(genericMessage) && !data.sms && !data.full_sms && !data.code && !data.pin && !data.otp) return null;

  const candidates = [data.sms, data.full_sms, data.code, data.pin, data.otp, data.text];
  for (const item of candidates) {
    if (item === undefined || item === null || item === '') continue;
    const text = typeof item === 'string' ? item : JSON.stringify(item);
    if (systemLike.test(text)) continue;
    return { raw: data, text, receivedAt: nowIso() };
  }

  // Only use `message` as SMS content if it looks like an actual verification text.
  if (genericMessage && /\b\d{4,8}\b|code|验证码|verification|otp/i.test(genericMessage) && !systemLike.test(genericMessage)) {
    return { raw: data, text: genericMessage, receivedAt: nowIso() };
  }

  if (Array.isArray(data.messages) && data.messages.length) {
    return { raw: data, text: JSON.stringify(data.messages[0]), receivedAt: nowIso() };
  }
  return null;
}

const BUSY_ACCOUNT_STATUSES = new Set(['waiting', 'resending']);
const TERMINAL_ACCOUNT_STATUSES = new Set(['failed', 'refund_pending', 'refunded', 'used_up']);

function accountMaxUses(account, config) {
  return Number(account?.maxUses || config.maxAccountUses || 3);
}

function cooldownReusedAccount(account, config) {
  if (!account) return;
  account.status = Number(account.useCount || 0) >= accountMaxUses(account, config) ? 'used_up' : 'available';
  account.resendCooldownUntil = addSecondsIso(config.resendCooldownSeconds || 300);
  account.updatedAt = nowIso();
  delete account.resendError;
}

function accountMatchesConfig(account, config) {
  const configuredPool = String(config.pool || '').trim();
  const poolMatches = (accountPool) => !configuredPool || configuredPool.toLowerCase() === 'auto' || String(accountPool || '') === configuredPool;
  return String(account.country) === String(config.country) &&
    String(account.service) === String(config.service) &&
    poolMatches(account.pool);
}

function countReusablePoolAccounts(db, config) {
  return db.accounts.filter(a =>
    accountMatchesConfig(a, config) &&
    a.orderid &&
    !TERMINAL_ACCOUNT_STATUSES.has(String(a.status || 'available')) &&
    Number(a.useCount || 0) < accountMaxUses(a, config)
  ).length;
}

function reusableSuccessfulAccounts(db, config) {
  return db.accounts.filter(a =>
    accountMatchesConfig(a, config) &&
    ['available', 'resend_failed'].includes(String(a.status || 'available')) &&
    !BUSY_ACCOUNT_STATUSES.has(String(a.status || 'available')) &&
    (!a.resendCooldownUntil || Date.now() > new Date(a.resendCooldownUntil).getTime()) &&
    Number(a.useCount || 0) > 0 &&
    Number(a.useCount || 0) < accountMaxUses(a, config) &&
    a.orderid
  );
}

function isRetryCdk(db, cdkCode) {
  return db.sessions.some(s => String(s.cdk || '').toUpperCase() === cdkCode && ['timeout', 'changed'].includes(String(s.status || '')));
}

function findReusableAccount(db, config, { cdkCode = '', forceReuse = false } = {}) {
  if (config.reuseUsedNumbersEnabled === false || String(config.reuseUsedNumbersEnabled).toLowerCase() === 'false') return null;
  const successfulAccounts = reusableSuccessfulAccounts(db, config);
  const successfulReuseThreshold = Number(config.successfulReuseThreshold ?? process.env.SUCCESSFUL_REUSE_THRESHOLD ?? 5);
  const retryFlow = forceReuse || isRetryCdk(db, cdkCode);

  // Retry flows always prefer proven numbers. First-time flows buy fresh numbers
  // until successful reusable numbers reach the configured threshold.
  if (!retryFlow && successfulAccounts.length < successfulReuseThreshold) return null;

  return successfulAccounts
    .sort((a, b) => Number(b.useCount || 0) - Number(a.useCount || 0) || String(a.createdAt).localeCompare(String(b.createdAt)))[0];
}

function expireStaleWaitingSessions(db, config) {
  const now = Date.now();
  let changed = false;
  for (const session of db.sessions || []) {
    if (session.status !== 'waiting') continue;
    if (!session.deadlineAt || now <= new Date(session.deadlineAt).getTime()) continue;

    const account = db.accounts.find(a => a.id === session.accountId);
    const cdk = db.cdks.find(c => String(c.code || '').toUpperCase() === String(session.cdk || '').toUpperCase());
    session.status = 'timeout';
    session.updatedAt = nowIso();
    if (cdk && cdk.status === 'reserved' && cdk.reservedSessionId === session.id) {
      cdk.status = 'active';
      cdk.reservedSessionId = null;
      cdk.reservedAt = null;
    }
    if (account) {
      if (Number(account.useCount || 0) === 0 && !session.reused) {
        account.status = 'failed';
      } else if (session.reused || Number(account.useCount || 0) > 0) {
        cooldownReusedAccount(account, config);
      }
    }
    changed = true;
  }
  return changed;
}

function reserveReusableAccountForResend(cdkCode, config, opts = {}) {
  return transact(wdb => {
    expireStaleWaitingSessions(wdb, config);
    const c = opts.virtualCdk || wdb.cdks.find(x => x.code.toUpperCase() === cdkCode);
    if (!c || (c.status || 'active') !== 'active') throw Object.assign(new Error('CDK 不可用'), { status: 400 });
    const reusable = findReusableAccount(wdb, config, { cdkCode });
    if (!reusable) return null;
    const ts = nowIso();
    reusable.status = 'resending';
    reusable.resendingAt = ts;
    reusable.updatedAt = ts;
    if (!opts.virtualCdk) {
      c.status = 'resending';
      c.reservedAt = ts;
      c.reservedAccountId = reusable.id;
    }
    return { ...reusable };
  });
}


function isPoolTemporarilyUnavailableError(err) {
  const txt = JSON.stringify(err?.details || {}) + ' ' + String(err?.message || '');
  return /PORT_OCCUPIED|OUT_OF_STOCK|available slots are currently occupied|couldn't find an available phone number|try again in 5 minutes/i.test(txt);
}

function retryAfterSecondsFromError(err, fallback = 300) {
  const txt = JSON.stringify(err?.details || {}) + ' ' + String(err?.message || '');
  const m = txt.match(/try again later in\s+(\d+)\s+seconds/i) || txt.match(/try again in\s+(\d+)\s+seconds/i);
  return m ? Math.max(Number(m[1]), 60) : fallback;
}

function isPhoneUnavailableError(err) {
  const txt = JSON.stringify(err?.details || {}) + ' ' + String(err?.message || '');
  return /phonenumber is not available|try again later in\s+\d+\s+seconds/i.test(txt);
}

function poolIdOf(item) {
  if (item === null || item === undefined) return '';
  if (typeof item === 'string' || typeof item === 'number') return String(item);
  return String(item.id ?? item.pool ?? item.pool_id ?? item.value ?? item.name ?? '');
}

async function buildPoolCandidates(config) {
  const configured = String(config.pool || '').trim();
  if (configured && configured.toLowerCase() !== 'auto') return [configured];
  const raw = await retrieveValidPools(config, { country: config.country, service: config.service });
  const arr = Array.isArray(raw) ? raw : (Array.isArray(raw?.data) ? raw.data : (Array.isArray(raw?.pools) ? raw.pools : []));
  const ids = [...new Set(arr.map(poolIdOf).filter(Boolean))];
  return ids.length ? ids : [''];
}

async function purchaseSmsAuto(config) {
  const candidates = await buildPoolCandidates(config);
  const errors = [];
  for (const pool of candidates) {
    try {
      const upstream = await purchaseSms(config, {
        country: config.country,
        service: config.service,
        pool,
        max_price: config.maxPrice,
        pricing_option: config.pricingOption,
      });
      return { upstream, poolUsed: pool, triedPools: candidates };
    } catch (e) {
      errors.push({ pool, message: e.message, details: e.details || null });
      if (!isPoolTemporarilyUnavailableError(e)) throw e;
    }
  }
  const err = new Error('当前号码暂时繁忙，请稍后再试');
  err.status = 503;
  err.publicMessage = true;
  err.details = { type: 'ALL_POOLS_UNAVAILABLE', triedPools: candidates, errors };
  throw err;
}

function findExpiredRefundCandidates(db) {
  return (db.sessions || [])
    .filter(s => s.status === 'timeout' && !s.counted && !s.reused && s.refundStatus !== 'refunded' && s.refundStatus !== 'pending')
    .filter(s => {
      const a = db.accounts.find(x => x.id === s.accountId);
      return a && a.source === 'new' && Number(a.useCount || 0) === 0 && a.orderid &&
        a.status !== 'refunded' && a.status !== 'refund_pending' &&
        a.refundStatus !== 'refunded' && a.refundStatus !== 'pending' &&
        (!a.refundRetryAfter || Date.now() >= new Date(a.refundRetryAfter).getTime());
    });
}

async function refundExpiredUnusedNumbers() {
  const snapshot = readDb();
  const candidates = findExpiredRefundCandidates(snapshot);
  for (const session of candidates) {
    try {
      await refundIfEligible(readDb(), session.id);
    } catch {
      // refundIfEligible already records the detailed error and retry time.
    }
  }
  return candidates.length;
}

async function refundIfEligible(dbSnapshot, sessionId) {
  const session = dbSnapshot.sessions.find(s => s.id === sessionId);
  if (!session) return { skipped: true, reason: 'session_not_found' };
  const account = dbSnapshot.accounts.find(a => a.id === session.accountId);
  if (!account) return { skipped: true, reason: 'account_not_found' };
  if (session.reused || account.source !== 'new' || Number(account.useCount || 0) > 0 || !account.orderid) {
    return { skipped: true, reason: 'not_eligible' };
  }
  if (session.refundStatus === 'refunded' || account.refundStatus === 'refunded' || account.status === 'refunded') {
    return { skipped: true, reason: 'already_refunded' };
  }
  if (session.refundStatus === 'pending' || account.refundStatus === 'pending' || account.status === 'refund_pending') {
    return { skipped: true, reason: 'refund_pending' };
  }
  if (account.refundRetryAfter && Date.now() < new Date(account.refundRetryAfter).getTime()) {
    return { skipped: true, reason: 'refund_retry_cooldown' };
  }

  const locked = transact(db => {
    const s = db.sessions.find(x => x.id === sessionId);
    const a = db.accounts.find(x => x.id === account.id);
    if (!s || !a) return false;
    if (s.refundStatus === 'pending' || a.refundStatus === 'pending' || a.status === 'refund_pending') return false;
    if (s.refundStatus === 'refunded' || a.refundStatus === 'refunded' || a.status === 'refunded') return false;
    if (s.reused || a.source !== 'new' || Number(a.useCount || 0) > 0) return false;
    s.refundStatus = 'pending';
    s.updatedAt = nowIso();
    a.refundStatus = 'pending';
    a.status = 'refund_pending';
    a.updatedAt = nowIso();
    audit(db, null, 'system.refund_pending', { sessionId, accountId: a.id, phone: a.phone });
    return true;
  });
  if (!locked) return { skipped: true, reason: 'lock_failed' };

  try {
    const result = await cancelSms(getRuntimeConfig(dbSnapshot), account.orderid);
    transact(db => {
      const s = db.sessions.find(x => x.id === sessionId);
      const a = db.accounts.find(x => x.id === account.id);
      if (s) { s.refundStatus = 'refunded'; s.refundResult = result; s.updatedAt = nowIso(); }
      if (a && Number(a.useCount || 0) === 0) {
        a.status = 'refunded';
        a.refundStatus = 'refunded';
        a.refundResult = result;
        a.updatedAt = nowIso();
        delete a.refundRetryAfter;
      }
      db.logs.unshift({ id: makeId('log'), type: 'refund', sessionId, accountId: account.id, result, createdAt: nowIso() });
      audit(db, null, 'system.refund', { sessionId, accountId: account.id, phone: account.phone, result });
    });
    return result;
  } catch (e) {
    transact(db => {
      const s = db.sessions.find(x => x.id === sessionId);
      const a = db.accounts.find(x => x.id === account.id);
      const retryAfter = addSecondsIso(db.config.refundRetrySeconds || 600);
      const err = scrubSensitive({ message: e.message, details: e.details || null });
      if (s) { s.refundStatus = 'failed'; s.refundError = err; s.updatedAt = nowIso(); }
      if (a && Number(a.useCount || 0) === 0) {
        a.status = 'failed';
        a.refundStatus = 'failed';
        a.refundError = err;
        a.refundRetryAfter = retryAfter;
        a.updatedAt = nowIso();
      }
      audit(db, null, 'system.refund_error', { sessionId, accountId: account.id, phone: account.phone, retryAfter, message: e.message, details: e.details || null });
    });
    throw e;
  }
}

async function allocateSession(cdkCode, opts = {}) {
  const db = readDb();
  const config = getRuntimeConfig(db);
  if (expireStaleWaitingSessions(db, config)) { writeDb(db); return allocateSession(cdkCode, opts); }
  const virtualCdk = opts.virtualCdk || null;
  const cdk = virtualCdk || db.cdks.find(x => x.code.toUpperCase() === cdkCode);
  if (!cdk) throw Object.assign(new Error('CDK 不可用'), { status: 400 });
  if (!['active'].includes(cdk.status || 'active')) throw Object.assign(new Error('CDK 不可用'), { status: 400 });
  if (!config.mockMode && !config.apiKey) throw Object.assign(new Error('服务暂时不可用，请稍后再试'), { status: 503, publicMessage: true });

  const reusable = opts.skipReusable ? null : reserveReusableAccountForResend(cdkCode, config, opts);
  if (reusable) {
    try {
      await resendSms(config, reusable.orderid);
    } catch (e) {
      const cooldown = retryAfterSecondsFromError(e, config.resendCooldownSeconds || 300);
      transact(wdb => {
        const a = wdb.accounts.find(x => x.id === reusable.id);
        if (a) {
          a.status = 'resend_failed';
          a.resendError = scrubSensitive({ message: e.message, details: e.details || null });
          a.resendCooldownUntil = addSecondsIso(cooldown);
          a.updatedAt = nowIso();
          delete a.resendingAt;
        }
        const c = wdb.cdks.find(x => x.code.toUpperCase() === cdkCode);
        if (c && c.status === 'resending' && c.reservedAccountId === reusable.id) {
          c.status = 'active';
          c.reservedAt = null;
          delete c.reservedAccountId;
        }
        audit(wdb, null, 'system.resend_failed_cooldown', { accountId: reusable.id, phone: reusable.phone, cooldownSeconds: cooldown, error: e.message, details: e.details || null });
      });
      return allocateSession(cdkCode);
    }
    return transact(wdb => {
      const c = opts.virtualCdk || wdb.cdks.find(x => x.code.toUpperCase() === cdkCode);
      const a = wdb.accounts.find(x => x.id === reusable.id);
      if (!opts.virtualCdk && (!c || c.status !== 'resending' || c.reservedAccountId !== a?.id)) throw Object.assign(new Error('CDK 不可用'), { status: 400 });
      if (!a || a.status !== 'resending') throw Object.assign(new Error('号码刚刚变为不可用，请重试'), { status: 409 });
      if (Number(a.useCount || 0) >= accountMaxUses(a, config)) throw Object.assign(new Error('号码刚刚变为不可用，请重试'), { status: 409 });
      a.status = 'waiting';
      a.updatedAt = nowIso();
      delete a.resendingAt;
      const sessionToken = randomToken();
      const session = {
        id: makeId('sess'), sessionTokenHash: hashToken(sessionToken), sessionTokenEncrypted: encryptSecret(sessionToken), cdk: c.code, accountId: a.id, orderid: a.orderid, phone: a.phone,
        country: a.country, service: a.service, pool: a.pool || '', status: 'waiting', counted: false,
        reused: true, clientId: opts.clientId || null, externalId: opts.externalId || '', billed: false, createdAt: nowIso(), updatedAt: nowIso(), deadlineAt: addSecondsIso(config.timeoutSeconds || 120),
      };
      if (!opts.virtualCdk) { c.status = 'reserved'; c.reservedAt = session.createdAt; c.reservedSessionId = session.id; delete c.reservedAccountId; }
      wdb.sessions.unshift(session);
      wdb.logs.unshift({ id: makeId('log'), type: 'reuse', sessionId: session.id, accountId: a.id, createdAt: nowIso() });
      return { session, sessionToken, account: a, reused: true };
    });
  }

  const purchaseResult = await purchaseSmsAuto(config);
  const upstream = purchaseResult.upstream;
  const poolUsed = purchaseResult.poolUsed;
  const orderid = String(extractOrderId(upstream) || '');
  const phone = String(extractPhone(upstream) || '');
  if (!orderid) {
    const err = new Error('上游未返回 orderid');
    err.status = 502;
    err.details = upstream;
    throw err;
  }

  return transact(wdb => {
    const c = opts.virtualCdk || wdb.cdks.find(x => x.code.toUpperCase() === cdkCode);
    if (!c || (c.status || 'active') !== 'active') throw Object.assign(new Error('CDK 不可用'), { status: 400 });
    const account = {
      id: makeId('acct'), orderid, phone, country: String(config.country), service: String(config.service), pool: String(poolUsed || config.pool || ''),
      useCount: 0, maxUses: Number(config.maxAccountUses || 3), status: 'waiting', source: 'new', upstream,
      createdAt: nowIso(), updatedAt: nowIso(), lastMessageAt: null,
    };
    const sessionToken = randomToken();
    const session = {
      id: makeId('sess'), sessionTokenHash: hashToken(sessionToken), sessionTokenEncrypted: encryptSecret(sessionToken), cdk: c.code, accountId: account.id, orderid, phone,
      country: account.country, service: account.service, pool: account.pool, status: 'waiting', counted: false,
      reused: false, clientId: opts.clientId || null, externalId: opts.externalId || '', billed: false, createdAt: nowIso(), updatedAt: nowIso(), deadlineAt: addSecondsIso(config.timeoutSeconds || 120),
    };
    if (!opts.virtualCdk) { c.status = 'reserved'; c.reservedAt = session.createdAt; c.reservedSessionId = session.id; }
    wdb.accounts.unshift(account);
    wdb.sessions.unshift(session);
    wdb.logs.unshift({ id: makeId('log'), type: 'purchase', sessionId: session.id, accountId: account.id, poolUsed, triedPools: purchaseResult.triedPools, upstream, createdAt: nowIso() });
    return { session, sessionToken, account, reused: false };
  });
}

app.get('/api/health', (req, res) => res.json({ success: 1, time: nowIso() }));
app.get('/admin', (req, res) => res.status(404).send('Not Found'));
app.get(ADMIN_PATH, (req, res) => {
  const html = fs.readFileSync(path.resolve('private/admin.html'), 'utf8').replaceAll('__ADMIN_PATH__', ADMIN_PATH);
  res.type('html').send(html);
});
app.get(`${ADMIN_PATH}/`, (req, res) => res.redirect(302, ADMIN_PATH));
app.get(`${ADMIN_PATH}/admin.js`, (req, res) => res.type('application/javascript').sendFile(path.resolve('private/admin.js')));



function apiNumberResponse(allocated) {
  return {
    success: 1,
    ...apiSessionPayload(allocated.session, allocated.account, readDb().clients.find(c => c.id === allocated.session.clientId)),
    sessionToken: allocated.sessionToken,
    pollIntervalSeconds: readDb().config.pollIntervalSeconds,
  };
}

app.get('/api/v1/balance', requireApiClient, (req, res) => {
  const db = readDb();
  const client = db.clients.find(c => c.id === req.apiClient.id);
  auditApi(req, 'api.balance', { balance: Number(client.balance || 0), status: client.status || 'active' });
  res.json({ success: 1, balance: Number(client.balance || 0), pricePerSuccess: Number(client.pricePerSuccess || 1), status: client.status || 'active' });
});

app.post('/api/v1/number', requireApiClient, async (req, res, next) => {
  try {
    const db = readDb();
    const client = db.clients.find(c => c.id === req.apiClient.id);
    try { ensureClientBalance(client); } catch (e) { auditApi(req, 'api.number_rejected', { reason: e.code || 'INSUFFICIENT_BALANCE', balance: Number(client.balance || 0), pricePerSuccess: Number(client.pricePerSuccess || 1) }); throw e; }
    const externalId = String(req.body?.externalId || '').trim().slice(0, 120);
    if (externalId) {
      const existing = db.sessions.find(s => s.clientId === client.id && s.externalId === externalId && ['waiting', 'received'].includes(String(s.status || '')));
      if (existing) {
        const account = db.accounts.find(a => a.id === existing.accountId);
        const sessionToken = recoverOrRotateSessionToken(existing.id, req);
        auditApi(req, 'api.number_idempotent', { sessionId: existing.id, accountId: existing.accountId, externalId, status: existing.status, tokenRecovered: !!sessionToken });
        return res.json({ success: 1, ...apiSessionPayload(existing, account, client), sessionToken, idempotent: true, pollIntervalSeconds: db.config.pollIntervalSeconds });
      }
    }
    const virtualCdk = { code: `API-${client.id}-${makeId('req')}`, status: 'active' };
    const allocated = await allocateSession(virtualCdk.code, { virtualCdk, clientId: client.id, externalId });
    transact(wdb => audit(wdb, req, 'api.number_allocated', { clientId: client.id, sessionId: allocated.session.id, accountId: allocated.account.id, externalId, reused: allocated.reused, phone: allocated.account.phone, country: allocated.account.country, service: allocated.account.service, pool: allocated.account.pool }));
    res.json(apiNumberResponse(allocated));
  } catch (e) { auditApi(req, 'api.number_error', { message: e.message, status: e.status || 500, code: e.code || '', details: e.details || null }); next(e); }
});

app.post('/api/v1/session/check', requireApiClient, async (req, res, next) => {
  try {
    requireFields(req.body, ['sessionId', 'sessionToken']);
    const sessionId = String(req.body.sessionId);
    const token = String(req.body.sessionToken);
    const db = readDb();
    const session = db.sessions.find(s => s.id === sessionId && s.clientId === req.apiClient.id);
    if (!session) { auditApi(req, 'api.check_rejected', { reason: 'SESSION_NOT_FOUND', sessionId }); return res.status(404).json({ success: 0, code: 'SESSION_NOT_FOUND', message: '会话不存在' }); }
    if (!session.sessionTokenHash || hashToken(token) !== session.sessionTokenHash) { auditApi(req, 'api.check_rejected', { reason: 'SESSION_FORBIDDEN', sessionId }); return res.status(403).json({ success: 0, code: 'SESSION_FORBIDDEN', message: '无权访问该会话' }); }
    const account = db.accounts.find(a => a.id === session.accountId);
    if (!account) { auditApi(req, 'api.check_rejected', { reason: 'NUMBER_NOT_FOUND', sessionId, accountId: session.accountId }); return res.status(404).json({ success: 0, code: 'NUMBER_NOT_FOUND', message: '号码不存在' }); }

    if (session.status === 'received' || session.counted) {
      const client = readDb().clients.find(c => c.id === req.apiClient.id);
      auditApi(req, 'api.check_already_received', { sessionId, accountId: account.id, externalId: session.externalId || '', billed: !!session.billed });
      return res.json({ success: 1, ...apiSessionPayload(session, account, client) });
    }

    const timedOut = Date.now() > new Date(session.deadlineAt).getTime();
    if (timedOut && session.status === 'waiting') {
      transact(wdb => {
        const s = wdb.sessions.find(x => x.id === sessionId);
        const a = wdb.accounts.find(x => x.id === account.id);
        if (s) { s.status = 'timeout'; s.updatedAt = nowIso(); }
        if (a && Number(a.useCount || 0) === 0 && !session.reused) { a.status = 'failed'; a.updatedAt = nowIso(); }
        else if (a && session.reused) { cooldownReusedAccount(a, wdb.config); }
        audit(wdb, req, 'api.session_timeout', { clientId: req.apiClient.id, sessionId, accountId: account.id, phone: account.phone });
      });
      refundIfEligible(readDb(), sessionId).catch(() => {});
      const fresh = readDb();
      const s = fresh.sessions.find(x => x.id === sessionId);
      const a = fresh.accounts.find(x => x.id === account.id);
      const c = fresh.clients.find(x => x.id === req.apiClient.id);
      return res.json({ success: 1, timedOut: true, ...apiSessionPayload(s, a, c) });
    }

    let data;
    try {
      data = await checkSms(getRuntimeConfig(db), account.orderid);
    } catch (e) {
      const fresh = transact(wdb => {
        const s = wdb.sessions.find(x => x.id === sessionId);
        const a = wdb.accounts.find(x => x.id === account.id);
        if (s) { s.lastCheckError = scrubSensitive({ message: e.message, details: e.details || null }); s.updatedAt = nowIso(); }
        if (a) { a.lastCheckError = scrubSensitive({ message: e.message, details: e.details || null }); a.updatedAt = nowIso(); }
        audit(wdb, req, 'api.sms_check_error', { clientId: req.apiClient.id, sessionId, accountId: account.id, message: e.message, details: e.details || null });
        return { session: s, account: a, client: wdb.clients.find(c => c.id === req.apiClient.id) };
      });
      return res.json({ success: 1, received: false, ...apiSessionPayload(fresh.session, fresh.account, fresh.client) });
    }
    const msg = extractMessage(data);
    const updated = transact(wdb => {
      const s = wdb.sessions.find(x => x.id === sessionId);
      const a = wdb.accounts.find(x => x.id === account.id);
      s.lastCheck = data;
      s.updatedAt = nowIso();
      a.lastCheck = data;
      a.updatedAt = nowIso();
      if (msg && !s.counted) {
        s.status = 'received';
        s.message = msg;
        s.counted = true;
        s.receivedAt = msg.receivedAt;
        a.useCount = Number(a.useCount || 0) + 1;
        a.lastMessage = msg;
        a.lastMessageAt = msg.receivedAt;
        a.status = a.useCount >= Number(a.maxUses || wdb.config.maxAccountUses || 3) ? 'used_up' : 'available';
        chargeClientForSession(wdb, s, a);
        wdb.logs.unshift({ id: makeId('log'), type: 'api_received', sessionId: s.id, accountId: a.id, clientId: req.apiClient.id, createdAt: nowIso() });
        audit(wdb, req, 'api.sms_received', { clientId: req.apiClient.id, sessionId: s.id, accountId: a.id, phone: a.phone });
      } else if (msg) {
        s.message = s.message || msg;
      } else if (isSuccessFlagFalse(data)) {
        s.status = 'waiting';
      }
      return { session: s, account: a, client: wdb.clients.find(c => c.id === req.apiClient.id) };
    });
    const payload = apiSessionPayload(updated.session, updated.account, updated.client);
    if (updated.session.billingId) payload.billing.charged = !!msg && !!updated.session.billed;
    auditApi(req, 'api.check_result', { sessionId, accountId: account.id, externalId: session.externalId || '', received: !!msg, upstreamSuccess: data?.success ?? null, status: updated.session.status });
    res.json({ success: 1, timedOut: false, ...payload });
  } catch (e) { auditApi(req, 'api.check_error', { message: e.message, status: e.status || 500, code: e.code || '', sessionId: req.body?.sessionId || '' }); next(e); }
});

app.post('/api/v1/session/change-number', requireApiClient, async (req, res, next) => {
  try {
    requireFields(req.body, ['sessionId', 'sessionToken']);
    const oldId = String(req.body.sessionId);
    const token = String(req.body.sessionToken);
    const snapshot = readDb();
    const client = snapshot.clients.find(c => c.id === req.apiClient.id);
    ensureClientBalance(client);
    const oldSession = snapshot.sessions.find(s => s.id === oldId && s.clientId === client.id);
    if (!oldSession) { auditApi(req, 'api.change_rejected', { reason: 'SESSION_NOT_FOUND', sessionId: oldId }); return res.status(404).json({ success: 0, code: 'SESSION_NOT_FOUND', message: '会话不存在' }); }
    if (!oldSession.sessionTokenHash || hashToken(token) !== oldSession.sessionTokenHash) { auditApi(req, 'api.change_rejected', { reason: 'SESSION_FORBIDDEN', sessionId: oldId }); return res.status(403).json({ success: 0, code: 'SESSION_FORBIDDEN', message: '无权访问该会话' }); }
    if (oldSession.status === 'received' || oldSession.counted) { auditApi(req, 'api.change_rejected', { reason: 'SMS_RECEIVED_CANNOT_CHANGE', sessionId: oldId }); return res.status(400).json({ success: 0, code: 'SMS_RECEIVED_CANNOT_CHANGE', message: '已收到短信，不能更换号码' }); }
    if (oldSession.status === 'waiting' && !canChangeSession(oldSession, snapshot.config)) { auditApi(req, 'api.change_rejected', { reason: 'CHANGE_TOO_EARLY', sessionId: oldId, canChangeAt: oldSession.canChangeAt || addSecondsIsoFrom(oldSession.createdAt, snapshot.config.changeNumberAfterSeconds || 120) }); return res.status(400).json({ success: 0, code: 'CHANGE_TOO_EARLY', message: '等待满 2 分钟后才能更换号码' }); }
    const oldAccount = snapshot.accounts.find(a => a.id === oldSession.accountId);
    transact(db => {
      const s = db.sessions.find(x => x.id === oldId);
      const a = oldAccount ? db.accounts.find(x => x.id === oldAccount.id) : null;
      if (s) { s.status = 'changed'; s.updatedAt = nowIso(); }
      if (a && Number(a.useCount || 0) === 0 && !s.reused) { a.status = 'failed'; a.updatedAt = nowIso(); }
      else if (a && s?.reused) { cooldownReusedAccount(a, db.config); }
      audit(db, req, 'api.change_number', { clientId: client.id, sessionId: oldId, accountId: oldAccount?.id, phone: oldAccount?.phone });
    });
    if (oldAccount && !oldSession.reused && Number(oldAccount.useCount || 0) === 0) {
      try { await refundIfEligible(snapshot, oldId); } catch {}
    }
    const virtualCdk = { code: `API-${client.id}-${makeId('req')}`, status: 'active' };
    const allocated = await allocateSession(virtualCdk.code, { virtualCdk, clientId: client.id, externalId: oldSession.externalId || '' });
    auditApi(req, 'api.change_allocated', { oldSessionId: oldId, newSessionId: allocated.session.id, accountId: allocated.account.id, externalId: oldSession.externalId || '', reused: allocated.reused, phone: allocated.account.phone });
    res.json(apiNumberResponse(allocated));
  } catch (e) { auditApi(req, 'api.change_error', { message: e.message, status: e.status || 500, code: e.code || '', sessionId: req.body?.sessionId || '' }); next(e); }
});

app.get('/api/public-config', (req, res) => {
  const cfg = readDb().config;
  res.json({ success: 1, purchase: { enabled: !!cfg.purchaseEnabled, url: cfg.purchaseUrl || '', textZh: cfg.purchaseTextZh || '购买', textEn: cfg.purchaseTextEn || 'Buy' } });
});

app.post('/api/cdk/redeem', requireSameOrigin, async (req, res, next) => {
  try {
    const code = String(req.body.code || '').trim().toUpperCase();
    if (!code) return res.status(400).json({ success: 0, message: '请输入 CDK' });
    transact(db => audit(db, req, 'user.cdk_redeem_attempt', { cdk: maskCdk(code) }));
    const allocated = await allocateSession(code);
    transact(db => audit(db, req, 'user.cdk_redeemed', { cdk: maskCdk(code), sessionId: allocated.session.id, accountId: allocated.account.id, reused: allocated.reused }));
    res.json({
      success: 1,
      ...frontendSessionPayload(allocated.session, allocated.account),
      sessionToken: allocated.sessionToken,
      config: { timeoutSeconds: readDb().config.timeoutSeconds, changeNumberAfterSeconds: readDb().config.changeNumberAfterSeconds, pollIntervalSeconds: readDb().config.pollIntervalSeconds },
    });
  } catch (e) { next(e); }
});


app.post('/api/cdk/records', requireSameOrigin, (req, res) => {
  const code = String(req.body.code || '').trim().toUpperCase();
  if (!code) return res.status(400).json({ success: 0, message: '请输入 CDK' });
  const db = readDb();
  const cdk = db.cdks.find(x => x.code.toUpperCase() === code);
  if (!cdk) return res.status(400).json({ success: 0, message: 'CDK 不可用' });
  const sessions = db.sessions
    .filter(s => s.cdk.toUpperCase() === code)
    .map(s => {
      const account = db.accounts.find(a => a.id === s.accountId);
      return frontendRecord(s, account);
    });
  transact(wdb => audit(wdb, req, 'user.cdk_records_query', { cdk: maskCdk(code), count: sessions.length }));
  res.json({ success: 1, records: sessions });
});

app.post('/api/session/check', requireSameOrigin, async (req, res, next) => {
  try {
    requireFields(req.body, ['sessionId']);
    const sessionId = String(req.body.sessionId);
    const db = readDb();
    const session = db.sessions.find(s => s.id === sessionId);
    if (!session) return res.status(404).json({ success: 0, message: '会话不存在' });
    if (!verifySessionAccess(req, session)) return res.status(403).json({ success: 0, message: '无权访问该会话' });
    const account = db.accounts.find(a => a.id === session.accountId);
    if (!account) return res.status(404).json({ success: 0, message: '号码不存在' });
    if (session.status === 'received' || session.counted) {
      return res.json({ success: 1, received: true, stopped: true, ...frontendSessionPayload(session, account) });
    }

    const cdkForSession = db.cdks.find(c => c.code.toUpperCase() === session.cdk.toUpperCase());
    if (!session.counted && cdkForSession && !((cdkForSession.status || 'active') === 'reserved' && cdkForSession.reservedSessionId === session.id) && (cdkForSession.status || 'active') !== 'active') {
      return res.status(400).json({ success: 0, message: 'CDK 不可用' });
    }

    const timedOut = Date.now() > new Date(session.deadlineAt).getTime();
    if (timedOut && session.status === 'waiting') {
      transact(wdb => {
        const s = wdb.sessions.find(x => x.id === sessionId);
        const a = wdb.accounts.find(x => x.id === account.id);
        const c = s && !s.clientId ? wdb.cdks.find(x => x.code.toUpperCase() === s.cdk.toUpperCase()) : null;
        if (s) { s.status = 'timeout'; s.updatedAt = nowIso(); }
        if (c && c.status === 'reserved' && c.reservedSessionId === sessionId) { c.status = 'active'; c.reservedSessionId = null; c.reservedAt = null; }
        if (a && Number(a.useCount || 0) === 0 && !session.reused) { a.status = 'failed'; a.updatedAt = nowIso(); }
        else if (a && session.reused) { cooldownReusedAccount(a, wdb.config); }
        audit(wdb, req, 'user.session_timeout', { sessionId, accountId: account.id, phone: account.phone });
      });
      refundIfEligible(readDb(), sessionId).catch(() => {});
      return res.json({ success: 1, received: false, timedOut: true, ...frontendSessionPayload({ ...session, status: 'timeout' }, account) });
    }

    let data;
    try {
      data = await checkSms(getRuntimeConfig(db), account.orderid);
    } catch (e) {
      const updated = transact(wdb => {
        const s = wdb.sessions.find(x => x.id === sessionId);
        const a = wdb.accounts.find(x => x.id === account.id);
        if (s) { s.lastCheckError = scrubSensitive({ message: e.message, details: e.details || null }); s.updatedAt = nowIso(); }
        if (a) { a.lastCheckError = scrubSensitive({ message: e.message, details: e.details || null }); a.updatedAt = nowIso(); }
        audit(wdb, req, 'system.sms_check_error', { sessionId, accountId: account.id, message: e.message, details: e.details || null });
        return { session: s, account: a };
      });
      return res.json({ success: 1, received: false, message: '短信仍在等待中', ...frontendSessionPayload(updated.session, updated.account) });
    }
    const msg = extractMessage(data);

    const updated = transact(wdb => {
      const s = wdb.sessions.find(x => x.id === sessionId);
      const a = wdb.accounts.find(x => x.id === account.id);
      const c = s.clientId ? null : wdb.cdks.find(x => x.code.toUpperCase() === s.cdk.toUpperCase());
      s.lastCheck = data;
      s.updatedAt = nowIso();
      a.lastCheck = data;
      a.updatedAt = nowIso();
      if (msg && !s.counted) {
        s.status = 'received';
        s.message = msg;
        s.counted = true;
        s.receivedAt = msg.receivedAt;
        a.useCount = Number(a.useCount || 0) + 1;
        a.lastMessage = msg;
        a.lastMessageAt = msg.receivedAt;
        a.status = a.useCount >= Number(a.maxUses || wdb.config.maxAccountUses || 3) ? 'used_up' : 'available';
        if (c) { c.status = 'used'; c.usedAt = msg.receivedAt; c.usedSessionId = s.id; c.consumedReason = 'sms_received'; }
        chargeClientForSession(wdb, s, a);
        wdb.logs.unshift({ id: makeId('log'), type: 'received', sessionId: s.id, accountId: a.id, createdAt: nowIso() });
        audit(wdb, req, 'user.sms_received', { sessionId: s.id, accountId: a.id, cdk: maskCdk(s.cdk), phone: a.phone });
      } else if (msg) {
        s.message = s.message || msg;
      } else if (isSuccessFlagFalse(data)) {
        s.status = 'waiting';
      }
      return { session: s, account: a, cdk: c };
    });

    res.json({ success: 1, received: !!msg, timedOut: false, ...frontendSessionPayload(updated.session, updated.account) });
  } catch (e) { next(e); }
});

app.post('/api/session/change-number', requireSameOrigin, async (req, res, next) => {
  try {
    requireFields(req.body, ['sessionId']);
    const oldId = String(req.body.sessionId);
    const snapshot = readDb();
    const oldSession = snapshot.sessions.find(s => s.id === oldId);
    if (!oldSession) return res.status(404).json({ success: 0, message: '会话不存在' });
    if (!verifySessionAccess(req, oldSession)) return res.status(403).json({ success: 0, message: '无权访问该会话' });
    const oldAccount = snapshot.accounts.find(a => a.id === oldSession.accountId);
    const oldCdk = snapshot.cdks.find(c => c.code.toUpperCase() === oldSession.cdk.toUpperCase());
    if (!oldCdk || !(((oldCdk.status || 'active') === 'reserved' && oldCdk.reservedSessionId === oldSession.id) || (oldCdk.status || 'active') === 'active')) return res.status(400).json({ success: 0, message: 'CDK 不可用' });
    if (oldSession.status === 'received' || oldSession.counted) return res.status(400).json({ success: 0, message: '已收到短信，不能更换号码' });
    if (oldSession.status === 'waiting' && !canChangeSession(oldSession, snapshot.config)) {
      return res.status(400).json({ success: 0, message: '等待满 2 分钟后才能更换号码' });
    }

    transact(db => {
      const s = db.sessions.find(x => x.id === oldId);
      const a = oldAccount ? db.accounts.find(x => x.id === oldAccount.id) : null;
      if (s) { s.status = 'changed'; s.updatedAt = nowIso(); }
      const c = oldSession.clientId ? null : db.cdks.find(x => x.code.toUpperCase() === oldSession.cdk.toUpperCase());
      if (c && c.status === 'reserved' && c.reservedSessionId === oldId) { c.status = 'active'; c.reservedSessionId = null; c.reservedAt = null; }
      if (a && Number(a.useCount || 0) === 0 && !s.reused) { a.status = 'failed'; a.updatedAt = nowIso(); }
      else if (a && s?.reused) { cooldownReusedAccount(a, db.config); }
      db.logs.unshift({ id: makeId('log'), type: 'change_number', sessionId: oldId, accountId: oldAccount?.id, createdAt: nowIso() });
      audit(db, req, 'user.change_number', { sessionId: oldId, accountId: oldAccount?.id, phone: oldAccount?.phone });
    });

    if (oldAccount && !oldSession.reused && Number(oldAccount.useCount || 0) === 0) {
      try { await refundIfEligible(snapshot, oldId); } catch (e) { audit(readDb(), req, 'system.refund_error', { sessionId: oldId, message: e.message, details: e.details || null }); }
    }

    const allocated = await allocateSession(oldSession.cdk.toUpperCase());
    res.json({ success: 1, ...frontendSessionPayload(allocated.session, allocated.account), sessionToken: allocated.sessionToken, config: { timeoutSeconds: readDb().config.timeoutSeconds, changeNumberAfterSeconds: readDb().config.changeNumberAfterSeconds, pollIntervalSeconds: readDb().config.pollIntervalSeconds } });
  } catch (e) { next(e); }
});

app.get('/api/session/:id', (req, res) => {
  const db = readDb();
  const session = db.sessions.find(s => s.id === req.params.id);
  if (!session) return res.status(404).json({ success: 0, message: '会话不存在' });
  if (!verifySessionAccess(req, session)) return res.status(403).json({ success: 0, message: '无权访问该会话' });
  const account = db.accounts.find(a => a.id === session.accountId);
  res.json({ success: 1, ...frontendSessionPayload(session, account) });
});

app.post('/api/admin/login', requireSameOrigin, (req, res) => {
  if (!safeEqual(String(req.body?.adminToken || '').trim(), ADMIN_TOKEN)) { transact(db => audit(db, req, 'admin.login_failed')); return res.status(401).json({ success: 0, message: '认证失败' }); }
  transact(db => audit(db, req, 'admin.login_success'));
  res.cookie('admin_session', makeAdminCookie(), { httpOnly: true, sameSite: 'strict', secure: IS_PROD, maxAge: 12 * 60 * 60 * 1000 });
  res.json({ success: 1 });
});

app.post('/api/admin/logout', requireSameOrigin, (req, res) => {
  transact(db => audit(db, req, 'admin.logout'));
  res.clearCookie('admin_session');
  res.json({ success: 1 });
});

app.get('/api/admin/overview', requireAdmin, async (req, res) => {
  const db = readDb();
  let balance = null;
  try { balance = await getBalance(getRuntimeConfig(db)); } catch (e) { balance = { error: e.message }; }
  res.json({
    success: 1,
    config: safeConfig(db.config),
    balance,
    cdks: db.cdks.map(c => publicCdk(c, { admin: true })),
    accounts: db.accounts.map(a => publicAccount(a, { admin: true })),
    sessions: db.sessions.map(s => publicSession(s, db.accounts.find(a => a.id === s.accountId), { admin: true })),
    clients: (db.clients || []).map(c => publicClient(c)),
    billingLogs: scrubSensitive((db.billingLogs || []).slice(0, 300)),
    logs: scrubSensitive(db.logs.slice(0, 100)),
    auditLogs: scrubSensitive((db.auditLogs || []).slice(0, 300)),
  });
});

app.post('/api/admin/config', requireSameOrigin, requireAdmin, (req, res) => {
  const allowed = ['apiKey', 'country', 'service', 'pool', 'maxPrice', 'pricingOption', 'maxAccountUses', 'timeoutSeconds', 'changeNumberAfterSeconds', 'pollIntervalSeconds', 'mockMode', 'mockReceiveAfterChecks', 'purchaseEnabled', 'purchaseUrl', 'purchaseTextZh', 'purchaseTextEn', 'resendCooldownSeconds', 'refundRetrySeconds', 'successfulReuseThreshold', 'reuseUsedNumbersEnabled'];
  const updated = transact(db => {
    for (const k of allowed) {
      if (req.body[k] !== undefined) {
        if (['maxAccountUses', 'timeoutSeconds', 'changeNumberAfterSeconds', 'pollIntervalSeconds', 'mockReceiveAfterChecks', 'resendCooldownSeconds', 'refundRetrySeconds', 'successfulReuseThreshold'].includes(k)) db.config[k] = Number(req.body[k]);
        else if (k === 'mockMode' || k === 'purchaseEnabled' || k === 'reuseUsedNumbersEnabled') db.config[k] = req.body[k] === true || req.body[k] === 'true' || req.body[k] === '1' || req.body[k] === 'on';
        else if (k === 'apiKey' && String(req.body[k]) === '********') continue;
        else if (k === 'apiKey') db.config[k] = storeApiKey(String(req.body[k] ?? ''));
        else db.config[k] = String(req.body[k] ?? '');
      }
    }
    db.logs.unshift({ id: makeId('log'), type: 'config_update', createdAt: nowIso() });
    audit(db, req, 'admin.config_update', { fields: Object.keys(req.body || {}) });
    return safeConfig(db.config);
  });
  res.json({ success: 1, config: updated });
});


app.post('/api/admin/clients', requireSameOrigin, requireAdmin, (req, res) => {
  const name = String(req.body.name || '').trim() || 'API Client';
  const balance = Number(req.body.balance || 0);
  const pricePerSuccess = Number(req.body.pricePerSuccess || 1);
  const apiKey = makeApiKey();
  const client = transact(db => {
    const row = {
      id: makeId('client'),
      name,
      apiKeyHash: hashApiKey(apiKey),
      apiKeyPrefix: apiKey.slice(0, 22),
      status: 'active',
      balance,
      pricePerSuccess,
      createdAt: nowIso(),
      updatedAt: nowIso(),
    };
    db.clients.unshift(row);
    audit(db, req, 'admin.client_create', { clientId: row.id, name, balance, pricePerSuccess });
    return publicClient({ ...row, apiKey }, { revealKey: true });
  });
  res.json({ success: 1, client });
});

app.post('/api/admin/client/:id/update', requireSameOrigin, requireAdmin, (req, res) => {
  const id = String(req.params.id);
  const updated = transact(db => {
    const c = db.clients.find(x => x.id === id);
    if (!c) return null;
    if (req.body.name !== undefined) c.name = String(req.body.name || '');
    if (req.body.status !== undefined) c.status = String(req.body.status || 'active');
    if (req.body.balance !== undefined) c.balance = Number(req.body.balance || 0);
    if (req.body.pricePerSuccess !== undefined) c.pricePerSuccess = Number(req.body.pricePerSuccess || 1);
    c.updatedAt = nowIso();
    audit(db, req, 'admin.client_update', { clientId: id, fields: Object.keys(req.body || {}) });
    return publicClient(c);
  });
  if (!updated) return res.status(404).json({ success: 0, message: '客户不存在' });
  res.json({ success: 1, client: updated });
});

app.post('/api/admin/client/:id/recharge', requireSameOrigin, requireAdmin, (req, res) => {
  const id = String(req.params.id);
  const amount = Number(req.body.amount || 0);
  const updated = transact(db => {
    const c = db.clients.find(x => x.id === id);
    if (!c) return null;
    const before = Number(c.balance || 0);
    c.balance = before + amount;
    c.updatedAt = nowIso();
    db.billingLogs.unshift({ id: makeId('bill'), clientId: id, type: 'recharge', amount, balanceBefore: before, balanceAfter: c.balance, createdAt: nowIso() });
    audit(db, req, 'admin.client_recharge', { clientId: id, amount, balanceBefore: before, balanceAfter: c.balance });
    return publicClient(c);
  });
  if (!updated) return res.status(404).json({ success: 0, message: '客户不存在' });
  res.json({ success: 1, client: updated });
});

app.post('/api/admin/client/:id/reset-key', requireSameOrigin, requireAdmin, (req, res) => {
  const id = String(req.params.id);
  const apiKey = makeApiKey();
  const updated = transact(db => {
    const c = db.clients.find(x => x.id === id);
    if (!c) return null;
    c.apiKeyHash = hashApiKey(apiKey);
    c.apiKeyPrefix = apiKey.slice(0, 22);
    c.updatedAt = nowIso();
    audit(db, req, 'admin.client_reset_key', { clientId: id, apiKeyPrefix: c.apiKeyPrefix });
    return publicClient({ ...c, apiKey }, { revealKey: true });
  });
  if (!updated) return res.status(404).json({ success: 0, message: '客户不存在' });
  res.json({ success: 1, client: updated });
});

app.post('/api/admin/cdks', requireSameOrigin, requireAdmin, (req, res) => {
  const count = Math.min(Math.max(Number(req.body.count || 1), 1), 1000);
  const note = String(req.body.note || '');
  const created = transact(db => {
    const arr = [];
    for (let i = 0; i < count; i++) {
      let code;
      do { code = makeCdk(); } while (db.cdks.some(x => x.code === code));
      const row = { code, status: 'active', note, createdAt: nowIso(), usedAt: null, usedSessionId: null };
      db.cdks.unshift(row);
      arr.push(publicCdk(row, { admin: true }));
    }
    db.logs.unshift({ id: makeId('log'), type: 'cdk_create', count, createdAt: nowIso() });
    audit(db, req, 'admin.cdk_create', { count, note });
    return arr;
  });
  res.json({ success: 1, cdks: created });
});

app.post('/api/admin/cdk/:code/disable', requireSameOrigin, requireAdmin, (req, res) => {
  const code = req.params.code.toUpperCase();
  const cdk = transact(db => {
    const row = db.cdks.find(x => x.code.toUpperCase() === code);
    if (!row) return null;
    if (row.status === 'active') row.status = 'disabled';
    audit(db, req, 'admin.cdk_disable', { cdk: maskCdk(row.code) });
    return publicCdk(row, { admin: true });
  });
  if (!cdk) return res.status(404).json({ success: 0, message: 'CDK 不存在' });
  res.json({ success: 1, cdk });
});

app.post('/api/admin/cdks/redeem', requireSameOrigin, requireAdmin, (req, res) => {
  const input = Array.isArray(req.body.codes) ? req.body.codes.join('\n') : String(req.body.codes || req.body.code || '');
  const codes = [...new Set(input.split(/[\s,，;；]+/).map(x => x.trim().toUpperCase()).filter(Boolean))];
  if (!codes.length) return res.status(400).json({ success: 0, message: '请输入 CDK' });
  const result = transact(db => {
    const rows = [];
    let redeemed = 0;
    let missing = 0;
    let skipped = 0;
    for (const code of codes) {
      const row = db.cdks.find(x => x.code.toUpperCase() === code);
      if (!row) { missing++; rows.push({ code, status: 'missing' }); continue; }
      if (['used', 'redeemed', 'disabled'].includes(String(row.status || 'active'))) {
        skipped++;
        rows.push(publicCdk(row, { admin: true }));
        continue;
      }
      row.status = 'redeemed';
      row.redeemedAt = nowIso();
      row.redeemedReason = 'admin_manual';
      row.reservedSessionId = null;
      row.reservedAt = null;
      redeemed++;
      rows.push(publicCdk(row, { admin: true }));
    }
    db.logs.unshift({ id: makeId('log'), type: 'cdk_redeem_admin', count: redeemed, createdAt: nowIso() });
    audit(db, req, 'admin.cdk_redeem', { requested: codes.length, redeemed, skipped, missing });
    return { requested: codes.length, redeemed, skipped, missing, rows };
  });
  res.json({ success: 1, ...result });
});

app.get('/api/catalog/countries', requireAdmin, async (req, res, next) => { try { const result = await getCachedCountries(getRuntimeConfig(readDb()), { force: req.query.force === '1' || req.query.refresh === '1' }); res.json({ success: 1, ...result }); } catch (e) { next(e); } });
app.get('/api/catalog/services', requireAdmin, async (req, res, next) => { try { res.json({ success: 1, data: await listServices(getRuntimeConfig(readDb())) }); } catch (e) { next(e); } });
app.get('/api/catalog/pools', requireAdmin, async (req, res, next) => { try { res.json({ success: 1, data: await listPools(getRuntimeConfig(readDb())) }); } catch (e) { next(e); } });
app.post('/api/sms/price', requireAdmin, async (req, res, next) => { try { res.json({ success: 1, data: await getPrice(getRuntimeConfig(readDb()), req.body) }); } catch (e) { transact(db => audit(db, req, 'admin.price_error', { message: e.message, details: e.details || null })); next(e); } });
app.post('/api/sms/stock', requireAdmin, async (req, res, next) => { try { res.json({ success: 1, data: await getStock(getRuntimeConfig(readDb()), req.body) }); } catch (e) { transact(db => audit(db, req, 'admin.stock_error', { message: e.message, details: e.details || null })); next(e); } });

app.use((err, req, res, next) => {
  const status = err.status || (err instanceof SmsPoolError ? err.status : 500);
  const isAdminReq = req.path.startsWith('/api/admin');
  const safeClientMessages = ['请输入 CDK','CDK 不可用','已收到短信，不能更换号码','等待满 2 分钟后才能更换号码','会话不存在','号码不存在','无权访问该会话','已超时，可以更换号码'];
  const msg = isAdminReq || err.publicMessage || safeClientMessages.includes(err.message) ? (err.message || 'server error') : '服务暂时不可用，请稍后再试';
  if (!isAdminReq) { try { transact(db => audit(db, req, 'frontend.error', { path: req.path, status, message: err.message, details: err.details || null })); } catch {} }
  res.status(status).json({ success: 0, message: msg, details: isAdminReq && err.details ? scrubSensitive(err.details) : undefined });
});


// Temporary migration: status=6/refunded must not be treated as a received SMS.
transact(db => {
  let changed = false;
  for (const s of db.sessions || []) {
    const text = String(s.message?.text || s.lastCheck?.message || '');
    if (s.status === 'received' && /refund|refunded|cancel|cancelled/i.test(text)) {
      s.status = 'failed';
      s.counted = false;
      s.message = null;
      s.receivedAt = null;
      changed = true;
      const c = db.cdks.find(x => x.code === s.cdk);
      if (c && c.usedSessionId === s.id) { c.status = 'active'; c.usedAt = null; c.usedSessionId = null; c.consumedReason = null; }
    }
  }
  for (const a of db.accounts || []) {
    const text = String(a.lastMessage?.text || a.lastCheck?.message || '');
    if (/refund|refunded|cancel|cancelled/i.test(text)) {
      a.status = 'refunded';
      a.useCount = 0;
      a.lastMessage = null;
      a.lastMessageAt = null;
      changed = true;
    }
  }
  if (changed) audit(db, null, 'system.cleanup_false_received');
});


async function cleanupExpiredWaitingSessions() {
  try {
    const db = readDb();
    const config = getRuntimeConfig(db);
    if (expireStaleWaitingSessions(db, config)) {
      audit(db, null, 'system.expired_waiting_cleanup');
      writeDb(db);
    }
    await refundExpiredUnusedNumbers();
  } catch (e) {
    console.error('expired waiting cleanup failed:', e.message);
  }
}
cleanupExpiredWaitingSessions();
setInterval(() => { cleanupExpiredWaitingSessions(); }, Number(process.env.WAITING_CLEANUP_INTERVAL_SECONDS || 30) * 1000).unref?.();

app.listen(PORT, HOST, () => {
  console.log(`GPTSMS front site running: http://${HOST}:${PORT}/`);
  console.log(`GPTSMS admin site running: http://${HOST}:${PORT}${ADMIN_PATH}`);
});
