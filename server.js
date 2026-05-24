import express from 'express';
import path from 'node:path';
import fs from 'node:fs';
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import { transact, readDb, makeId, makeCdk, nowIso, addSecondsIso, safeConfig, getRuntimeConfig, storeApiKey } from './src/db.js';
import { getBalance, listCountries, listServices, listPools, getPrice, getStock, purchaseSms, checkSms, cancelSms, resendSms, retrieveValidPools, SmsPoolError } from './src/smspool.js';

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
app.use('/api/admin/login', rateLimit({ windowMs: 15 * 60_000, limit: 8, standardHeaders: true, legacyHeaders: false }));
app.use('/api/admin', rateLimit({ windowMs: 60_000, limit: 60, standardHeaders: true, legacyHeaders: false }));
app.use(express.static(path.resolve('public'), { dotfiles: 'deny', index: 'index.html', extensions: ['html'] }));
app.use('/api', (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });


function randomToken() {
  return makeId('tok');
}

function hashToken(token) {
  return createHmac('sha256', APP_SECRET).update(String(token)).digest('hex');
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
    lastMessageAt: account.lastMessageAt || null,
    createdAt: admin ? account.createdAt : undefined,
    updatedAt: admin ? account.updatedAt : undefined,
  };
}

function publicSession(session, account, { admin = false, revealPhone = false } = {}) {
  return {
    id: session.id,
    cdk: admin ? session.cdk : maskCdk(session.cdk),
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
  };
}

function frontendAccount(account) {
  return {
    phone: account?.phone || '',
  };
}

function frontendSession(session) {
  return {
    id: session.id,
    status: session.status,
    deadlineAt: session.deadlineAt,
    message: session.message ? { text: session.message.text || '' } : null,
  };
}

function frontendRecord(session, account) {
  return {
    phone: account?.phone || session.phone || '',
    status: session.status,
    messageText: session.message?.text || '',
    receivedAt: session.receivedAt || session.message?.receivedAt || '',
  };
}

function frontendSessionPayload(session, account) {
  return {
    account: frontendAccount(account),
    session: frontendSession(session),
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

function findReusableAccount(db, config) {
  const maxUses = Number(config.maxAccountUses || 3);
  const configuredPool = String(config.pool || '').trim();
  const poolMatches = (accountPool) => !configuredPool || configuredPool.toLowerCase() === 'auto' || String(accountPool || '') === configuredPool;
  return db.accounts
    .filter(a =>
      String(a.country) === String(config.country) &&
      String(a.service) === String(config.service) &&
      poolMatches(a.pool) &&
      ['available', 'resend_failed'].includes(String(a.status || 'available')) &&
      (!a.resendCooldownUntil || Date.now() > new Date(a.resendCooldownUntil).getTime()) &&
      Number(a.useCount || 0) > 0 &&
      Number(a.useCount || 0) < Number(a.maxUses || maxUses) &&
      a.orderid
    )
    .sort((a, b) => Number(b.useCount || 0) - Number(a.useCount || 0) || String(a.createdAt).localeCompare(String(b.createdAt)))[0];
}


function isPortOccupiedError(err) {
  const txt = JSON.stringify(err?.details || {}) + ' ' + String(err?.message || '');
  return /PORT_OCCUPIED|available slots are currently occupied|try again in 5 minutes/i.test(txt);
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
      if (!isPortOccupiedError(e)) throw e;
    }
  }
  const err = new Error('当前号码暂时繁忙，请稍后再试');
  err.status = 503;
  err.publicMessage = true;
  err.details = { type: 'ALL_POOLS_OCCUPIED', triedPools: candidates, errors };
  throw err;
}

async function refundIfEligible(dbSnapshot, sessionId) {
  const session = dbSnapshot.sessions.find(s => s.id === sessionId);
  if (!session) return { skipped: true, reason: 'session_not_found' };
  const account = dbSnapshot.accounts.find(a => a.id === session.accountId);
  if (!account) return { skipped: true, reason: 'account_not_found' };
  if (session.reused || account.source !== 'new' || Number(account.useCount || 0) > 0) {
    return { skipped: true, reason: 'not_eligible' };
  }
  const result = await cancelSms(getRuntimeConfig(dbSnapshot), account.orderid);
  transact(db => {
    const s = db.sessions.find(x => x.id === sessionId);
    const a = db.accounts.find(x => x.id === account.id);
    if (s) { s.refundStatus = 'refunded'; s.refundResult = result; s.updatedAt = nowIso(); }
    if (a && Number(a.useCount || 0) === 0) { a.status = 'refunded'; a.refundResult = result; a.updatedAt = nowIso(); }
    db.logs.unshift({ id: makeId('log'), type: 'refund', sessionId, accountId: account.id, result, createdAt: nowIso() });
    audit(db, null, 'system.refund', { sessionId, accountId: account.id, phone: account.phone, result });
  });
  return result;
}

async function allocateSession(cdkCode) {
  const db = readDb();
  const config = getRuntimeConfig(db);
  const cdk = db.cdks.find(x => x.code.toUpperCase() === cdkCode);
  if (!cdk) throw Object.assign(new Error('CDK 不可用'), { status: 400 });
  if (!['active'].includes(cdk.status || 'active')) throw Object.assign(new Error('CDK 不可用'), { status: 400 });
  if (!config.mockMode && !config.apiKey) throw Object.assign(new Error('服务暂时不可用，请稍后再试'), { status: 503, publicMessage: true });

  const reusable = findReusableAccount(db, config);
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
        }
        audit(wdb, null, 'system.resend_failed_cooldown', { accountId: reusable.id, phone: reusable.phone, cooldownSeconds: cooldown, error: e.message, details: e.details || null });
      });
      return allocateSession(cdkCode);
    }
    return transact(wdb => {
      const c = wdb.cdks.find(x => x.code.toUpperCase() === cdkCode);
      const a = wdb.accounts.find(x => x.id === reusable.id);
      if (!c || (c.status || 'active') !== 'active') throw Object.assign(new Error('CDK 不可用'), { status: 400 });
      if (!a || Number(a.useCount || 0) >= Number(a.maxUses || config.maxAccountUses)) throw Object.assign(new Error('号码刚刚变为不可用，请重试'), { status: 409 });
      a.status = 'waiting';
      a.updatedAt = nowIso();
      const sessionToken = randomToken();
      const session = {
        id: makeId('sess'), sessionTokenHash: hashToken(sessionToken), cdk: c.code, accountId: a.id, orderid: a.orderid, phone: a.phone,
        country: a.country, service: a.service, pool: a.pool || '', status: 'waiting', counted: false,
        reused: true, createdAt: nowIso(), updatedAt: nowIso(), deadlineAt: addSecondsIso(config.timeoutSeconds || 120),
      };
      c.status = 'reserved'; c.reservedAt = session.createdAt; c.reservedSessionId = session.id;
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
    const c = wdb.cdks.find(x => x.code.toUpperCase() === cdkCode);
    if (!c || (c.status || 'active') !== 'active') throw Object.assign(new Error('CDK 不可用'), { status: 400 });
    const account = {
      id: makeId('acct'), orderid, phone, country: String(config.country), service: String(config.service), pool: String(poolUsed || config.pool || ''),
      useCount: 0, maxUses: Number(config.maxAccountUses || 3), status: 'waiting', source: 'new', upstream,
      createdAt: nowIso(), updatedAt: nowIso(), lastMessageAt: null,
    };
    const sessionToken = randomToken();
    const session = {
      id: makeId('sess'), sessionTokenHash: hashToken(sessionToken), cdk: c.code, accountId: account.id, orderid, phone,
      country: account.country, service: account.service, pool: account.pool, status: 'waiting', counted: false,
      reused: false, createdAt: nowIso(), updatedAt: nowIso(), deadlineAt: addSecondsIso(config.timeoutSeconds || 120),
    };
    c.status = 'reserved'; c.reservedAt = session.createdAt; c.reservedSessionId = session.id;
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
      config: { timeoutSeconds: readDb().config.timeoutSeconds, pollIntervalSeconds: readDb().config.pollIntervalSeconds },
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
        if (s) { s.status = 'timeout'; s.updatedAt = nowIso(); }
        if (a && Number(a.useCount || 0) === 0 && !session.reused) { a.status = 'failed'; a.updatedAt = nowIso(); }
        else if (a && session.reused) { a.status = 'resend_failed'; a.resendCooldownUntil = addSecondsIso(wdb.config.resendCooldownSeconds || 300); a.updatedAt = nowIso(); }
        audit(wdb, req, 'user.session_timeout', { sessionId, accountId: account.id, phone: account.phone });
      });
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
      const c = wdb.cdks.find(x => x.code.toUpperCase() === s.cdk.toUpperCase());
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

    transact(db => {
      const s = db.sessions.find(x => x.id === oldId);
      const a = oldAccount ? db.accounts.find(x => x.id === oldAccount.id) : null;
      if (s) { s.status = 'changed'; s.updatedAt = nowIso(); }
      const c = db.cdks.find(x => x.code.toUpperCase() === oldSession.cdk.toUpperCase());
      if (c && c.status === 'reserved' && c.reservedSessionId === oldId) { c.status = 'active'; c.reservedSessionId = null; c.reservedAt = null; }
      if (a && Number(a.useCount || 0) === 0 && !s.reused) { a.status = 'failed'; a.updatedAt = nowIso(); }
      else if (a && s?.reused) { a.status = 'resend_failed'; a.resendCooldownUntil = addSecondsIso(db.config.resendCooldownSeconds || 300); a.updatedAt = nowIso(); }
      db.logs.unshift({ id: makeId('log'), type: 'change_number', sessionId: oldId, accountId: oldAccount?.id, createdAt: nowIso() });
      audit(db, req, 'user.change_number', { sessionId: oldId, accountId: oldAccount?.id, phone: oldAccount?.phone });
    });

    if (oldAccount && !oldSession.reused && Number(oldAccount.useCount || 0) === 0) {
      try { await refundIfEligible(snapshot, oldId); } catch (e) { audit(readDb(), req, 'system.refund_error', { sessionId: oldId, message: e.message, details: e.details || null }); }
    }

    const allocated = await allocateSession(oldSession.cdk.toUpperCase());
    res.json({ success: 1, ...frontendSessionPayload(allocated.session, allocated.account), sessionToken: allocated.sessionToken, config: { timeoutSeconds: readDb().config.timeoutSeconds, pollIntervalSeconds: readDb().config.pollIntervalSeconds } });
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
  if (!safeEqual(req.body?.adminToken, ADMIN_TOKEN)) { transact(db => audit(db, req, 'admin.login_failed')); return res.status(401).json({ success: 0, message: '认证失败' }); }
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
    logs: scrubSensitive(db.logs.slice(0, 100)),
    auditLogs: scrubSensitive((db.auditLogs || []).slice(0, 300)),
  });
});

app.post('/api/admin/config', requireSameOrigin, requireAdmin, (req, res) => {
  const allowed = ['apiKey', 'country', 'service', 'pool', 'maxPrice', 'pricingOption', 'maxAccountUses', 'timeoutSeconds', 'pollIntervalSeconds', 'mockMode', 'mockReceiveAfterChecks', 'purchaseEnabled', 'purchaseUrl', 'purchaseTextZh', 'purchaseTextEn', 'resendCooldownSeconds'];
  const updated = transact(db => {
    for (const k of allowed) {
      if (req.body[k] !== undefined) {
        if (['maxAccountUses', 'timeoutSeconds', 'pollIntervalSeconds', 'mockReceiveAfterChecks', 'resendCooldownSeconds'].includes(k)) db.config[k] = Number(req.body[k]);
        else if (k === 'mockMode' || k === 'purchaseEnabled') db.config[k] = req.body[k] === true || req.body[k] === 'true' || req.body[k] === '1' || req.body[k] === 'on';
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

app.get('/api/catalog/countries', requireAdmin, async (req, res, next) => { try { res.json({ success: 1, data: await listCountries(getRuntimeConfig(readDb())) }); } catch (e) { next(e); } });
app.get('/api/catalog/services', requireAdmin, async (req, res, next) => { try { res.json({ success: 1, data: await listServices(getRuntimeConfig(readDb())) }); } catch (e) { next(e); } });
app.get('/api/catalog/pools', requireAdmin, async (req, res, next) => { try { res.json({ success: 1, data: await listPools(getRuntimeConfig(readDb())) }); } catch (e) { next(e); } });
app.post('/api/sms/price', requireAdmin, async (req, res, next) => { try { res.json({ success: 1, data: await getPrice(getRuntimeConfig(readDb()), req.body) }); } catch (e) { transact(db => audit(db, req, 'admin.price_error', { message: e.message, details: e.details || null })); next(e); } });
app.post('/api/sms/stock', requireAdmin, async (req, res, next) => { try { res.json({ success: 1, data: await getStock(getRuntimeConfig(readDb()), req.body) }); } catch (e) { transact(db => audit(db, req, 'admin.stock_error', { message: e.message, details: e.details || null })); next(e); } });

app.use((err, req, res, next) => {
  const status = err.status || (err instanceof SmsPoolError ? err.status : 500);
  const isAdminReq = req.path.startsWith('/api/admin');
  const safeClientMessages = ['请输入 CDK','CDK 不可用','已收到短信，不能更换号码','会话不存在','号码不存在','无权访问该会话','已超时，可以更换号码'];
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

app.listen(PORT, HOST, () => {
  console.log(`GPTSMS front site running: http://${HOST}:${PORT}/`);
  console.log(`GPTSMS admin site running: http://${HOST}:${PORT}${ADMIN_PATH}`);
});
