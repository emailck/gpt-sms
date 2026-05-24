const BASE_URL = 'https://api.smspool.net';

const mockOrders = new Map();
let mockSeq = 10000;

function mockEnabled(config = {}) {
  return String(config.mockMode || process.env.MOCK_SMSPOOL || '').toLowerCase() === 'true' || String(config.mockMode || '') === '1';
}

function mockOrder(orderid) {
  if (!mockOrders.has(orderid)) {
    mockOrders.set(orderid, { checks: 0, resendCount: 0, code: String(Math.floor(100000 + Math.random() * 900000)) });
  }
  return mockOrders.get(orderid);
}


export class SmsPoolError extends Error {
  constructor(message, status = 500, details = null) {
    super(message);
    this.name = 'SmsPoolError';
    this.status = status;
    this.details = details;
  }
}

function form(payload = {}, apiKey = '', includeKey = true) {
  const body = new URLSearchParams();
  if (includeKey && apiKey) body.set('key', apiKey);
  for (const [k, v] of Object.entries(payload)) {
    if (v !== undefined && v !== null && String(v) !== '') body.set(k, String(v));
  }
  return body;
}

async function parseResponse(res) {
  const text = await res.text();
  let data = text;
  try { data = text ? JSON.parse(text) : {}; } catch {}
  if (!res.ok) throw new SmsPoolError(`SMSPool HTTP ${res.status}`, res.status, data);
  return data;
}

function keyFrom(config) {
  const apiKey = config?.apiKey || process.env.SMSPOOL_API_KEY || '';
  if (!apiKey) throw new SmsPoolError('未配置 SMSPool API Key', 500);
  return apiKey;
}

export async function smspoolPost(config, path, payload = {}, { includeKey = true } = {}) {
  const apiKey = includeKey ? keyFrom(config) : (config?.apiKey || '');
  const res = await fetch(`${BASE_URL}${path}`, { method: 'POST', body: form(payload, apiKey, includeKey) });
  return parseResponse(res);
}

export async function getBalance(config) {
  if (mockEnabled(config)) return { balance: '999.99', mock: true };
  return smspoolPost(config, '/request/balance');
}

export async function listCountries(config = {}) {
  return smspoolPost(config, '/country/retrieve_all', {}, { includeKey: false });
}

export async function listServices(config = {}) {
  return smspoolPost(config, '/service/retrieve_all', {}, { includeKey: false });
}

export async function listPools(config = {}) {
  return smspoolPost(config, '/pool/retrieve_all', {}, { includeKey: false });
}

export async function getPrice(config, { country, service, pool }) {
  return smspoolPost(config, '/request/price', { country, service, pool }, { includeKey: !!(config?.apiKey || process.env.SMSPOOL_API_KEY) });
}

export async function getStock(config, { country, service, pool }) {
  return smspoolPost(config, '/sms/stock', { country, service, pool }, { includeKey: !!(config?.apiKey || process.env.SMSPOOL_API_KEY) });
}

export async function purchaseSms(config, { country, service, pool, max_price, pricing_option, areacode, exclude }) {
  if (mockEnabled(config)) {
    const orderid = `MOCK-${mockSeq++}`;
    mockOrders.set(orderid, { checks: 0, resendCount: 0, code: String(Math.floor(100000 + Math.random() * 900000)) });
    return { success: 1, orderid, phonenumber: `+1555${String(mockSeq).padStart(7, '0')}`, mock: true };
  }
  return smspoolPost(config, '/purchase/sms', { country, service, pool, max_price, pricing_option, quantity: 1, areacode, exclude });
}

export async function checkSms(config, orderid) {
  if (mockEnabled(config)) {
    const o = mockOrder(orderid);
    o.checks += 1;
    if (o.checks >= Number(config.mockReceiveAfterChecks || process.env.MOCK_RECEIVE_AFTER_CHECKS || 2)) {
      return { success: 1, sms: `Your verification code is ${o.code}`, code: o.code, orderid, mock: true };
    }
    return { success: 0, message: 'pending', orderid, mock: true };
  }
  return smspoolPost(config, '/sms/check', { orderid });
}

export async function cancelSms(config, orderid) {
  if (mockEnabled(config)) { mockOrders.delete(orderid); return { success: 1, refunded: true, orderid, mock: true }; }
  return smspoolPost(config, '/sms/cancel', { orderid });
}

export async function resendSms(config, orderid) {
  if (mockEnabled(config)) { const o = mockOrder(orderid); o.checks = 0; o.resendCount += 1; o.code = String(Math.floor(100000 + Math.random() * 900000)); return { success: 1, message: 'mock resent', orderid, mock: true }; }
  return smspoolPost(config, '/sms/resend', { orderid });
}

export async function retrieveValidPools(config, { country, service }) {
  if (mockEnabled(config)) return [{ id: '7', pool: '7', name: 'Mock Pool' }];
  return smspoolPost(config, '/pool/retrieve_valid', { country, service, web: 1 }, { includeKey: false });
}
