import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import dotenv from 'dotenv';
import { encryptSecret, decryptSecret } from './crypto.js';

dotenv.config();

export const DB_PATH = path.resolve(process.env.DATABASE_PATH || './data/app.json');

export const DEFAULT_CONFIG = {
  apiKey: process.env.SMSPOOL_API_KEY ? encryptSecret(process.env.SMSPOOL_API_KEY) : '',
  country: process.env.DEFAULT_COUNTRY || 'US',
  service: process.env.DEFAULT_SERVICE || '1',
  pool: process.env.DEFAULT_POOL || '',
  maxPrice: process.env.DEFAULT_MAX_PRICE || '',
  pricingOption: process.env.DEFAULT_PRICING_OPTION || '',
  maxAccountUses: Number(process.env.MAX_ACCOUNT_USES || 3),
  timeoutSeconds: Number(process.env.TIMEOUT_SECONDS || 300),
  changeNumberAfterSeconds: Number(process.env.CHANGE_NUMBER_AFTER_SECONDS || 120),
  pollIntervalSeconds: Number(process.env.POLL_INTERVAL_SECONDS || 5),
  mockMode: ['true','1','yes'].includes(String(process.env.MOCK_SMSPOOL || '').toLowerCase()),
  mockReceiveAfterChecks: Number(process.env.MOCK_RECEIVE_AFTER_CHECKS || 2),
  purchaseEnabled: String(process.env.PURCHASE_ENABLED || 'true').toLowerCase() !== 'false',
  purchaseUrl: process.env.PURCHASE_URL || '',
  purchaseTextZh: process.env.PURCHASE_TEXT_ZH || '购买',
  purchaseTextEn: process.env.PURCHASE_TEXT_EN || 'Buy',
  resendCooldownSeconds: Number(process.env.RESEND_COOLDOWN_SECONDS || 300),
  numberCooldownSeconds: Number(process.env.NUMBER_COOLDOWN_SECONDS || 30),
  numberPoolPriority: process.env.NUMBER_POOL_PRIORITY || 'manual_first',
  refundRetrySeconds: Number(process.env.REFUND_RETRY_SECONDS || 600),
  successfulReuseThreshold: Number(process.env.SUCCESSFUL_REUSE_THRESHOLD || 5),
  reuseUsedNumbersEnabled: String(process.env.REUSE_USED_NUMBERS_ENABLED || 'true').toLowerCase() !== 'false',
};

const DEFAULT_DB = {
  config: DEFAULT_CONFIG,
  cdks: [],
  accounts: [],
  sessions: [],
  logs: [],
  auditLogs: [],
  clients: [],
  billingLogs: [],
  meta: { version: 2, createdAt: new Date().toISOString() },
};

function normalizeDb(db) {
  db.config = { ...DEFAULT_CONFIG, ...(db.config || {}) };
  if (process.env.MOCK_SMSPOOL) db.config.mockMode = ['true','1','yes'].includes(String(process.env.MOCK_SMSPOOL).toLowerCase());
  if (process.env.MOCK_RECEIVE_AFTER_CHECKS) db.config.mockReceiveAfterChecks = Number(process.env.MOCK_RECEIVE_AFTER_CHECKS);
  if (process.env.TIMEOUT_SECONDS) db.config.timeoutSeconds = Number(process.env.TIMEOUT_SECONDS);
  if (process.env.CHANGE_NUMBER_AFTER_SECONDS) db.config.changeNumberAfterSeconds = Number(process.env.CHANGE_NUMBER_AFTER_SECONDS);
  if (process.env.REFUND_RETRY_SECONDS) db.config.refundRetrySeconds = Number(process.env.REFUND_RETRY_SECONDS);
  if (process.env.NUMBER_COOLDOWN_SECONDS) db.config.numberCooldownSeconds = Number(process.env.NUMBER_COOLDOWN_SECONDS);
  if (process.env.NUMBER_POOL_PRIORITY) db.config.numberPoolPriority = String(process.env.NUMBER_POOL_PRIORITY);
  if (process.env.SUCCESSFUL_REUSE_THRESHOLD) db.config.successfulReuseThreshold = Number(process.env.SUCCESSFUL_REUSE_THRESHOLD);
  if (process.env.REUSE_USED_NUMBERS_ENABLED) db.config.reuseUsedNumbersEnabled = String(process.env.REUSE_USED_NUMBERS_ENABLED).toLowerCase() !== 'false';
  db.cdks ||= [];
  db.accounts ||= [];
  db.sessions ||= [];
  db.logs ||= [];
  db.auditLogs ||= [];
  db.clients ||= [];
  db.billingLogs ||= [];
  db.meta ||= { version: 2, createdAt: new Date().toISOString() };
  return db;
}

function ensureDb() {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify(DEFAULT_DB, null, 2));
  }
}

export function readDb() {
  ensureDb();
  const raw = fs.readFileSync(DB_PATH, 'utf8');
  const db = raw.trim() ? JSON.parse(raw) : structuredClone(DEFAULT_DB);
  return normalizeDb(db);
}

export function writeDb(db) {
  ensureDb();
  normalizeDb(db);
  const tmp = `${DB_PATH}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_PATH);
}

export function transact(mutator) {
  const db = readDb();
  const result = mutator(db);
  writeDb(db);
  return result;
}

export function nowIso() {
  return new Date().toISOString();
}

export function addSecondsIso(seconds) {
  return new Date(Date.now() + Number(seconds) * 1000).toISOString();
}

export function makeId(prefix = '') {
  const id = crypto.randomBytes(12).toString('hex');
  return prefix ? `${prefix}_${id}` : id;
}

export function makeCdk() {
  return `CDK-${crypto.randomBytes(4).toString('hex').toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
}

export function getRuntimeConfig(dbOrConfig) {
  const cfg = dbOrConfig.config ? dbOrConfig.config : dbOrConfig;
  return { ...cfg, apiKey: decryptSecret(cfg.apiKey || '') };
}

export function safeConfig(config) {
  return { ...config, apiKey: config.apiKey ? '********' : '' };
}

export function storeApiKey(plain) {
  return encryptSecret(plain);
}

