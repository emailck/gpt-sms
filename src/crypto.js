import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

const PREFIX = 'enc:v1:';

function secret() {
  return process.env.APP_SECRET || process.env.ADMIN_TOKEN || 'dev-secret-change-me';
}

function key() {
  return createHash('sha256').update(secret()).digest();
}

export function encryptSecret(plain) {
  if (!plain) return '';
  if (String(plain).startsWith(PREFIX)) return plain;
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key(), iv);
  const encrypted = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return PREFIX + Buffer.concat([iv, tag, encrypted]).toString('base64url');
}

export function decryptSecret(value) {
  if (!value) return '';
  const s = String(value);
  if (!s.startsWith(PREFIX)) return s;
  const raw = Buffer.from(s.slice(PREFIX.length), 'base64url');
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const encrypted = raw.subarray(28);
  const decipher = createDecipheriv('aes-256-gcm', key(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

export function isEncryptedSecret(value) {
  return String(value || '').startsWith(PREFIX);
}
