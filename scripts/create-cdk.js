import { transact, makeCdk, nowIso } from '../src/db.js';

const count = Math.min(Math.max(Number(process.argv[2] || 1), 1), 1000);
const note = process.argv.slice(3).join(' ');
const cdks = transact(db => {
  const out = [];
  for (let i = 0; i < count; i++) {
    let code;
    do { code = makeCdk(); } while (db.cdks.some(x => x.code === code));
    db.cdks.unshift({ code, status: 'active', note, createdAt: nowIso(), usedAt: null, usedSessionId: null });
    out.push(code);
  }
  return out;
});
console.log(cdks.join('\n'));
