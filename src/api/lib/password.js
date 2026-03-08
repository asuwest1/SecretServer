import crypto from 'node:crypto';

const LEGACY_SCRYPT_N = 16384;
const SCRYPT_V2 = {
  n: 32768,
  r: 8,
  p: 1,
  keyLen: 64,
  saltLen: 16,
};

async function deriveScrypt(password, salt, keyLen, options) {
  return await new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keyLen, { ...options, maxmem: options.maxmem || 128 * 1024 * 1024 }, (err, buf) => {
      if (err) reject(err);
      else resolve(buf);
    });
  });
}

export async function hashPassword(password) {
  const salt = crypto.randomBytes(SCRYPT_V2.saltLen);
  const derived = await deriveScrypt(password, salt, SCRYPT_V2.keyLen, {
    N: SCRYPT_V2.n,
    r: SCRYPT_V2.r,
    p: SCRYPT_V2.p,
  });

  return `scryptv2$${SCRYPT_V2.n}$${SCRYPT_V2.r}$${SCRYPT_V2.p}$${salt.toString('base64')}$${derived.toString('base64')}`;
}

async function verifyLegacyScrypt(password, hash) {
  const [algorithm, nRaw, saltB64, expectedB64] = hash.split('$');
  if (algorithm !== 'scrypt') {
    return false;
  }

  const n = Number.parseInt(nRaw, 10);
  if (!Number.isFinite(n)) {
    return false;
  }

  const salt = Buffer.from(saltB64 || '', 'base64');
  const expected = Buffer.from(expectedB64 || '', 'base64');
  if (salt.length === 0 || expected.length === 0) {
    return false;
  }

  const actual = await deriveScrypt(password, salt, expected.length, { N: n });
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

async function verifyScryptV2(password, hash) {
  const [algorithm, nRaw, rRaw, pRaw, saltB64, expectedB64] = hash.split('$');
  if (algorithm !== 'scryptv2') {
    return false;
  }

  const n = Number.parseInt(nRaw, 10);
  const r = Number.parseInt(rRaw, 10);
  const p = Number.parseInt(pRaw, 10);
  if (!Number.isFinite(n) || !Number.isFinite(r) || !Number.isFinite(p)) {
    return false;
  }

  const salt = Buffer.from(saltB64 || '', 'base64');
  const expected = Buffer.from(expectedB64 || '', 'base64');
  if (salt.length === 0 || expected.length === 0) {
    return false;
  }

  const actual = await deriveScrypt(password, salt, expected.length, { N: n, r, p });
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

export async function verifyPassword(password, hash) {
  if (!hash || typeof hash !== 'string') {
    return false;
  }

  if (hash.startsWith('scryptv2$')) {
    return verifyScryptV2(password, hash);
  }

  if (hash.startsWith('scrypt$')) {
    return verifyLegacyScrypt(password, hash);
  }

  return false;
}

export function needsPasswordRehash(hash) {
  if (!hash || typeof hash !== 'string') {
    return true;
  }

  if (hash.startsWith('scrypt$')) {
    return true;
  }

  if (hash.startsWith('scryptv2$')) {
    const parts = hash.split('$');
    const n = Number.parseInt(parts[1] || '', 10);
    const r = Number.parseInt(parts[2] || '', 10);
    const p = Number.parseInt(parts[3] || '', 10);
    return n < SCRYPT_V2.n || r < SCRYPT_V2.r || p < SCRYPT_V2.p;
  }

  return true;
}

export { LEGACY_SCRYPT_N };

