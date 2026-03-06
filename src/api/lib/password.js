import crypto from 'node:crypto';

const SCRYPT_N = 16384;

export async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derived = await new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, { N: SCRYPT_N }, (err, buf) => {
      if (err) reject(err);
      else resolve(buf);
    });
  });
  return `scrypt$${SCRYPT_N}$${salt.toString('base64')}$${derived.toString('base64')}`;
}

export async function verifyPassword(password, hash) {
  const [algorithm, nRaw, saltB64, expectedB64] = hash.split('$');
  if (algorithm !== 'scrypt') {
    return false;
  }
  const n = Number.parseInt(nRaw, 10);
  const salt = Buffer.from(saltB64, 'base64');
  const expected = Buffer.from(expectedB64, 'base64');
  const actual = await new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, expected.length, { N: n }, (err, buf) => {
      if (err) reject(err);
      else resolve(buf);
    });
  });
  return crypto.timingSafeEqual(actual, expected);
}
