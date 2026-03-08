import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

function base64UrlEncode(buffer) {
  return buffer.toString('base64url');
}

function base64UrlDecode(value) {
  return Buffer.from(value, 'base64url');
}

function ensureSigningKey(filePath) {
  if (fs.existsSync(filePath)) {
    try {
      fs.chmodSync(filePath, 0o600);
    } catch {
      // Best effort on platforms that ignore POSIX mode bits.
    }
    return fs.readFileSync(filePath);
  }

  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const key = crypto.randomBytes(32);
  fs.writeFileSync(filePath, key, { mode: 0o600 });
  try {
    fs.chmodSync(filePath, 0o600);
  } catch {
    // Best effort on platforms that ignore POSIX mode bits.
  }
  return key;
}

export class TokenService {
  constructor({ jwtSigningKeyPath, accessTokenLifetimeMinutes, refreshTokenLifetimeHours }) {
    this.signingKey = ensureSigningKey(jwtSigningKeyPath);
    this.accessTokenLifetimeMinutes = accessTokenLifetimeMinutes;
    this.refreshTokenLifetimeHours = refreshTokenLifetimeHours;
  }

  sign(payload, ttlSeconds) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const now = Math.floor(Date.now() / 1000);
    const claims = { ...payload, iat: now, exp: now + ttlSeconds, jti: payload.jti || crypto.randomUUID() };
    const encodedHeader = base64UrlEncode(Buffer.from(JSON.stringify(header)));
    const encodedPayload = base64UrlEncode(Buffer.from(JSON.stringify(claims)));
    const data = `${encodedHeader}.${encodedPayload}`;
    const signature = crypto.createHmac('sha256', this.signingKey).update(data).digest('base64url');
    return `${data}.${signature}`;
  }

  verify(token) {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('TOKEN_INVALID');
    }

    const [header, payload, signature] = parts;
    const data = `${header}.${payload}`;
    const expected = crypto.createHmac('sha256', this.signingKey).update(data).digest('base64url');

    const signatureBuf = base64UrlDecode(signature);
    const expectedBuf = base64UrlDecode(expected);
    if (signatureBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(signatureBuf, expectedBuf)) {
      throw new Error('TOKEN_INVALID');
    }

    const claims = JSON.parse(base64UrlDecode(payload).toString('utf8'));
    const now = Math.floor(Date.now() / 1000);
    if (claims.exp < now) {
      throw new Error('TOKEN_EXPIRED');
    }
    return claims;
  }

  createAccessToken(user) {
    return this.sign({ sub: user.id, username: user.username, isSuperAdmin: !!user.isSuperAdmin, type: 'access' }, this.accessTokenLifetimeMinutes * 60);
  }

  createRefreshToken(user, parentJti = null) {
    return this.sign({ sub: user.id, type: 'refresh', parentJti }, this.refreshTokenLifetimeHours * 3600);
  }
}
