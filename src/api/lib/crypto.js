import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

function ensureKey(filePath) {
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

export class CryptoService {
  constructor({ keyFilePath }) {
    this.mek = ensureKey(keyFilePath);
  }

  generateDek() {
    return crypto.randomBytes(32);
  }

  encryptWithKey(plaintext, key) {
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
    const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
      ciphertext: ciphertext.toString('base64'),
      nonce: nonce.toString('base64'),
      tag: tag.toString('base64'),
    };
  }

  decryptWithKey({ ciphertext, nonce, tag }, key) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(nonce, 'base64'));
    decipher.setAuthTag(Buffer.from(tag, 'base64'));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(ciphertext, 'base64')),
      decipher.final(),
    ]);
    return plaintext.toString('utf8');
  }

  wrapDek(dek) {
    return this.encryptWithKey(dek.toString('base64'), this.mek);
  }

  unwrapDek(encDek) {
    const unwrapped = this.decryptWithKey(encDek, this.mek);
    return Buffer.from(unwrapped, 'base64');
  }

  encryptSecret(plaintext) {
    const dek = this.generateDek();
    const encryptedValue = this.encryptWithKey(plaintext, dek);
    const encryptedDek = this.wrapDek(dek);
    return { encryptedValue, encryptedDek };
  }

  decryptSecret(record) {
    const dek = this.unwrapDek(record.dekEnc);
    return this.decryptWithKey(record.valueEnc, dek);
  }

  // Re-wrap a single DEK envelope under a different MEK without touching the
  // underlying secret ciphertext. Used by the MEK rotation procedure.
  rewrapDek(encDek, newMek) {
    const dekBase64 = this.decryptWithKey(encDek, this.mek);
    return this.encryptWithKey(dekBase64, newMek);
  }

  // Rotate the master encryption key across all DEK envelopes in the store.
  // After this call this.mek is updated to newMek; callers must persist the
  // store and write newMek to the key file before restarting the server.
  //
  // Only the DEK wrappers change — the secret ciphertext is untouched, making
  // rotation fast regardless of the number of secrets.
  rotateMek(newMek, store) {
    for (const secret of store.secrets) {
      secret.dekEnc = this.rewrapDek(secret.dekEnc, newMek);
    }
    for (const version of store.secretVersions) {
      version.dekEnc = this.rewrapDek(version.dekEnc, newMek);
    }
    for (const user of store.users) {
      if (user.mfaSecretEnc) {
        user.mfaSecretEnc.dekEnc = this.rewrapDek(user.mfaSecretEnc.dekEnc, newMek);
      }
      if (user.mfaPendingSecretEnc) {
        user.mfaPendingSecretEnc.dekEnc = this.rewrapDek(user.mfaPendingSecretEnc.dekEnc, newMek);
      }
    }
    this.mek = newMek;
  }
}
