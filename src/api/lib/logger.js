import crypto from 'node:crypto';

const REDACT = /password|secret|key|token|hash/i;

function scrub(value) {
  if (value === null || value === undefined) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((v) => scrub(v));
  }
  if (typeof value !== 'object') {
    return value;
  }
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = REDACT.test(k) ? '[REDACTED]' : scrub(v);
  }
  return out;
}

export function createLogger(component) {
  function log(level, message, data = {}) {
    const line = {
      timestamp: new Date().toISOString(),
      level,
      component,
      message,
      ...scrub(data),
    };
    process.stdout.write(`${JSON.stringify(line)}\n`);
  }

  return {
    debug: (message, data) => log('Debug', message, data),
    info: (message, data) => log('Information', message, data),
    warn: (message, data) => log('Warning', message, data),
    error: (message, data) => log('Error', message, data),
  };
}

export function randomId() {
  return crypto.randomUUID();
}
