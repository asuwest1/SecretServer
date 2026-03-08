function normalizeString(value) {
  if (value === null || value === undefined) return '';
  return String(value).trim();
}

function validateLength(value, { min = 0, max = 1024 }) {
  return value.length >= min && value.length <= max;
}

export function validateUsername(value) {
  const username = normalizeString(value);
  if (!validateLength(username, { min: 3, max: 64 })) {
    return { ok: false, error: 'Username must be between 3 and 64 characters.' };
  }

  if (!/^[A-Za-z0-9._@\\-]+$/.test(username)) {
    return { ok: false, error: 'Username contains invalid characters.' };
  }

  return { ok: true, value: username };
}

export function validatePassword(value) {
  const password = String(value || '');
  if (!validateLength(password, { min: 12, max: 256 })) {
    return { ok: false, error: 'Password must be between 12 and 256 characters.' };
  }
  if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
    return { ok: false, error: 'Password must include uppercase, lowercase, number, and symbol.' };
  }
  return { ok: true, value: password };
}

export function validateDisplayName(value) {
  const displayName = normalizeString(value);
  if (!validateLength(displayName, { min: 1, max: 128 })) {
    return { ok: false, error: 'Display name must be between 1 and 128 characters.' };
  }
  return { ok: true, value: displayName };
}

export function validateEmail(value) {
  const email = normalizeString(value).toLowerCase();
  if (!validateLength(email, { min: 3, max: 254 })) {
    return { ok: false, error: 'Email must be between 3 and 254 characters.' };
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { ok: false, error: 'Email format is invalid.' };
  }
  return { ok: true, value: email };
}

export function validateSecretName(value) {
  const name = normalizeString(value);
  if (!validateLength(name, { min: 1, max: 200 })) {
    return { ok: false, error: 'Secret name must be between 1 and 200 characters.' };
  }
  return { ok: true, value: name };
}

export function validateSecretType(value) {
  const type = normalizeString(value || 'password');
  if (!validateLength(type, { min: 1, max: 64 })) {
    return { ok: false, error: 'Secret type must be between 1 and 64 characters.' };
  }
  return { ok: true, value: type };
}

export function validateOptionalText(value, fieldName, maxLength) {
  if (value === undefined || value === null) {
    return { ok: true, value: null };
  }
  const text = normalizeString(value);
  if (!validateLength(text, { min: 0, max: maxLength })) {
    return { ok: false, error: `${fieldName} exceeds maximum length of ${maxLength}.` };
  }
  return { ok: true, value: text || null };
}

export function validateOptionalUrl(value) {
  if (value === undefined || value === null) {
    return { ok: true, value: null };
  }

  const raw = normalizeString(value);
  if (!raw) return { ok: true, value: null };
  if (!validateLength(raw, { min: 1, max: 2048 })) {
    return { ok: false, error: 'URL exceeds maximum length of 2048.' };
  }

  try {
    const parsed = new URL(raw);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { ok: false, error: 'URL must start with http:// or https://.' };
    }
  } catch {
    return { ok: false, error: 'URL format is invalid.' };
  }

  return { ok: true, value: raw };
}

export function validateTags(value) {
  if (value === undefined || value === null) {
    return { ok: true, value: [] };
  }

  if (!Array.isArray(value)) {
    return { ok: false, error: 'Tags must be an array.' };
  }

  if (value.length > 32) {
    return { ok: false, error: 'Tags cannot exceed 32 entries.' };
  }

  const tags = [];
  const seen = new Set();
  for (const tag of value) {
    const t = normalizeString(tag);
    if (!t) continue;
    if (!validateLength(t, { min: 1, max: 64 })) {
      return { ok: false, error: 'Each tag must be between 1 and 64 characters.' };
    }
    const key = t.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      tags.push(t);
    }
  }

  return { ok: true, value: tags };
}

export function validateLargeText(value, fieldName, maxLength) {
  const text = String(value ?? '');
  if (text.length > maxLength) {
    return { ok: false, error: `${fieldName} exceeds maximum length of ${maxLength}.` };
  }
  return { ok: true, value: text };
}

export function normalizeForLookup(value) {
  return normalizeString(value).toLowerCase();
}

