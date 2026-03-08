let csrfToken = '';

function loadCsrfToken() {
  if (typeof localStorage === 'undefined') return '';
  try {
    return localStorage.getItem('ss_csrf_token') || '';
  } catch {
    return '';
  }
}

function saveCsrfToken(token) {
  csrfToken = String(token || '').trim();
  if (typeof localStorage === 'undefined') return;
  try {
    if (csrfToken) {
      localStorage.setItem('ss_csrf_token', csrfToken);
    }
  } catch {
    // ignore storage failures
  }
}

csrfToken = loadCsrfToken();

export function decodeJwtPayload(token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length !== 3) return null;
    const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
    return JSON.parse(atob(b64 + pad));
  } catch {
    return null;
  }
}

export async function apiRequest(path, { method = 'GET', token = '', body } = {}) {
  const headers = {
    'Content-Type': 'application/json',
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  if (csrfToken) {
    headers['X-CSRF-Token'] = csrfToken;
  }

  const response = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  const csrfHeader = response.headers.get('x-csrf-token');
  if (csrfHeader) {
    saveCsrfToken(csrfHeader);
  }

  let payload = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }

  if (!response.ok) {
    const message = payload?.error?.message || `Request failed with status ${response.status}`;
    const code = payload?.error?.code || 'REQUEST_FAILED';
    const err = new Error(message);
    err.code = code;
    err.status = response.status;
    throw err;
  }

  return payload?.data;
}
