export function json(res, status, payload) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(JSON.stringify(payload));
}

export function text(res, status, payload, contentType = 'text/plain; charset=utf-8') {
  res.writeHead(status, {
    'Content-Type': contentType,
    'Cache-Control': 'no-store',
  });
  res.end(payload);
}

function codedError(code, message) {
  const err = new Error(message || code);
  err.code = code;
  return err;
}

export async function readJson(req, maxBytes = 1024 * 1024) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBytes) {
      throw codedError('PAYLOAD_TOO_LARGE', 'Request payload exceeds allowed size.');
    }
    chunks.push(chunk);
  }
  if (chunks.length === 0) {
    return {};
  }

  const raw = Buffer.concat(chunks).toString('utf8').trim();
  if (!raw) {
    return {};
  }

  try {
    return JSON.parse(raw);
  } catch {
    throw codedError('INVALID_JSON', 'Malformed JSON request body.');
  }
}

export function notFound(res) {
  json(res, 404, {
    error: {
      code: 'NOT_FOUND',
      message: 'Resource does not exist or is not visible to caller.',
    },
  });
}

export function sendError(res, status, code, message, traceId) {
  json(res, status, {
    error: {
      code,
      message,
      traceId,
    },
  });
}
