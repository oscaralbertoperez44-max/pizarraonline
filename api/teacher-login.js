import crypto from 'node:crypto';

// Protección básica contra intentos repetidos. En funciones serverless la memoria
// puede reiniciarse; sirve como capa adicional, no como rate-limit distribuido.
const attempts = globalThis.__mathBoardTeacherAttempts || new Map();
globalThis.__mathBoardTeacherAttempts = attempts;

const WINDOW_MS = 10 * 60 * 1000;
const MAX_ATTEMPTS = 5;

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length) {
    return forwarded.split(',')[0].trim();
  }
  return req.headers['x-real-ip'] || 'unknown';
}

function safeEqual(a, b) {
  const aBuf = Buffer.from(String(a), 'utf8');
  const bBuf = Buffer.from(String(b), 'utf8');
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

export default function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false });
  }

  const secretPin = process.env.TEACHER_PIN;
  if (!secretPin) {
    console.error('Falta configurar TEACHER_PIN en Vercel.');
    return res.status(500).json({ ok: false });
  }

  const ip = getClientIp(req);
  const now = Date.now();
  const current = attempts.get(ip);

  if (current && now - current.startedAt < WINDOW_MS && current.count >= MAX_ATTEMPTS) {
    const retryAfter = Math.ceil((WINDOW_MS - (now - current.startedAt)) / 1000);
    res.setHeader('Retry-After', String(Math.max(retryAfter, 1)));
    return res.status(429).json({ ok: false });
  }

  const pin = typeof req.body?.pin === 'string' ? req.body.pin : '';
  const valid = pin.length > 0 && pin.length <= 128 && safeEqual(pin, secretPin);

  if (!valid) {
    if (!current || now - current.startedAt >= WINDOW_MS) {
      attempts.set(ip, { count: 1, startedAt: now });
    } else {
      current.count += 1;
      attempts.set(ip, current);
    }
    return res.status(401).json({ ok: false });
  }

  attempts.delete(ip);
  return res.status(200).json({ ok: true });
}
