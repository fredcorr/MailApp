import express, { Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import nodemailer from 'nodemailer';
import handlebars from 'handlebars';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const app = express();

// Resolve paths relative to this module (Vercel/ESM friendly).
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Basic Express setup: trust proxy for IPs, parse JSON/form bodies with size limits.
app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// Global rate limit to reduce abuse across both endpoints.
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// Preload and compile email templates once at startup.
const templateDir = path.join(__dirname, '..', 'templates');
const confirmationTemplate = handlebars.compile(
  fs.readFileSync(path.join(templateDir, 'confirmation.hbs'), 'utf8')
);
const notificationTemplate = handlebars.compile(
  fs.readFileSync(path.join(templateDir, 'notification.hbs'), 'utf8')
);

// Build a nodemailer transport from environment config.
function buildTransporter() {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!host) {
    throw new Error('Missing SMTP_HOST');
  }

  return nodemailer.createTransport({
    host,
    port,
    secure: process.env.SMTP_SECURE === 'true',
    auth: user ? { user, pass } : undefined,
  });
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing ${name}`);
  }
  return value;
}

// Allow bypassing reCAPTCHA in non-production when explicitly enabled.
function isRecaptchaBypassEnabled() {
  return process.env.RECAPTCHA_BYPASS === 'true' && process.env.NODE_ENV !== 'production';
}

// Verify reCAPTCHA token with Google's API.
async function verifyRecaptcha(token: string, remoteIp?: string) {
  const secret = requireEnv('RECAPTCHA_SECRET');

  const body = new URLSearchParams({
    secret,
    response: token,
  });

  if (remoteIp) {
    body.append('remoteip', remoteIp);
  }

  const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });

  if (!response.ok) {
    throw new Error('reCAPTCHA verification failed');
  }

  const data = await response.json();
  return data.success === true;
}

function formatFrom() {
  const fromEmail = requireEnv('FROM_EMAIL');
  const fromName = process.env.FROM_NAME;
  if (fromName) {
    return `"${fromName}" <${fromEmail}>`;
  }
  return fromEmail;
}

// Constant-time compare to avoid leaking token info.
function isSameToken(a: string, b: string) {
  if (a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// Pick the first value when a field can be posted multiple times.
function pickFirstValue(value: unknown) {
  if (Array.isArray(value)) {
    return value[0];
  }
  return value;
}

// Main submit handler: verify reCAPTCHA, send confirmation + notification.
async function handleSubmit(req: Request, res: Response) {
  try {
    // Require a shared secret token in the header for server-to-server calls.
    const expectedToken = requireEnv('SUBMISSION_SECRET');
    const providedToken = req.header('x-submit-token') || '';
    if (!providedToken) {
      return res.status(401).json({ error: 'Missing submission token.' });
    }
    if (!isSameToken(providedToken, expectedToken)) {
      return res.status(403).json({ error: 'Invalid submission token.' });
    }

    // Only accept object-like payloads.
    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
      return res.status(400).json({ error: 'Invalid submission payload.' });
    }

    const body = req.body as Record<string, unknown>;
    // Support standard reCAPTCHA field names.
    const recaptchaToken =
      pickFirstValue(body.recaptchaToken) ||
      pickFirstValue(body['g-recaptcha-response']);

    // Allow flexible naming for common fields.
    const rawName = body.userName ?? body.name ?? body.fullName;
    const rawEmail = body.userEmail ?? body.email;
    const safeName = typeof rawName === 'string' ? rawName : '';
    const safeEmail = typeof rawEmail === 'string' ? rawEmail : '';

    if (!isRecaptchaBypassEnabled()) {
      if (!recaptchaToken) {
        return res.status(400).json({ error: 'Missing reCAPTCHA token.' });
      }

      const forwardedFor = Array.isArray(req.headers['x-forwarded-for'])
        ? req.headers['x-forwarded-for'][0]
        : req.headers['x-forwarded-for'];

      const recaptchaOk = await verifyRecaptcha(
        recaptchaToken,
        req.ip || forwardedFor
      );

      if (!recaptchaOk) {
        return res.status(400).json({ error: 'reCAPTCHA validation failed.' });
      }
    }

    const excludedKeys = new Set<string>(['recaptchaToken', 'g-recaptcha-response']);
    const fields = Object.entries(body)
      .filter(([key]) => !excludedKeys.has(key))
      .map(([key, value]) => ({ key, value }));

    // Render templates with only the required data.
    const confirmationHtml = confirmationTemplate({
      userName: safeName,
    });

    const notificationHtml = notificationTemplate({
      fields,
      hasFields: fields.length > 0,
      submittedAt: new Date().toISOString(),
    });

    const transporter = buildTransporter();

    // Only send a confirmation if we have an email address.
    if (safeEmail) {
      await transporter.sendMail({
        from: formatFrom(),
        to: safeEmail,
        subject: process.env.CONFIRM_SUBJECT || 'Thanks for reaching out',
        html: confirmationHtml,
      });
    }

    const notificationSubject =
      process.env.NOTIFY_SUBJECT ||
      (safeName || safeEmail
        ? `New form submission from ${safeName || safeEmail}`
        : 'New form submission');

    // Always notify the internal recipient.
    await transporter.sendMail({
      from: formatFrom(),
      to: requireEnv('NOTIFY_EMAIL'),
      replyTo: safeEmail || undefined,
      subject: notificationSubject,
      html: notificationHtml,
    });

    return res.status(200).json({ ok: true });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Unable to send message.' });
  }
}

// Accept submissions on both root and /submit paths.
app.post('/', handleSubmit);
app.post('/submit', handleSubmit);

// Reject any other method/path with a generic error.
app.use((req, res) => {
  res.status(405).json({ error: 'Method not allowed.' });
});

export default app;
