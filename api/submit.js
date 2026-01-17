const express = require('express');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const handlebars = require('handlebars');
const fs = require('fs');
const path = require('path');

const app = express();

app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

const templateDir = path.join(__dirname, '..', 'templates');
const confirmationTemplate = handlebars.compile(
  fs.readFileSync(path.join(templateDir, 'confirmation.hbs'), 'utf8')
);
const notificationTemplate = handlebars.compile(
  fs.readFileSync(path.join(templateDir, 'notification.hbs'), 'utf8')
);

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

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing ${name}`);
  }
  return value;
}

async function verifyRecaptcha(token, remoteIp) {
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

function normalizeString(value) {
  if (!value) {
    return '';
  }
  return String(value).trim();
}

function validatePayload({ userEmail, userMessage }) {
  if (!userEmail || !userEmail.includes('@')) {
    return 'Invalid email address.';
  }
  if (!userMessage || userMessage.trim().length < 2) {
    return 'Message is required.';
  }
  return null;
}

async function handleSubmit(req, res) {
  try {
    const {
      userName,
      userEmail,
      userMessage,
      userSubject,
      recaptchaToken,
    } = req.body || {};

    const validationError = validatePayload({ userEmail, userMessage });
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    if (!recaptchaToken) {
      return res.status(400).json({ error: 'Missing reCAPTCHA token.' });
    }

    const recaptchaOk = await verifyRecaptcha(
      recaptchaToken,
      req.ip || req.headers['x-forwarded-for']
    );

    if (!recaptchaOk) {
      return res.status(400).json({ error: 'reCAPTCHA validation failed.' });
    }

    const safeName = normalizeString(userName);
    const safeEmail = normalizeString(userEmail);
    const safeMessage = normalizeString(userMessage);
    const safeSubject = normalizeString(userSubject);

    const confirmationHtml = confirmationTemplate({
      userName: safeName,
      userEmail: safeEmail,
      userMessage: safeMessage,
    });

    const notificationHtml = notificationTemplate({
      userName: safeName || 'Unknown',
      userEmail: safeEmail,
      userMessage: safeMessage,
      userSubject: safeSubject,
      submittedAt: new Date().toISOString(),
    });

    const transporter = buildTransporter();

    await transporter.sendMail({
      from: formatFrom(),
      to: safeEmail,
      subject: process.env.CONFIRM_SUBJECT || 'Thanks for reaching out',
      html: confirmationHtml,
    });

    await transporter.sendMail({
      from: formatFrom(),
      to: requireEnv('NOTIFY_EMAIL'),
      replyTo: safeEmail,
      subject:
        process.env.NOTIFY_SUBJECT ||
        `New message from ${safeName || safeEmail}`,
      html: notificationHtml,
    });

    return res.status(200).json({ ok: true });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Unable to send message.' });
  }
}

app.post('/', handleSubmit);
app.post('/submit', handleSubmit);

app.all('*', (req, res) => {
  res.status(405).json({ error: 'Method not allowed.' });
});

if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    console.log(`Listening on http://localhost:${port}`);
  });
}

module.exports = app;
