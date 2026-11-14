const test = require('node:test');
const assert = require('node:assert/strict');
const { createEmailDeliveryConfig, sendAccountEmail } = require('./email-delivery');

const webhookSecret = 'a'.repeat(64);

test('Google Apps Script email configuration requires its HTTPS deployment URL and secret', () => {
  assert.deepEqual(createEmailDeliveryConfig({
    EMAIL_DELIVERY_PROVIDER: 'google_apps_script'
  }), { provider: 'google_apps_script', configured: false });
  assert.throws(() => createEmailDeliveryConfig({
    EMAIL_DELIVERY_PROVIDER: 'google_apps_script',
    EMAIL_WEBHOOK_URL: 'http://script.google.com/macros/s/deployment/exec',
    EMAIL_WEBHOOK_SECRET: webhookSecret
  }), /HTTPS Google Apps Script/);
  assert.throws(() => createEmailDeliveryConfig({
    EMAIL_DELIVERY_PROVIDER: 'google_apps_script',
    EMAIL_WEBHOOK_URL: 'https://script.google.com/macros/s/deployment/exec',
    EMAIL_WEBHOOK_SECRET: 'short'
  }), /secret of at least 32 characters/);
});

test('Google Apps Script email delivery authenticates the JSON request and requires a Sent response', async () => {
  const config = createEmailDeliveryConfig({
    EMAIL_DELIVERY_PROVIDER: 'google_apps_script',
    EMAIL_WEBHOOK_URL: 'https://script.google.com/macros/s/deployment/exec',
    EMAIL_WEBHOOK_SECRET: webhookSecret
  });
  let request;
  await sendAccountEmail(config, {
    to: 'buyer@example.com',
    subject: 'Verify your Z email address',
    text: 'Open the verification link.',
    html: '<p>Open the verification link.</p>'
  }, {
    fetchImpl: async (url, options) => {
      request = { url, options, body: JSON.parse(options.body) };
      return { ok: true, text: async () => 'Sent' };
    }
  });
  assert.equal(request.url, config.webhookUrl);
  assert.equal(request.options.method, 'POST');
  assert.equal(request.options.redirect, 'follow');
  assert.equal(request.options.headers['Content-Type'], 'application/json');
  assert.equal(request.body.secret, webhookSecret);
  assert.equal(request.body.to, 'buyer@example.com');
  assert.equal(request.body.html, '<p>Open the verification link.</p>');

  await assert.rejects(() => sendAccountEmail(config, {
    to: 'buyer@example.com',
    subject: 'Verify your Z email address',
    text: 'Open the verification link.'
  }, {
    fetchImpl: async () => ({ ok: true, text: async () => 'Unauthorized' })
  }), /rejected the request: Unauthorized/);

  await assert.rejects(() => sendAccountEmail(config, {
    to: 'buyer@example.com',
    subject: 'Verify your Z email address',
    text: 'Open the verification link.'
  }, {
    fetchImpl: async () => ({ ok: false, status: 403, text: async () => 'Access denied' })
  }), /returned HTTP 403/);

  await assert.rejects(() => sendAccountEmail(config, {
    to: 'buyer@example.com',
    subject: 'Verify your Z email address',
    text: 'Open the verification link.'
  }, {
    fetchImpl: async () => ({ ok: true, status: 200, text: async () => '<html>Sign in</html>' })
  }), /unexpected response \(HTTP 200\)/);
});

test('SMTP remains configurable and sends through the existing mailer', async () => {
  const config = createEmailDeliveryConfig({
    EMAIL_DELIVERY_PROVIDER: 'smtp',
    SMTP_HOST: 'smtp.example.com',
    SMTP_USER: 'mailer',
    SMTP_PASSWORD: 'configured'
  });
  let sentMessage;
  await sendAccountEmail(config, {
    to: 'buyer@example.com',
    subject: 'Verify your Z email address',
    text: 'Open the verification link.'
  }, {
    from: 'Z <noreply@example.com>',
    smtpMailer: { sendMail: async (message) => { sentMessage = message; } }
  });
  assert.equal(sentMessage.to, 'buyer@example.com');
  assert.equal(sentMessage.from, 'Z <noreply@example.com>');
});
