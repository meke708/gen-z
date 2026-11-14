function createEmailDeliveryConfig(environment = process.env) {
  const provider = environment.EMAIL_DELIVERY_PROVIDER || 'smtp';
  if (!['smtp', 'google_apps_script'].includes(provider)) {
    throw new Error('EMAIL_DELIVERY_PROVIDER must be smtp or google_apps_script.');
  }

  if (provider === 'smtp') {
    return {
      provider,
      configured: Boolean(environment.SMTP_HOST && environment.SMTP_USER && environment.SMTP_PASSWORD)
    };
  }

  const webhookUrl = environment.EMAIL_WEBHOOK_URL || '';
  const webhookSecret = environment.EMAIL_WEBHOOK_SECRET || '';
  if (!webhookUrl && !webhookSecret) return { provider, configured: false };
  if (!webhookUrl || webhookSecret.length < 32) {
    throw new Error('Google Apps Script email requires an HTTPS webhook URL and a secret of at least 32 characters.');
  }

  let url;
  try {
    url = new URL(webhookUrl);
  } catch {
    throw new Error('EMAIL_WEBHOOK_URL must be a valid Google Apps Script web app URL.');
  }
  if (url.protocol !== 'https:'
    || url.hostname !== 'script.google.com'
    || !/^\/macros\/s\/[^/]+\/exec\/?$/.test(url.pathname)
    || url.username
    || url.password
    || url.search
    || url.hash) {
    throw new Error('EMAIL_WEBHOOK_URL must be an HTTPS Google Apps Script /macros/s/.../exec URL.');
  }

  return { provider, configured: true, webhookUrl: url.toString(), webhookSecret };
}

async function sendAccountEmail(config, message, {
  smtpMailer,
  from,
  fetchImpl = globalThis.fetch
} = {}) {
  if (!config.configured) throw new Error('Email delivery is not configured.');

  if (config.provider === 'smtp') {
    if (!smtpMailer) throw new Error('SMTP email delivery is not configured.');
    await smtpMailer.sendMail({ from, ...message });
    return;
  }
  if (typeof fetchImpl !== 'function') throw new Error('This Node.js version does not provide fetch for the email webhook.');

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetchImpl(config.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...message, secret: config.webhookSecret }),
      redirect: 'follow',
      signal: controller.signal
    });
    const responseText = (await response.text()).trim();
    if (['Unauthorized', 'Invalid request', 'Invalid email'].includes(responseText)) {
      throw new Error(`Google Apps Script rejected the request: ${responseText}.`);
    }
    if (!response.ok) throw new Error(`Google Apps Script returned HTTP ${response.status}.`);
    if (responseText !== 'Sent') {
      throw new Error(`Google Apps Script returned an unexpected response (HTTP ${response.status}).`);
    }
  } finally {
    clearTimeout(timeout);
  }
}

module.exports = { createEmailDeliveryConfig, sendAccountEmail };
