const test = require('node:test');
const assert = require('node:assert/strict');
const {
  isEmailVerificationLinkAllowed,
  isEmailVerificationTestEmail,
  parseEmailVerificationTestEmails
} = require('./email-verification-settings');

test('verification test email allowlist normalizes and deduplicates addresses', () => {
  const allowedEmails = parseEmailVerificationTestEmails(' Test@Example.com, test@example.com, preview@example.com ');
  assert.deepEqual(allowedEmails, ['test@example.com', 'preview@example.com']);
  assert.equal(isEmailVerificationTestEmail('TEST@example.com', allowedEmails), true);
  assert.equal(isEmailVerificationTestEmail('other@example.com', allowedEmails), false);
});

test('direct verification links can be enabled for all addresses in a test deployment', () => {
  const allowedEmails = [];
  assert.equal(isEmailVerificationLinkAllowed('anyone@example.com', allowedEmails), false);
  assert.equal(isEmailVerificationLinkAllowed('anyone@example.com', allowedEmails, true), true);
});

test('verification test email allowlist can be empty and rejects invalid addresses', () => {
  assert.deepEqual(parseEmailVerificationTestEmails('  '), []);
  assert.throws(() => parseEmailVerificationTestEmails('valid@example.com,not-an-email'), /valid comma-separated/);
});
