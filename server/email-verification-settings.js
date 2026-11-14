const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function parseEmailVerificationTestEmails(value) {
  if (typeof value !== 'string' || !value.trim()) return [];
  const emails = value.split(',').map((email) => email.trim().toLowerCase()).filter(Boolean);
  if (emails.some((email) => email.length > 254 || !emailPattern.test(email))) {
    throw new Error('EMAIL_VERIFICATION_TEST_EMAILS must contain only valid comma-separated email addresses.');
  }
  return [...new Set(emails)];
}

function isEmailVerificationTestEmail(email, allowedEmails) {
  return typeof email === 'string' && allowedEmails.includes(email.trim().toLowerCase());
}

module.exports = { parseEmailVerificationTestEmails, isEmailVerificationTestEmail };
