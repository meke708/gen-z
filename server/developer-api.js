const { createHash, randomBytes, randomUUID } = require('node:crypto');

const apiTokenPattern = /^zstmt_live_[A-Za-z0-9_-]{43}$/;

function hashDeveloperToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

function createDeveloperCredentials() {
  const token = `zstmt_live_${randomBytes(32).toString('base64url')}`;
  return {
    appId: randomUUID(),
    token,
    tokenHash: hashDeveloperToken(token),
    tokenLast4: token.slice(-4)
  };
}

function normalizeDeveloperAppName(value) {
  const name = typeof value === 'string' ? value.trim() : '';
  if (!name || name.length > 80) return null;
  return name;
}

function isValidDeveloperToken(value) {
  return typeof value === 'string' && apiTokenPattern.test(value);
}

module.exports = {
  createDeveloperCredentials,
  hashDeveloperToken,
  isValidDeveloperToken,
  normalizeDeveloperAppName
};
