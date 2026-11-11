const { randomBytes, scryptSync, timingSafeEqual } = require('node:crypto');

function createDeveloperTestPasswordHash(password) {
  if (typeof password !== 'string' || password.length < 1 || password.length > 128) {
    throw new Error('Developer test password must contain 1 to 128 characters.');
  }
  const salt = randomBytes(16).toString('hex');
  const hash = scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyDeveloperTestPassword(password, storedHash) {
  if (typeof password !== 'string' || password.length < 1 || password.length > 128 || typeof storedHash !== 'string') return false;
  const [salt, hash, extra] = storedHash.split(':');
  if (extra !== undefined || !/^[a-f\d]{32}$/i.test(salt || '') || !/^[a-f\d]{128}$/i.test(hash || '')) return false;
  const actual = scryptSync(password, salt, 64);
  const expected = Buffer.from(hash, 'hex');
  return timingSafeEqual(actual, expected);
}

function isLoopbackAddress(address) {
  if (typeof address !== 'string') return false;
  const normalized = address.toLowerCase().replace(/^::ffff:/, '');
  return normalized === '::1' || /^127(?:\.\d{1,3}){3}$/.test(normalized);
}

module.exports = {
  createDeveloperTestPasswordHash,
  isLoopbackAddress,
  verifyDeveloperTestPassword
};
