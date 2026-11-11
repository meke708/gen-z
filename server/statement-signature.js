const { createHmac, timingSafeEqual } = require('node:crypto');

function getStatementSigningKey(value) {
  if (typeof value !== 'string' || !/^[a-f\d]{64}$/i.test(value)) return null;
  return Buffer.from(value, 'hex');
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value instanceof Date) return value.toISOString();
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

function signStatement(statement, key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('Statement signing requires a 32-byte key.');
  return createHmac('sha256', key).update(JSON.stringify(canonicalize(statement))).digest('hex');
}

function verifyStatement(statement, signature, key) {
  if (typeof signature !== 'string' || !/^[a-f\d]{64}$/i.test(signature)) return false;
  const expected = Buffer.from(signStatement(statement, key), 'hex');
  const actual = Buffer.from(signature, 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

module.exports = { getStatementSigningKey, signStatement, verifyStatement };
