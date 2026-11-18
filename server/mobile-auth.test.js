const test = require('node:test');
const assert = require('node:assert/strict');
const { parseMobileBearerToken } = require('./server');

test('mobile bearer parsing accepts only opaque 64-character hexadecimal tokens', () => {
  const token = 'ab'.repeat(32);
  assert.equal(parseMobileBearerToken(`Bearer ${token}`), token);
  assert.equal(parseMobileBearerToken(`bearer ${token}`), token);
  assert.equal(parseMobileBearerToken(`Bearer ${token.toUpperCase()}`), '');
  assert.equal(parseMobileBearerToken('Basic dXNlcjpwYXNz'), '');
  assert.equal(parseMobileBearerToken('Bearer short'), '');
  assert.equal(parseMobileBearerToken(`Bearer ${token} extra`), '');
});
