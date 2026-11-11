const test = require('node:test');
const assert = require('node:assert/strict');
const {
  createDeveloperTestPasswordHash,
  isLoopbackAddress,
  verifyDeveloperTestPassword
} = require('./developer-test-access');

test('developer test password hashes validate without storing plaintext', () => {
  const hash = createDeveloperTestPasswordHash('example test password');
  assert.notEqual(hash, 'example test password');
  assert.equal(verifyDeveloperTestPassword('example test password', hash), true);
  assert.equal(verifyDeveloperTestPassword('incorrect password', hash), false);
  assert.equal(verifyDeveloperTestPassword('x'.repeat(129), hash), false);
  assert.equal(verifyDeveloperTestPassword('example test password', 'invalid'), false);
});

test('developer test access accepts loopback addresses only', () => {
  assert.equal(isLoopbackAddress('127.0.0.1'), true);
  assert.equal(isLoopbackAddress('127.5.6.7'), true);
  assert.equal(isLoopbackAddress('::1'), true);
  assert.equal(isLoopbackAddress('::ffff:127.0.0.1'), true);
  assert.equal(isLoopbackAddress('192.168.1.20'), false);
  assert.equal(isLoopbackAddress('localhost'), false);
});
