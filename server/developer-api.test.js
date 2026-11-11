const test = require('node:test');
const assert = require('node:assert/strict');
const {
  createDeveloperCredentials,
  hashDeveloperToken,
  isValidDeveloperToken,
  normalizeDeveloperAppName
} = require('./developer-api');

test('developer credentials create a public app ID and an unguessable token stored as a hash', () => {
  const credentials = createDeveloperCredentials();
  assert.match(credentials.appId, /^[\da-f-]{36}$/i);
  assert.match(credentials.token, /^zstmt_live_[A-Za-z0-9_-]{43}$/);
  assert.equal(credentials.tokenHash, hashDeveloperToken(credentials.token));
  assert.notEqual(credentials.tokenHash, credentials.token);
  assert.equal(credentials.tokenLast4, credentials.token.slice(-4));
  assert.equal(isValidDeveloperToken(credentials.token), true);
  assert.equal(isValidDeveloperToken(credentials.tokenHash), false);
});

test('developer app names are trimmed and bounded', () => {
  assert.equal(normalizeDeveloperAppName('  Partner Portal  '), 'Partner Portal');
  assert.equal(normalizeDeveloperAppName(''), null);
  assert.equal(normalizeDeveloperAppName('x'.repeat(81)), null);
});
