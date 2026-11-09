const test = require('node:test');
const assert = require('node:assert/strict');
const { getSafeReturnPath } = require('./server');

test('login return paths preserve valid same-site destinations', () => {
  assert.equal(getSafeReturnPath('/cart'), '/cart');
  assert.equal(getSafeReturnPath('/cart?from=checkout#items'), '/cart?from=checkout#items');
});

test('login return paths reject external, malformed, and recursive login destinations', () => {
  assert.equal(getSafeReturnPath('https://example.com'), '/dashboard');
  assert.equal(getSafeReturnPath('//example.com'), '/dashboard');
  assert.equal(getSafeReturnPath('/\\example.com'), '/dashboard');
  assert.equal(getSafeReturnPath('/login'), '/dashboard');
  assert.equal(getSafeReturnPath('/login?returnTo=%2Fcart'), '/dashboard');
  assert.equal(getSafeReturnPath(undefined), '/dashboard');
});
