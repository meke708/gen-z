const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeShopStreetAddress, getPublicShopStreetAddress } = require('./shop-location');

test('street addresses are trimmed and internal whitespace is normalized', () => {
  assert.equal(normalizeShopStreetAddress('  12 Main   Street, Unit 4  '), '12 Main Street, Unit 4');
  assert.equal(normalizeShopStreetAddress('  '), '');
});

test('street address validation rejects oversized, markup, control, and non-string values', () => {
  assert.equal(normalizeShopStreetAddress('A'.repeat(201)), null);
  assert.equal(normalizeShopStreetAddress('<script>alert(1)</script>'), null);
  assert.equal(normalizeShopStreetAddress('12 Main\nStreet'), null);
  assert.equal(normalizeShopStreetAddress(['12 Main Street']), null);
});

test('public shop data hides street addresses unless the seller explicitly enables visibility', () => {
  assert.equal(getPublicShopStreetAddress({ streetAddress: '12 Main Street' }), '');
  assert.equal(getPublicShopStreetAddress({ streetAddress: '12 Main Street', showAddressPublicly: false }), '');
  assert.equal(getPublicShopStreetAddress({ streetAddress: '12 Main Street', showAddressPublicly: true }), '12 Main Street');
});
