const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeSavedWishlistIds } = require('./server');

const productIds = Array.from({ length: 501 }, (_, index) => (index + 1).toString(16).padStart(24, '0'));

test('wishlist validation accepts empty and up to 500 valid product IDs', () => {
  assert.deepEqual(normalizeSavedWishlistIds([]), []);
  assert.equal(normalizeSavedWishlistIds(productIds.slice(0, 500)).length, 500);
  assert.throws(() => normalizeSavedWishlistIds(productIds), /up to 500/);
});

test('wishlist validation rejects invalid and duplicate product IDs', () => {
  assert.throws(() => normalizeSavedWishlistIds(['not-a-product']), /invalid product/);
  assert.throws(() => normalizeSavedWishlistIds([
    productIds[0],
    productIds[0].toUpperCase()
  ]), /duplicate product/);
});
