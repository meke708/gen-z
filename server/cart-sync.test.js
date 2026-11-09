const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeCartItems, normalizeSavedCartItems } = require('./server');

const productIds = Array.from({ length: 21 }, (_, index) => (index + 1).toString(16).padStart(24, '0'));

test('cart sync accepts an empty cart and at most twenty unique products', () => {
  assert.deepEqual(normalizeSavedCartItems([]), []);
  assert.equal(normalizeSavedCartItems(productIds.slice(0, 20).map((id) => ({ id, quantity: 1 }))).length, 20);
  assert.throws(() => normalizeSavedCartItems(productIds.map((id) => ({ id, quantity: 1 }))), /up to 20/);
});

test('saved cart rejects duplicate products and invalid quantities', () => {
  assert.throws(() => normalizeSavedCartItems([
    { id: productIds[0], quantity: 1 },
    { id: productIds[0], quantity: 2 }
  ]), /duplicate product/);
  assert.throws(() => normalizeSavedCartItems([
    { id: productIds[0], quantity: 1 },
    { id: productIds[0].toUpperCase(), quantity: 1 }
  ]), /duplicate product/);
  assert.throws(() => normalizeSavedCartItems([{ id: productIds[0], quantity: 100 }]), /invalid product or quantity/);
});

test('checkout cart validation also caps distinct products at twenty', () => {
  assert.equal(normalizeCartItems(productIds.slice(0, 20).map((id) => ({ id, quantity: 1 }))).length, 20);
  assert.throws(() => normalizeCartItems(productIds.map((id) => ({ id, quantity: 1 }))), /20 different products/);
});
