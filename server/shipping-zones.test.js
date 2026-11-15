const test = require('node:test');
const assert = require('node:assert/strict');
const { resolveShippingZone } = require('./shipping-zones');

test('same-town delivery uses the local rate', () => {
  assert.equal(resolveShippingZone('Oshakati', 'Oshakati'), 'local');
});

test('nearby towns in the same region use the regional rate', () => {
  assert.equal(resolveShippingZone('Oshakati', 'Ongwediva'), 'regional');
  assert.equal(resolveShippingZone('Ongwediva', 'Oshakati'), 'regional');
  assert.equal(resolveShippingZone('Swakopmund', 'Walvis Bay'), 'regional');
});

test('different hub towns retain the hub rate when they are in different regions', () => {
  assert.equal(resolveShippingZone('Windhoek', 'Oshakati'), 'hub');
});

test('towns in different regions and ungrouped custom towns use the remote rate', () => {
  assert.equal(resolveShippingZone('Oshakati', 'Khorixas'), 'remote');
  assert.equal(resolveShippingZone('Custom Town A', 'Custom Town B'), 'remote');
});
