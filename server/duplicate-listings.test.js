const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeDuplicateText, buildProductDuplicateKey } = require('./server');

test('duplicate text normalization ignores case, punctuation, spacing, and accents', () => {
  assert.equal(normalizeDuplicateText('  Café-Shop  '), 'cafe shop');
  assert.equal(normalizeDuplicateText('CAFE shop'), 'cafe shop');
});

test('product duplicate key uses normalized title, description, and category', () => {
  const first = buildProductDuplicateKey({
    title: 'Hand-made Mug',
    description: 'Blue ceramic mug.',
    category: 'Home'
  });
  const equivalent = buildProductDuplicateKey({
    title: 'HAND MADE MUG',
    description: 'Blue ceramic mug',
    category: 'home'
  });
  const differentDetails = buildProductDuplicateKey({
    title: 'Hand-made Mug',
    description: 'Red ceramic mug',
    category: 'Home'
  });
  const differentCategory = buildProductDuplicateKey({
    title: 'Hand-made Mug',
    description: 'Blue ceramic mug.',
    category: 'Art & Crafts'
  });

  assert.equal(first, equivalent);
  assert.notEqual(first, differentDetails);
  assert.notEqual(first, differentCategory);
});
