const test = require('node:test');
const assert = require('node:assert/strict');
const { NAMIBIAN_TOWNS, normalizeNamibianTown } = require('./namibian-towns');

test('town list includes common towns across Namibia', () => {
  assert.ok(NAMIBIAN_TOWNS.includes('Windhoek'));
  assert.ok(NAMIBIAN_TOWNS.includes('Katima Mulilo'));
  assert.ok(NAMIBIAN_TOWNS.includes('Lüderitz'));
  assert.ok(NAMIBIAN_TOWNS.length > 50);
});

test('town normalization canonicalizes known towns and accepts well-formed custom towns', () => {
  assert.equal(normalizeNamibianTown('  oshakati  '), 'Oshakati');
  assert.equal(normalizeNamibianTown('  omatako settlement '), 'Omatako Settlement');
});

test('town normalization rejects blank, excessive, and unsafe values', () => {
  assert.equal(normalizeNamibianTown('  '), '');
  assert.equal(normalizeNamibianTown('A'.repeat(81)), '');
  assert.equal(normalizeNamibianTown('<script>alert(1)</script>'), '');
  assert.equal(normalizeNamibianTown(['Windhoek']), '');
  assert.equal(normalizeNamibianTown('Other'), 'Other');
});
