const test = require('node:test');
const assert = require('node:assert/strict');
const { getStatementSigningKey, signStatement, verifyStatement } = require('./statement-signature');

test('statement signing key accepts only a 32-byte hex secret', () => {
  assert.equal(getStatementSigningKey('a'.repeat(64)).length, 32);
  assert.equal(getStatementSigningKey('short'), null);
  assert.equal(getStatementSigningKey('g'.repeat(64)), null);
});

test('statement signatures verify exact data independent of object key order', () => {
  const key = Buffer.alloc(32, 7);
  const statement = { statementId: 'ref-1', issuedAt: new Date('2026-01-01T00:00:00.000Z'), totals: { spent: 4, balance: 8 } };
  const signature = signStatement(statement, key);
  assert.equal(verifyStatement({
    totals: { balance: 8, spent: 4 },
    issuedAt: new Date('2026-01-01T00:00:00.000Z'),
    statementId: 'ref-1'
  }, signature, key), true);
  assert.equal(verifyStatement({ ...statement, totals: { ...statement.totals, balance: 9 } }, signature, key), false);
  assert.equal(verifyStatement({ ...statement, issuedAt: new Date('2026-01-02T00:00:00.000Z') }, signature, key), false);
  assert.equal(verifyStatement(statement, 'invalid', key), false);
});
