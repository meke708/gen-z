const test = require('node:test');
const assert = require('node:assert/strict');
const { getStatementPdfChecks } = require('./statement-pdf');

test('uploaded statement PDF checks compare the signed record values with extracted text', () => {
  const statement = {
    shopName: 'Kavango Crafts',
    walletBalanceNAD: 125.5,
    entries: [{ orderNumber: 'Z-1001', shopName: 'Kavango Crafts', payoutNAD: 80 }],
    walletTransactions: [{
      description: 'Purchase debit',
      amountNAD: 5.5,
      balanceAfterNAD: 120,
      orderNumber: 'Z-1002'
    }]
  };
  const matchingText = 'Kavango Crafts N$125.50 Z-1001 N$80.00 Purchase debit N$5.50 N$120.00 Z-1002';
  assert.ok(getStatementPdfChecks(statement, matchingText).every((check) => check.matched));

  const tamperedText = matchingText.replace('125.50', '925.50');
  const checks = getStatementPdfChecks(statement, tamperedText);
  assert.equal(checks.find((check) => check.label === 'Z balance').matched, false);
  assert.equal(checks.every((check) => check.matched), false);
});
