const test = require('node:test');
const assert = require('node:assert/strict');
const { reconcileWalletBalance } = require('./server');

test('wallet balance without ledger history is shown as unverified, not mismatched', () => {
  const reconciliation = reconcileWalletBalance(42.5, null);

  assert.equal(reconciliation.status, 'unverified');
  assert.equal(reconciliation.accountBalanceNAD, 42.5);
  assert.equal(reconciliation.unverifiedBalanceNAD, 42.5);
  assert.equal(reconciliation.matchedBalanceNAD, null);
});

test('wallet credits, purchase debits, and refunds reconcile against the current balance', () => {
  const reconciliation = reconcileWalletBalance(145, {
    transactionCount: 4,
    firstType: 'seller_credit',
    firstAmountNAD: 20,
    firstBalanceAfterNAD: 120,
    creditsNAD: 50,
    debitsNAD: 10,
    refundsNAD: 5,
    lastBalanceAfterNAD: 145
  });

  assert.equal(reconciliation.status, 'matched');
  assert.equal(reconciliation.openingBalanceNAD, 100);
  assert.equal(reconciliation.expectedBalanceNAD, 145);
  assert.equal(reconciliation.matchedBalanceNAD, 145);
  assert.equal(reconciliation.differenceNAD, 0);
  assert.equal(reconciliation.ledgerIntegrityDifferenceNAD, 0);
});

test('a first wallet purchase debit infers its pre-transaction opening balance', () => {
  const reconciliation = reconcileWalletBalance(70, {
    transactionCount: 1,
    firstType: 'purchase_debit',
    firstAmountNAD: 30,
    firstBalanceAfterNAD: 70,
    creditsNAD: 0,
    debitsNAD: 30,
    refundsNAD: 0,
    lastBalanceAfterNAD: 70
  });

  assert.equal(reconciliation.status, 'matched');
  assert.equal(reconciliation.openingBalanceNAD, 100);
  assert.equal(reconciliation.expectedBalanceNAD, 70);
});

test('wallet reconciliation reports the portion shared by account and ledger balances', () => {
  const reconciliation = reconcileWalletBalance(130, {
    transactionCount: 2,
    firstType: 'seller_credit',
    firstAmountNAD: 50,
    firstBalanceAfterNAD: 150,
    creditsNAD: 50,
    debitsNAD: 0,
    refundsNAD: 0,
    lastBalanceAfterNAD: 150
  });

  assert.equal(reconciliation.status, 'mismatch');
  assert.equal(reconciliation.matchedBalanceNAD, 130);
  assert.equal(reconciliation.differenceNAD, -20);
});

test('wallet reconciliation detects transaction totals that do not match the final ledger snapshot', () => {
  const reconciliation = reconcileWalletBalance(140, {
    transactionCount: 2,
    firstType: 'seller_credit',
    firstAmountNAD: 50,
    firstBalanceAfterNAD: 150,
    creditsNAD: 50,
    debitsNAD: 5,
    refundsNAD: 0,
    lastBalanceAfterNAD: 140
  });

  assert.equal(reconciliation.status, 'mismatch');
  assert.equal(reconciliation.differenceNAD, 0);
  assert.equal(reconciliation.expectedBalanceNAD, 145);
  assert.equal(reconciliation.ledgerIntegrityDifferenceNAD, 5);
});
