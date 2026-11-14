const test = require('node:test');
const assert = require('node:assert/strict');
const {
  getWalletBalanceChange,
  isWalletDebitType,
  reconcileWalletBalance,
  shouldAutoCorrectWalletBalance
} = require('./server');

test('wallet balance without ledger history is shown as unverified, not mismatched', () => {
  const reconciliation = reconcileWalletBalance(42.5, null);

  assert.equal(reconciliation.status, 'unverified');
  assert.equal(reconciliation.accountBalanceNAD, 42.5);
  assert.equal(reconciliation.unverifiedBalanceNAD, 42.5);
  assert.equal(reconciliation.matchedBalanceNAD, null);
  assert.match(reconciliation.description, /no ledger evidence to verify it/);
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
  assert.match(reconciliation.description, /both equal N\$ 145\.00/);
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

test('a first simulated withdrawal debit infers its pre-transaction opening balance', () => {
  const reconciliation = reconcileWalletBalance(70, {
    transactionCount: 1,
    firstType: 'withdrawal_debit',
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

test('simulated withdrawals use the same debit direction as purchases', () => {
  assert.equal(isWalletDebitType('withdrawal_debit'), true);
  assert.equal(isWalletDebitType('purchase_debit'), true);
  assert.equal(isWalletDebitType('seller_credit'), false);
  assert.equal(getWalletBalanceChange('withdrawal_debit', 30), -30);
});

test('wallet reconciliation explains account funds missing from the ledger', () => {
  const reconciliation = reconcileWalletBalance(170, {
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
  assert.equal(reconciliation.matchedBalanceNAD, 150);
  assert.equal(reconciliation.differenceNAD, 20);
  assert.match(reconciliation.description, /N\$ 20\.00 is present in the account balance/);
  assert.match(reconciliation.description, /not, by itself, proof of fraud/);
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
  assert.match(reconciliation.description, /imply N\$ 145\.00, but the latest ledger snapshot is N\$ 140\.00/);
  assert.equal(shouldAutoCorrectWalletBalance(reconciliation), false);
});

test('wallet balances are auto-correctable only when a nonempty ledger is internally consistent', () => {
  const consistentMismatch = reconcileWalletBalance(170, {
    transactionCount: 2,
    firstType: 'seller_credit',
    firstAmountNAD: 50,
    firstBalanceAfterNAD: 150,
    creditsNAD: 50,
    debitsNAD: 0,
    refundsNAD: 0,
    lastBalanceAfterNAD: 150
  });
  const unverified = reconcileWalletBalance(170, null);
  const matched = reconcileWalletBalance(150, {
    transactionCount: 2,
    firstType: 'seller_credit',
    firstAmountNAD: 50,
    firstBalanceAfterNAD: 150,
    creditsNAD: 50,
    debitsNAD: 0,
    refundsNAD: 0,
    lastBalanceAfterNAD: 150
  });

  assert.equal(shouldAutoCorrectWalletBalance(consistentMismatch), true);
  assert.equal(shouldAutoCorrectWalletBalance(unverified), false);
  assert.equal(shouldAutoCorrectWalletBalance(matched), false);
});
