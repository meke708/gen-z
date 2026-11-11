const test = require('node:test');
const assert = require('node:assert/strict');
const { NAMIBIAN_BANKS, normalizeBankPayoutAccount, normalizePayoutRequestAmount } = require('./payout-settings');

test('saved payout account accepts only a bank display name, account name, and last four digits', () => {
  assert.deepEqual(normalizeBankPayoutAccount({
    bankName: `  ${NAMIBIAN_BANKS[0]} `,
    accountName: '  Jordan Lee ',
    accountLast4: '1234',
    accountNumber: '1234567890'
  }), {
    account: { bankName: NAMIBIAN_BANKS[0], accountName: 'Jordan Lee', accountLast4: '1234' }
  });
});

test('saved payout account rejects full or malformed account numbers as last-four input', () => {
  assert.match(normalizeBankPayoutAccount({
    bankName: NAMIBIAN_BANKS[0],
    accountName: 'Jordan Lee',
    accountLast4: '1234567890'
  }).error, /last four digits/);
  assert.match(normalizeBankPayoutAccount(null).error, /valid payout account/);
  assert.match(normalizeBankPayoutAccount({
    bankName: 'Not a Namibian bank',
    accountName: 'Jordan Lee',
    accountLast4: '1234'
  }).error, /Namibian bank list/);
});

test('payout account accepts only banks in the Namibian bank list', () => {
  for (const bankName of NAMIBIAN_BANKS) {
    assert.equal(normalizeBankPayoutAccount({
      bankName,
      accountName: 'Jordan Lee',
      accountLast4: '1234'
    }).account.bankName, bankName);
  }
  assert.match(normalizeBankPayoutAccount({
    bankName: 'International Example Bank',
    accountName: 'Jordan Lee',
    accountLast4: '1234'
  }).error, /Namibian bank list/);
});

test('simulated payout requests accept positive amounts up to the available balance', () => {
  assert.deepEqual(normalizePayoutRequestAmount(125.456, 200), { amountNAD: 125.46 });
  assert.match(normalizePayoutRequestAmount(200.01, 200).error, /cannot exceed/);
  assert.match(normalizePayoutRequestAmount(0, 200).error, /valid withdrawal amount/);
  assert.match(normalizePayoutRequestAmount(0.001, 200).error, /at least N\$ 0.01/);
});
