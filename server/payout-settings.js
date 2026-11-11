const NAMIBIAN_BANKS = Object.freeze([
  'Banco BIC Namibia',
  'Bank Windhoek',
  'First National Bank Namibia',
  'Letshego Bank Namibia',
  'Nedbank Namibia',
  'Standard Bank Namibia',
  'Trustco Bank Namibia'
]);

function normalizeBankPayoutAccount(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { error: 'Enter valid payout account display details.' };
  }
  const bankName = typeof input.bankName === 'string' ? input.bankName.trim() : '';
  const accountName = typeof input.accountName === 'string' ? input.accountName.trim() : '';
  const accountLast4 = typeof input.accountLast4 === 'string' ? input.accountLast4.trim() : '';
  if (!NAMIBIAN_BANKS.includes(bankName)) {
    return { error: 'Choose a bank from the Namibian bank list.' };
  }
  if (accountName.length < 2 || accountName.length > 80) {
    return { error: 'Account display name must be between 2 and 80 characters.' };
  }
  if (!/^\d{4}$/.test(accountLast4)) {
    return { error: 'Enter only the last four digits for the simulated payout account.' };
  }
  return { account: { bankName, accountName, accountLast4 } };
}

function normalizePayoutRequestAmount(input, availableBalanceNAD) {
  if (typeof input !== 'number' || !Number.isFinite(input) || input <= 0) {
    return { error: 'Enter a valid withdrawal amount.' };
  }
  const amountNAD = Math.round(input * 100) / 100;
  const available = Math.round(Math.max(0, Number(availableBalanceNAD) || 0) * 100) / 100;
  if (amountNAD <= 0) return { error: 'Withdrawal amount must be at least N$ 0.01.' };
  if (amountNAD > available) return { error: 'Withdrawal amount cannot exceed your available Z balance.' };
  return { amountNAD };
}

module.exports = { NAMIBIAN_BANKS, normalizeBankPayoutAccount, normalizePayoutRequestAmount };
