function normalizePdfText(value) {
  return String(value || '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z\d]/g, '');
}

function formatAmount(value) {
  const amount = Number(value);
  return Number.isFinite(amount) ? amount.toFixed(2) : '';
}

function getStatementPdfChecks(statement, text) {
  const normalizedText = normalizePdfText(text);
  const checks = [];
  const addCheck = (label, value) => {
    const expected = normalizePdfText(value);
    if (expected) checks.push({ label, matched: normalizedText.includes(expected) });
  };

  addCheck('Statement reference', statement.statementId);
  addCheck('Issuer', statement.issuer);
  addCheck('Shop name', statement.shopName);
  addCheck('Z balance', formatAmount(statement.walletBalanceNAD));
  statement.entries.forEach((entry, index) => {
    addCheck(`Seller order ${index + 1} reference`, entry.orderNumber);
    addCheck(`Seller order ${index + 1} shop`, entry.shopName);
    addCheck(`Seller order ${index + 1} amount`, formatAmount(entry.payoutNAD));
  });
  statement.walletTransactions.forEach((transaction, index) => {
    addCheck(`Wallet activity ${index + 1} description`, transaction.description);
    addCheck(`Wallet activity ${index + 1} amount`, formatAmount(transaction.amountNAD));
    addCheck(`Wallet activity ${index + 1} resulting balance`, formatAmount(transaction.balanceAfterNAD));
    if (transaction.orderNumber) addCheck(`Wallet activity ${index + 1} order reference`, transaction.orderNumber);
  });

  return checks;
}

module.exports = { getStatementPdfChecks };
