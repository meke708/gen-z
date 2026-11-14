function normalizePdfText(value) {
  return String(value || '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z\d]/g, '');
}

function formatAmount(value) {
  const amount = Number(value);
  return Number.isFinite(amount) ? amount.toFixed(2) : '';
}

function getClaimExcerpt(text, markers) {
  const lines = String(text || '').split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const normalizedMarkers = markers.map(normalizePdfText).filter(Boolean);
  const matchIndex = lines.findIndex((line) => {
    const normalizedLine = normalizePdfText(line);
    return normalizedMarkers.some((marker) => normalizedLine.includes(marker));
  });
  if (matchIndex < 0) return '';
  return lines.slice(Math.max(0, matchIndex - 1), matchIndex + 2).join(' · ').slice(0, 500);
}

function getStatementPdfChecks(statement, text) {
  const normalizedText = normalizePdfText(text);
  const checks = [];
  const addCheck = (label, value, markers = []) => {
    const expected = normalizePdfText(value);
    if (expected) {
      const matched = normalizedText.includes(expected);
      checks.push({
        label,
        matched,
        expectedValue: String(value),
        ...(!matched ? { claimExcerpt: getClaimExcerpt(text, markers) } : {})
      });
    }
  };

  addCheck('Statement reference', statement.statementId);
  addCheck('Issuer', statement.issuer);
  addCheck('Shop name', statement.shopName);
  addCheck('Z balance', formatAmount(statement.walletBalanceNAD), ['Z balance', 'current balance']);
  statement.entries.forEach((entry, index) => {
    const markers = [entry.orderNumber, entry.shopName];
    addCheck(`Seller order ${index + 1} reference`, entry.orderNumber, markers);
    addCheck(`Seller order ${index + 1} shop`, entry.shopName, markers);
    addCheck(`Seller order ${index + 1} amount`, formatAmount(entry.payoutNAD), markers);
  });
  statement.walletTransactions.forEach((transaction, index) => {
    const markers = [transaction.description, transaction.orderNumber].filter(Boolean);
    addCheck(`Wallet activity ${index + 1} description`, transaction.description, markers);
    addCheck(`Wallet activity ${index + 1} amount`, formatAmount(transaction.amountNAD), markers);
    addCheck(`Wallet activity ${index + 1} resulting balance`, formatAmount(transaction.balanceAfterNAD), markers);
    if (transaction.orderNumber) addCheck(`Wallet activity ${index + 1} order reference`, transaction.orderNumber, markers);
  });

  return checks;
}

module.exports = { getStatementPdfChecks };
