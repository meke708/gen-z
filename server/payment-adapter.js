const { randomBytes } = require('crypto');

function createPaymentAdapter(mode = 'mock') {
  if (mode !== 'mock') {
    throw new Error('Only the mock payment adapter is configured. DPO requires merchant approval and sandbox credentials.');
  }

  return {
    mode,
    createIntent(orderNumber) {
      return {
        reference: `mock_${orderNumber}_${randomBytes(4).toString('hex')}`,
        status: 'pending'
      };
    },
    confirmIntent(reference) {
      if (typeof reference !== 'string' || !reference.startsWith('mock_')) {
        throw new Error('Invalid mock payment reference.');
      }
      return { reference, status: 'paid', confirmedAt: new Date() };
    }
  };
}

module.exports = { createPaymentAdapter };
