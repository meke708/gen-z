const test = require('node:test');
const assert = require('node:assert/strict');

const { createPaymentAdapter, isMatchingDpoPayment } = require('./payment-adapter');

const companyToken = 'B3F59BE7-0756-420E-BB88-1D98E7A6B040';
const transactionToken = '72983CAC-5DB1-4C7F-BD88-352066B71592';

test('DPO creates a hosted sandbox payment from the order amount and return URL', async () => {
  let request;
  const adapter = createPaymentAdapter('dpo', {
    companyToken,
    serviceTypeId: '54841',
    fetchImpl: async (url, options) => {
      request = { url, options };
      return { ok: true, status: 200, text: async () => '<API3G><Result>000</Result><TransToken>' + transactionToken + '</TransToken></API3G>' };
    }
  });

  const intent = await adapter.createIntent('Z-123-ABCD', {
    amountNAD: 12.5,
    customerEmail: 'buyer@example.com',
    returnUrl: 'http://localhost:3001/api/payments/dpo/return?orderNumber=Z-123-ABCD',
    paymentTimeoutMinutes: 15
  });

  assert.equal(adapter.mode, 'dpo');
  assert.equal(intent.reference, transactionToken);
  assert.equal(intent.status, 'pending');
  assert.equal(intent.redirectUrl, `https://secure.3gdirectpay.com/payv2.php?ID=${transactionToken}`);
  assert.equal(request.url, 'https://secure.3gdirectpay.com/API/v6/');
  assert.match(request.options.body, /<PaymentAmount>12\.50<\/PaymentAmount>/);
  assert.match(request.options.body, /<PaymentCurrency>NAD<\/PaymentCurrency>/);
  assert.match(request.options.body, /<CompanyRef>Z-123-ABCD<\/CompanyRef>/);
  assert.match(request.options.body, /<ServiceType>54841<\/ServiceType>/);
  assert.match(request.options.body, /<PTL>15<\/PTL><PTLtype>minutes<\/PTLtype>/);
  assert.match(request.options.body, /<customerEmail>buyer@example\.com<\/customerEmail>/);
});

test('DPO verification returns the provider status and transaction details', async () => {
  let requestBody;
  const adapter = createPaymentAdapter('dpo', {
    companyToken,
    serviceTypeId: '54841',
    fetchImpl: async (_url, options) => {
      requestBody = options.body;
      return {
        ok: true,
        status: 200,
        text: async () => '<API3G><Result>000</Result><TransactionAmount>12.50</TransactionAmount><TransactionCurrency>nad</TransactionCurrency><CompanyRef>Z-123-ABCD</CompanyRef></API3G>'
      };
    }
  });

  const payment = await adapter.verifyIntent(transactionToken);
  assert.match(requestBody, /<Request>verifyToken<\/Request>/);
  assert.match(requestBody, new RegExp(`<TransactionToken>${transactionToken}<\\/TransactionToken>`));
  assert.deepEqual(payment, {
    reference: transactionToken,
    status: 'paid',
    result: '000',
    amountNAD: 12.5,
    currency: 'NAD',
    companyReference: 'Z-123-ABCD'
  });
});

test('DPO payment is accepted only when provider amount, currency, and optional order reference match', () => {
  const payment = {
    status: 'paid',
    amountNAD: 12.5,
    currency: 'NAD',
    companyReference: 'Z-123-ABCD'
  };
  assert.equal(isMatchingDpoPayment(payment, 12.5, 'Z-123-ABCD'), true);
  assert.equal(isMatchingDpoPayment({ ...payment, amountNAD: 12.49 }, 12.5, 'Z-123-ABCD'), false);
  assert.equal(isMatchingDpoPayment({ ...payment, currency: 'USD' }, 12.5, 'Z-123-ABCD'), false);
  assert.equal(isMatchingDpoPayment({ ...payment, companyReference: 'other-order' }, 12.5, 'Z-123-ABCD'), false);
  assert.equal(isMatchingDpoPayment({ ...payment, status: 'pending' }, 12.5, 'Z-123-ABCD'), false);
});

test('DPO non-paid verification remains pending and API errors are explicit', async () => {
  const adapter = createPaymentAdapter('dpo', {
    companyToken,
    serviceTypeId: '54841',
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      text: async () => '<API3G><Result>900</Result><ResultExplanation>Not paid</ResultExplanation></API3G>'
    })
  });
  assert.equal((await adapter.verifyIntent(transactionToken)).status, 'pending');

  const failedAdapter = createPaymentAdapter('dpo', {
    companyToken,
    serviceTypeId: '54841',
    fetchImpl: async () => ({ ok: false, status: 502, text: async () => '' })
  });
  await assert.rejects(() => failedAdapter.verifyIntent(transactionToken), /HTTP 502/);
});

test('DPO adapter rejects invalid credentials, payment inputs, and provider tokens', async () => {
  assert.throws(() => createPaymentAdapter('dpo', { companyToken: '', serviceTypeId: '54841' }), /DPO_COMPANY_TOKEN/);
  assert.throws(() => createPaymentAdapter('dpo', { companyToken, serviceTypeId: 'invalid' }), /DPO_SERVICE_TYPE_ID/);

  const adapter = createPaymentAdapter('dpo', {
    companyToken,
    serviceTypeId: '54841',
    fetchImpl: async () => ({ ok: true, status: 200, text: async () => '<API3G><Result>000</Result></API3G>' })
  });
  await assert.rejects(() => adapter.createIntent('Z-123-ABCD', {
    amountNAD: 0,
    returnUrl: 'http://localhost:3001/return',
    paymentTimeoutMinutes: 15
  }), /amount must be greater than zero/);
  await assert.rejects(() => adapter.verifyIntent('not-a-token'), /Invalid DPO payment token/);
});
