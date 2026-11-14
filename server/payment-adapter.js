const { randomBytes } = require('crypto');

const DPO_API_URL = 'https://secure.3gdirectpay.com/API/v6/';
const DPO_CHECKOUT_URL = 'https://secure.3gdirectpay.com/payv2.php';
const MAX_DPO_RESPONSE_SIZE = 64 * 1024;
const DPO_TOKEN_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function escapeXml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function getXmlValue(xml, tagName) {
  const expression = new RegExp(`<${tagName}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tagName}\\s*>`, 'i');
  const match = xml.match(expression);
  if (!match) return '';
  return match[1]
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&')
    .trim();
}

function buildDpoApiRequest(companyToken, requestName, contents) {
  return `<?xml version="1.0" encoding="utf-8"?><API3G><CompanyToken>${escapeXml(companyToken)}</CompanyToken><Request>${requestName}</Request>${contents}</API3G>`;
}

function isMatchingDpoPayment(payment, expectedAmountNAD, orderNumber) {
  const paidAmount = Number(payment?.amountNAD);
  const expectedAmount = Number(expectedAmountNAD);
  const roundNAD = (amount) => Math.round((amount + Number.EPSILON) * 100) / 100;
  return payment?.status === 'paid' &&
    Number.isFinite(paidAmount) &&
    Number.isFinite(expectedAmount) &&
    roundNAD(paidAmount) === roundNAD(expectedAmount) &&
    payment.currency === 'NAD' &&
    (!payment.companyReference || payment.companyReference === orderNumber);
}

function createDpoPaymentAdapter({
  companyToken = process.env.DPO_COMPANY_TOKEN,
  serviceTypeId = process.env.DPO_SERVICE_TYPE_ID,
  fetchImpl = globalThis.fetch
} = {}) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(companyToken || '')) {
    throw new Error('DPO_COMPANY_TOKEN must be a DPO sandbox Company Token UUID.');
  }
  if (!/^\d+$/.test(serviceTypeId || '')) {
    throw new Error('DPO_SERVICE_TYPE_ID must be the numeric service type from DPO sandbox credentials.');
  }
  if (typeof fetchImpl !== 'function') {
    throw new Error('This Node.js version must provide fetch to use the DPO sandbox.');
  }

  async function sendRequest(xml) {
    let response;
    try {
      response = await fetchImpl(DPO_API_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/xml; charset=utf-8',
          Accept: 'application/xml'
        },
        body: xml,
        signal: AbortSignal.timeout(15000)
      });
    } catch (error) {
      throw new Error('DPO sandbox request failed. Check the network and try again.', { cause: error });
    }

    if (!response.ok) {
      throw new Error(`DPO sandbox returned HTTP ${response.status}.`);
    }

    const body = await response.text();
    if (Buffer.byteLength(body, 'utf8') > MAX_DPO_RESPONSE_SIZE) {
      throw new Error('DPO sandbox returned an oversized response.');
    }
    if (!/<API3G(?:\s[^>]*)?>/i.test(body)) {
      throw new Error('DPO sandbox returned an invalid XML response.');
    }
    return body;
  }

  return {
    mode: 'dpo',
    async createIntent(orderNumber, { amountNAD, customerEmail, returnUrl, paymentTimeoutMinutes }) {
      const amount = Number(amountNAD);
      if (!Number.isFinite(amount) || amount <= 0) {
        throw new Error('DPO payment amount must be greater than zero.');
      }
      if (typeof orderNumber !== 'string' || !orderNumber || orderNumber.length > 100) {
        throw new Error('A valid order reference is required for DPO checkout.');
      }
      let callbackUrl;
      try {
        callbackUrl = new URL(returnUrl);
      } catch {
        throw new Error('A valid DPO payment return URL is required.');
      }
      if (!['http:', 'https:'].includes(callbackUrl.protocol)) {
        throw new Error('The DPO payment return URL must use HTTP or HTTPS.');
      }
      if (!Number.isInteger(paymentTimeoutMinutes) || paymentTimeoutMinutes < 1) {
        throw new Error('DPO payment timeout must be at least one minute.');
      }

      const serviceDate = new Date().toISOString().slice(0, 16).replace(/-/g, '/').replace('T', ' ');
      const customerEmailTag = typeof customerEmail === 'string' && customerEmail
        ? `<customerEmail>${escapeXml(customerEmail)}</customerEmail>`
        : '';
      const transaction = `<Transaction><PaymentAmount>${amount.toFixed(2)}</PaymentAmount><PaymentCurrency>NAD</PaymentCurrency><CompanyRef>${escapeXml(orderNumber)}</CompanyRef><CompanyRefUnique>1</CompanyRefUnique><RedirectURL>${escapeXml(callbackUrl.toString())}</RedirectURL><BackURL>${escapeXml(callbackUrl.toString())}</BackURL><PTL>${paymentTimeoutMinutes}</PTL><PTLtype>minutes</PTLtype>${customerEmailTag}</Transaction>`;
      const services = `<Services><Service><ServiceType>${serviceTypeId}</ServiceType><ServiceDescription>${escapeXml(`Z Namibia order ${orderNumber}`)}</ServiceDescription><ServiceDate>${serviceDate}</ServiceDate></Service></Services>`;
      const response = await sendRequest(buildDpoApiRequest(companyToken, 'createToken', `${transaction}${services}`));
      const result = getXmlValue(response, 'Result');
      if (result !== '000') {
        throw new Error(`DPO could not create the sandbox payment (code ${result || 'unknown'}).`);
      }
      const reference = getXmlValue(response, 'TransToken');
      if (!DPO_TOKEN_PATTERN.test(reference)) {
        throw new Error('DPO sandbox did not return a valid payment token.');
      }
      const redirectUrl = new URL(DPO_CHECKOUT_URL);
      redirectUrl.searchParams.set('ID', reference);
      return { reference, status: 'pending', redirectUrl: redirectUrl.toString() };
    },
    async verifyIntent(reference) {
      if (typeof reference !== 'string' || !DPO_TOKEN_PATTERN.test(reference)) {
        throw new Error('Invalid DPO payment token.');
      }
      const contents = `<TransactionToken>${escapeXml(reference)}</TransactionToken>`;
      const response = await sendRequest(buildDpoApiRequest(companyToken, 'verifyToken', contents));
      const result = getXmlValue(response, 'Result');
      return {
        reference,
        status: result === '000' ? 'paid' : 'pending',
        result,
        amountNAD: Number(getXmlValue(response, 'TransactionAmount')),
        currency: getXmlValue(response, 'TransactionCurrency').toUpperCase(),
        companyReference: getXmlValue(response, 'CompanyRef')
      };
    }
  };
}

function createPaymentAdapter(mode = 'mock', options = {}) {
  if (mode === 'dpo') return createDpoPaymentAdapter(options);
  if (mode !== 'mock') {
    throw new Error('Unsupported payment mode. Use mock or dpo.');
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

module.exports = { createPaymentAdapter, isMatchingDpoPayment };
