const test = require('node:test');
const assert = require('node:assert/strict');
const { describeLoginDevice } = require('./server');
const { buildLoginNetworkDetails, getPublicClientIp, resolveLoginNetwork } = require('./login-activity');

test('login activity describes common browser and platform pairs', () => {
  assert.equal(
    describeLoginDevice('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36'),
    'Chrome on Windows'
  );
  assert.equal(
    describeLoginDevice('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15'),
    'Safari on macOS'
  );
  assert.equal(describeLoginDevice(''), 'Unknown browser on unknown device');
});

test('login network details retain only valid public client IP addresses', () => {
  assert.equal(getPublicClientIp('203.0.113.10'), '');
  assert.equal(getPublicClientIp('10.0.0.4'), '');
  assert.equal(getPublicClientIp('::ffff:192.168.1.4'), '');
  assert.equal(getPublicClientIp('196.25.1.2'), '196.25.1.2');
  assert.equal(getPublicClientIp('2001:4860:4860::8888'), '2001:4860:4860::8888');
});

test('login network details use local country, city, and ASN database results', () => {
  assert.deepEqual(buildLoginNetworkDetails('196.25.1.2', {
    country: { iso_code: 'NA' },
    city: { names: { en: 'Windhoek' } }
  }, {
    autonomous_system_organization: 'MTC Namibia'
  }), {
    client_ip: '196.25.1.2',
    country_code: 'NA',
    city: 'Windhoek',
    isp_provider: 'MTC Namibia'
  });
});

test('login network lookup keeps the IP and leaves GeoIP fields empty when databases are not configured', async () => {
  assert.deepEqual(await resolveLoginNetwork('196.25.1.2', {
    cityDatabasePath: '',
    asnDatabasePath: ''
  }), {
    client_ip: '196.25.1.2',
    country_code: '',
    city: '',
    isp_provider: ''
  });
});
