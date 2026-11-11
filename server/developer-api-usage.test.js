const test = require('node:test');
const assert = require('node:assert/strict');
const { getDeveloperApiUsageCounters } = require('./developer-api-usage');

test('developer API usage separates successful, client-error, and server-error responses', () => {
  assert.deepEqual(getDeveloperApiUsageCounters(200), { requests: 1, successes: 1 });
  assert.deepEqual(getDeveloperApiUsageCounters(429), { requests: 1, clientErrors: 1 });
  assert.deepEqual(getDeveloperApiUsageCounters(500), { requests: 1, serverErrors: 1 });
});

test('developer API usage records statement verification outcomes separately from HTTP success', () => {
  assert.deepEqual(getDeveloperApiUsageCounters(200, 'verified'), { requests: 1, successes: 1, verified: 1 });
  assert.deepEqual(getDeveloperApiUsageCounters(200, 'mismatched'), { requests: 1, successes: 1, mismatched: 1 });
  assert.deepEqual(getDeveloperApiUsageCounters(409, 'mismatched'), { requests: 1, clientErrors: 1, mismatched: 1 });
});

test('developer API usage rejects invalid HTTP response statuses', () => {
  assert.throws(() => getDeveloperApiUsageCounters(99), /valid HTTP status code/);
  assert.throws(() => getDeveloperApiUsageCounters(600), /valid HTTP status code/);
  assert.throws(() => getDeveloperApiUsageCounters(200, 'unknown'), /outcome is invalid/);
});
