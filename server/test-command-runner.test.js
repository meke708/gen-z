const test = require('node:test');
const assert = require('node:assert/strict');
const { listAllowedTests, runAllowedTest } = require('./approved-test-runner');

test('only approved project test files are exposed for remote runs', () => {
  const tests = listAllowedTests();
  assert.ok(tests.length > 0);
  assert.ok(tests.every(({ id, file }) => /^[a-z0-9-]+$/.test(id) && /^(?:server|client)\/[a-z0-9-]+\.test\.js$/.test(file)));
  assert.ok(tests.some(({ file }) => file === 'server/test-command-runner.test.js'));
});

test('unknown test identifiers are rejected before starting a process', async () => {
  await assert.rejects(runAllowedTest('../../server.js'), {
    code: 'INVALID_TEST',
    message: 'Choose a test from the approved test list.'
  });
});
