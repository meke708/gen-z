const { execFile } = require('node:child_process');
const path = require('node:path');

const allowedTests = [
  { id: 'admin-notification', file: 'server/admin-notification.test.js' },
  { id: 'assistant-purchase', file: 'server/assistant-purchase.test.js' },
  { id: 'cancel-order', file: 'server/cancel-order.test.js' },
  { id: 'cart-sync', file: 'server/cart-sync.test.js' },
  { id: 'duplicate-listings', file: 'server/duplicate-listings.test.js' },
  { id: 'kyc-storage', file: 'server/kyc-storage.test.js' },
  { id: 'login-activity', file: 'server/login-activity.test.js' },
  { id: 'login-redirect', file: 'server/login-redirect.test.js' },
  { id: 'product-review', file: 'server/product-review.test.js' },
  { id: 'promotion', file: 'server/promotion.test.js' },
  { id: 'runtime-diagnostics', file: 'server/runtime-diagnostics.test.js' },
  { id: 'shop-assistant', file: 'server/shop-assistant.test.js' },
  { id: 'test-command-runner', file: 'server/test-command-runner.test.js' },
  { id: 'wishlist', file: 'server/wishlist.test.js' },
  { id: 'client-cart-sync', file: 'client/cart-sync.test.js' },
  { id: 'client-wishlist-sync', file: 'client/wishlist-sync.test.js' }
];
const testById = new Map(allowedTests.map((test) => [test.id, test]));
const testTimeoutMs = 120 * 1000;
let testRunActive = false;

function listAllowedTests() {
  return allowedTests.map(({ id, file }) => ({ id, file }));
}

function runTestFiles(testId, files, fileLabel) {
  if (testRunActive) {
    const error = new Error('Another test run is already in progress.');
    error.code = 'TEST_RUN_IN_PROGRESS';
    return Promise.reject(error);
  }

  testRunActive = true;
  const startedAt = Date.now();
  return new Promise((resolve) => {
    execFile(process.execPath, ['--test', ...files], {
      cwd: path.resolve(__dirname, '..'),
      encoding: 'utf8',
      maxBuffer: 1024 * 1024,
      timeout: testTimeoutMs,
      windowsHide: true
    }, (error, stdout, stderr) => {
      testRunActive = false;
      const timedOut = Boolean(error && (error.killed || error.code === 'ETIMEDOUT'));
      const outputLimitExceeded = Boolean(error && error.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER');
      resolve({
        testId,
        file: fileLabel,
        testCount: files.length,
        success: !error,
        exitCode: error && Number.isInteger(error.code) ? error.code : (error ? null : 0),
        durationMs: Date.now() - startedAt,
        stdout,
        stderr,
        error: error
          ? timedOut
            ? 'The test exceeded the 120-second time limit.'
            : outputLimitExceeded
              ? 'The test output exceeded the 1 MB limit.'
              : error.code === 1
                ? 'One or more tests failed.'
                : 'The test process could not complete.'
          : null
      });
    });
  });
}

function runAllowedTest(testId) {
  const test = testById.get(testId);
  if (!test) {
    const error = new Error('Choose a test from the approved test list.');
    error.code = 'INVALID_TEST';
    return Promise.reject(error);
  }
  return runTestFiles(test.id, [test.file], test.file);
}

function runAllAllowedTests() {
  const files = allowedTests.map(({ file }) => file);
  return runTestFiles('all', files, `All ${files.length} approved test files`);
}

module.exports = { listAllowedTests, runAllowedTest, runAllAllowedTests };
