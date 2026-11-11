const test = require('node:test');
const assert = require('node:assert/strict');
const { getDatabaseConnectionStatus, getOperatingSystemName, getServerDiagnostics } = require('./runtime-diagnostics');

test('operating system names identify Windows and Linux hosts', () => {
  assert.equal(getOperatingSystemName('win32'), 'Windows');
  assert.equal(getOperatingSystemName('linux'), 'Linux');
  assert.equal(getOperatingSystemName('darwin'), 'macOS');
  assert.equal(getOperatingSystemName('freebsd'), 'Other');
});

test('database connection states are reported without exposing internals', () => {
  assert.equal(getDatabaseConnectionStatus(1), 'Connected');
  assert.equal(getDatabaseConnectionStatus(2), 'Connecting');
  assert.equal(getDatabaseConnectionStatus(3), 'Disconnecting');
  assert.equal(getDatabaseConnectionStatus(0), 'Disconnected');
});

test('server diagnostics return sanitized, read-only runtime details', () => {
  const diagnostics = getServerDiagnostics({
    appVersion: '1.2.3',
    databaseReadyState: 1,
    platform: 'linux',
    osRelease: 'test-release',
    architecture: 'x64',
    nodeVersion: 'v22.1.0',
    processUptimeSeconds: 125.8,
    hostUptimeSeconds: 1000.9,
    memoryUsage: { rss: 10485760, heapUsed: 5242880, heapTotal: 8388608 },
    totalMemoryBytes: 20971520,
    freeMemoryBytes: 10485760,
    nodeEnvironment: 'production'
  });

  assert.deepEqual(diagnostics, {
    operatingSystem: 'Linux',
    osRelease: 'test-release',
    architecture: 'x64',
    nodeVersion: 'v22.1.0',
    appVersion: '1.2.3',
    environment: 'Production',
    processUptimeSeconds: 125,
    hostUptimeSeconds: 1000,
    memory: {
      processRssMB: 10,
      heapUsedMB: 5,
      heapTotalMB: 8,
      systemFreeMB: 10,
      systemTotalMB: 20
    },
    databaseStatus: 'Connected',
    health: 'Healthy'
  });
  assert.equal(Object.keys(diagnostics).some((key) => ['secret', 'token', 'password', 'env'].includes(key.toLowerCase())), false);
});
