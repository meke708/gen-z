const os = require('node:os');

function getOperatingSystemName(platform) {
  if (platform === 'win32') return 'Windows';
  if (platform === 'linux') return 'Linux';
  if (platform === 'darwin') return 'macOS';
  return 'Other';
}

function getDatabaseConnectionStatus(readyState) {
  switch (readyState) {
    case 1: return 'Connected';
    case 2: return 'Connecting';
    case 3: return 'Disconnecting';
    default: return 'Disconnected';
  }
}

function getServerDiagnostics({
  appVersion,
  databaseReadyState,
  platform = os.platform(),
  osRelease = os.release(),
  architecture = os.arch(),
  nodeVersion = process.version,
  processUptimeSeconds = process.uptime(),
  hostUptimeSeconds = os.uptime(),
  memoryUsage = process.memoryUsage(),
  totalMemoryBytes = os.totalmem(),
  freeMemoryBytes = os.freemem(),
  nodeEnvironment = process.env.NODE_ENV
} = {}) {
  const megabytes = (bytes) => Math.round(bytes / (1024 * 1024));
  const databaseStatus = getDatabaseConnectionStatus(databaseReadyState);

  return {
    operatingSystem: getOperatingSystemName(platform),
    osRelease,
    architecture,
    nodeVersion,
    appVersion,
    environment: nodeEnvironment === 'production' ? 'Production' : 'Non-production',
    processUptimeSeconds: Math.floor(processUptimeSeconds),
    hostUptimeSeconds: Math.floor(hostUptimeSeconds),
    memory: {
      processRssMB: megabytes(memoryUsage.rss),
      heapUsedMB: megabytes(memoryUsage.heapUsed),
      heapTotalMB: megabytes(memoryUsage.heapTotal),
      systemFreeMB: megabytes(freeMemoryBytes),
      systemTotalMB: megabytes(totalMemoryBytes)
    },
    databaseStatus,
    health: databaseStatus === 'Connected' ? 'Healthy' : 'Degraded'
  };
}

module.exports = { getDatabaseConnectionStatus, getOperatingSystemName, getServerDiagnostics };
