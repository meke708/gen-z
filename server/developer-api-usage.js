function getDeveloperApiUsageCounters(statusCode, outcome = null) {
  if (!Number.isInteger(statusCode) || statusCode < 100 || statusCode > 599) {
    throw new Error('Developer API response status must be a valid HTTP status code.');
  }
  if (outcome !== null && !['verified', 'mismatched'].includes(outcome)) {
    throw new Error('Developer API verification outcome is invalid.');
  }
  const counters = statusCode < 400
    ? { requests: 1, successes: 1 }
    : statusCode < 500
      ? { requests: 1, clientErrors: 1 }
      : { requests: 1, serverErrors: 1 };
  if (outcome === 'verified') counters.verified = 1;
  if (outcome === 'mismatched') counters.mismatched = 1;
  return counters;
}

module.exports = { getDeveloperApiUsageCounters };
