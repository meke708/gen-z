const test = require('node:test');
const assert = require('node:assert/strict');
const {
  EMAIL_VERIFICATION_RESEND_COOLDOWN_MS,
  createEmailVerificationResendReservation,
  getEmailVerificationResendLimitStatus
} = require('./email-verification-resend');

const now = new Date('2026-11-14T20:00:00.000Z');

test('verification resend cooldown blocks requests until 60 seconds have passed', () => {
  const status = getEmailVerificationResendLimitStatus({
    emailVerificationResendHistory: [new Date(now.getTime() - 60_000)],
    emailVerificationLastResendAt: new Date(now.getTime() - 59_000)
  }, now);

  assert.deepEqual(status, { reason: 'cooldown', retryAfterSeconds: 1 });
  assert.equal(EMAIL_VERIFICATION_RESEND_COOLDOWN_MS, 60 * 1000);
});

test('verification resend cap blocks a third resend until the oldest resend leaves the rolling window', () => {
  const status = getEmailVerificationResendLimitStatus({
    emailVerificationResendHistory: [
      new Date(now.getTime() - 23 * 60 * 60 * 1000),
      new Date(now.getTime() - 22 * 60 * 60 * 1000)
    ],
    emailVerificationLastResendAt: new Date(now.getTime() - 61_000)
  }, now);

  assert.deepEqual(status, { reason: 'daily_limit', retryAfterSeconds: 60 * 60 });
});

test('verification resend is allowed after cooldown or window expiration', () => {
  assert.equal(getEmailVerificationResendLimitStatus({
    emailVerificationResendHistory: [new Date(now.getTime() - 60_000)],
    emailVerificationLastResendAt: new Date(now.getTime() - 60_000)
  }, now), null);

  assert.equal(getEmailVerificationResendLimitStatus({
    emailVerificationResendHistory: [
      new Date(now.getTime() - 24 * 60 * 60 * 1000),
      new Date(now.getTime() - 2 * 60 * 1000)
    ],
    emailVerificationLastResendAt: new Date(now.getTime() - 2 * 60 * 1000)
  }, now), null);
});

test('verification resend reservation atomically filters cooldown and rolling-window limits', () => {
  const reservation = createEmailVerificationResendReservation('user-1', now);

  assert.equal(reservation.filter._id, 'user-1');
  assert.equal(reservation.filter.$expr.$lt[1], 2);
  assert.equal(reservation.filter.$or[2].emailVerificationLastResendAt.$lte.getTime(),
    now.getTime() - EMAIL_VERIFICATION_RESEND_COOLDOWN_MS);
  assert.deepEqual(reservation.update[0].$set.emailVerificationResendHistory.$concatArrays[1], [now]);
  assert.equal(reservation.update[0].$set.emailVerificationLastResendAt, now);
  assert.equal(reservation.options.updatePipeline, true);
});
