const EMAIL_VERIFICATION_RESEND_LIMIT = 2;
const EMAIL_VERIFICATION_RESEND_WINDOW_MS = 24 * 60 * 60 * 1000;
const EMAIL_VERIFICATION_RESEND_COOLDOWN_MS = 60 * 1000;

function createEmailVerificationResendReservation(userId, now = new Date()) {
  const windowCutoff = new Date(now.getTime() - EMAIL_VERIFICATION_RESEND_WINDOW_MS);
  const cooldownCutoff = new Date(now.getTime() - EMAIL_VERIFICATION_RESEND_COOLDOWN_MS);
  const recentResends = {
    $filter: {
      input: { $ifNull: ['$emailVerificationResendHistory', []] },
      as: 'resendAt',
      cond: { $gt: ['$$resendAt', windowCutoff] }
    }
  };

  return {
    filter: {
      _id: userId,
      $expr: {
        $lt: [{ $size: recentResends }, EMAIL_VERIFICATION_RESEND_LIMIT]
      },
      $or: [
        { emailVerificationLastResendAt: { $exists: false } },
        { emailVerificationLastResendAt: null },
        { emailVerificationLastResendAt: { $lte: cooldownCutoff } }
      ]
    },
    update: [{
      $set: {
        emailVerificationResendHistory: { $concatArrays: [recentResends, [now]] },
        emailVerificationLastResendAt: now
      }
    }],
    options: { returnDocument: 'after', timestamps: false, updatePipeline: true }
  };
}

function getEmailVerificationResendLimitStatus(user, now = new Date()) {
  if (!user) return null;
  const nowMs = now.getTime();
  const lastResendAt = user.emailVerificationLastResendAt
    ? new Date(user.emailVerificationLastResendAt).getTime()
    : NaN;
  if (Number.isFinite(lastResendAt)) {
    const cooldownRemaining = EMAIL_VERIFICATION_RESEND_COOLDOWN_MS - (nowMs - lastResendAt);
    if (cooldownRemaining > 0) {
      return {
        reason: 'cooldown',
        retryAfterSeconds: Math.ceil(cooldownRemaining / 1000)
      };
    }
  }

  const windowCutoff = nowMs - EMAIL_VERIFICATION_RESEND_WINDOW_MS;
  const recentResends = (user.emailVerificationResendHistory || [])
    .map((resendAt) => new Date(resendAt).getTime())
    .filter((resendAt) => Number.isFinite(resendAt) && resendAt > windowCutoff)
    .sort((left, right) => left - right);
  if (recentResends.length >= EMAIL_VERIFICATION_RESEND_LIMIT) {
    const windowRemaining = recentResends[0] + EMAIL_VERIFICATION_RESEND_WINDOW_MS - nowMs;
    if (windowRemaining > 0) {
      return {
        reason: 'daily_limit',
        retryAfterSeconds: Math.ceil(windowRemaining / 1000)
      };
    }
  }
  return null;
}

module.exports = {
  EMAIL_VERIFICATION_RESEND_COOLDOWN_MS,
  EMAIL_VERIFICATION_RESEND_LIMIT,
  createEmailVerificationResendReservation,
  getEmailVerificationResendLimitStatus
};
