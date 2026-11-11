const test = require('node:test');
const assert = require('node:assert/strict');
const {
  buildPromotionSchedule,
  normalizePromotionVisitorId,
  calculatePromotionClickThroughRate,
  calculateWalletPayment,
  isMatchingPromotionWalletDebit,
  getPromotionPaymentIssue,
  shouldCancelUnpaidPromotion
} = require('./server');

test('promotion schedule uses the fixed price and seven-day duration', () => {
  const startsAt = new Date('2026-03-01T12:00:00.000Z');
  const schedule = buildPromotionSchedule(startsAt);

  assert.equal(schedule.amountNAD, 50);
  assert.equal(schedule.durationDays, 7);
  assert.equal(schedule.startsAt.toISOString(), startsAt.toISOString());
  assert.equal(schedule.expiresAt.toISOString(), '2026-03-08T12:00:00.000Z');
});

test('promotion schedule rejects invalid start dates', () => {
  assert.throws(() => buildPromotionSchedule('not-a-date'), /start date must be valid/);
});

test('promotion payment supports card or wallet-first split payments', () => {
  assert.deepEqual(calculateWalletPayment(50, 20, 'wallet'), { walletUsedNAD: 20, cardDueNAD: 30 });
  assert.deepEqual(calculateWalletPayment(50, 80, 'wallet'), { walletUsedNAD: 50, cardDueNAD: 0 });
  assert.deepEqual(calculateWalletPayment(50, 80, 'card'), { walletUsedNAD: 0, cardDueNAD: 50 });
});

test('active promotions are cancelled when payment cannot be verified', () => {
  const campaign = {
    _id: 'campaign-1',
    sellerId: 'seller-1',
    status: 'active',
    paymentMethod: 'wallet',
    amountNAD: 50,
    walletUsedNAD: 20,
    cardDueNAD: 30,
    paidAt: new Date('2026-03-01T12:00:00.000Z')
  };
  const debit = {
    reference: 'promotion:campaign-1',
    userId: 'seller-1',
    type: 'purchase_debit',
    amountNAD: 20
  };

  assert.equal(getPromotionPaymentIssue(campaign, debit), null);
  assert.equal(shouldCancelUnpaidPromotion(campaign, debit), false);
  assert.match(getPromotionPaymentIssue(campaign, null), /Z-balance debit is missing/);
  assert.equal(shouldCancelUnpaidPromotion(campaign, null), true);
  assert.match(getPromotionPaymentIssue({ ...campaign, paymentMethod: null }, null), /payment method is missing/);
  assert.equal(shouldCancelUnpaidPromotion({ ...campaign, paymentMethod: null }, null), true);
  assert.equal(getPromotionPaymentIssue({
    ...campaign,
    paymentMethod: 'card',
    walletUsedNAD: 0,
    cardDueNAD: 50
  }, null), null);
  assert.match(getPromotionPaymentIssue({
    ...campaign,
    paymentMethod: 'card',
    walletUsedNAD: 0,
    cardDueNAD: 50,
    paidAt: null
  }, null), /payment timestamp is missing/);
  assert.equal(shouldCancelUnpaidPromotion({ ...campaign, status: 'pending' }, null), false);
  assert.equal(isMatchingPromotionWalletDebit(campaign, debit), true);
  assert.equal(isMatchingPromotionWalletDebit(campaign, { ...debit, amountNAD: 19 }), false);
  assert.equal(isMatchingPromotionWalletDebit(campaign, { ...debit, userId: 'another-seller' }), false);
  assert.match(getPromotionPaymentIssue(campaign, { ...debit, amountNAD: 19 }), /debit record does not match/);
  assert.match(getPromotionPaymentIssue({ ...campaign, cardDueNAD: 20 }, debit), /amounts do not match/);
});

test('promotion visitor IDs accept UUIDs and normalize to lowercase hex', () => {
  assert.equal(normalizePromotionVisitorId('A1B2C3D4-E5F6-4789-ABCD-0123456789AB'), 'a1b2c3d4e5f64789abcd0123456789ab');
  assert.equal(normalizePromotionVisitorId('a1b2c3d4e5f64789abcd0123456789ab'), 'a1b2c3d4e5f64789abcd0123456789ab');
  assert.equal(normalizePromotionVisitorId('invalid-id'), null);
  assert.equal(normalizePromotionVisitorId(123), null);
});

test('promotion click-through rate is a percentage and handles no impressions', () => {
  assert.equal(calculatePromotionClickThroughRate(200, 7), 3.5);
  assert.equal(calculatePromotionClickThroughRate(0, 0), 0);
});
