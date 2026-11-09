const test = require('node:test');
const assert = require('node:assert/strict');

const {
  canCancelOrder,
  resolveSellerApprovalState,
  resolveAppBaseUrl,
  getBuyerDisplayName,
  normalizeSupportRequest,
  normalizeSuspensionAppeal,
  normalizeSuspensionAppealStatusEmail,
  normalizeSuspensionAppealStatusAccess,
  normalizeSuspensionAppealReview,
  getSupportTriage,
  getSupportRequestVisibilityFilter,
  getSupportCategory,
  getListingReportCredibilityPoints,
  isListingReportBlocked,
  shouldAutoHideListing,
  shouldRestoreReportHiddenListing,
  shouldAutoRestrictSeller,
  isSellerAutoRestricted,
  buildSellerMarketBenchmarks,
  normalizePasswordResetInput,
  normalizeProfileInput,
  isValidEmailVerificationToken,
  isEmailVerified,
  assertProductionPaymentConfiguration,
  isConfiguredAdminIdentity,
  isAdminUser,
  isModeratorUser,
  isSandboxUser,
  isLocalMongoUri,
  getPublicRole,
  isValidCommissionRatePercent,
  validateImageUrl,
  hasValidImageSignature,
  resolvePayoutStatus,
  assertProductionAdminConfiguration
} = require('./server');

test('seller market benchmarks compare only active category listings and handle empty competition', () => {
  assert.deepEqual(buildSellerMarketBenchmarks(
    ['Fashion', 'Beauty'],
    [
      { _id: 'Fashion', productCount: 2, averagePriceNAD: 125.555 },
      { _id: 'Beauty', productCount: 1, averagePriceNAD: 80 }
    ],
    [
      { _id: 'Fashion', productCount: 7, shopIds: ['shop-a', 'shop-b'], averagePriceNAD: 110.126 }
    ]
  ), [
    {
      category: 'Fashion',
      ownProductCount: 2,
      ownAveragePriceNAD: 125.56,
      marketProductCount: 7,
      competitorShopCount: 2,
      marketAveragePriceNAD: 110.13
    },
    {
      category: 'Beauty',
      ownProductCount: 1,
      ownAveragePriceNAD: 80,
      marketProductCount: 0,
      competitorShopCount: 0,
      marketAveragePriceNAD: null
    }
  ]);
});

test('public app URLs prefer Render for a localhost override and preserve custom domains', () => {
  assert.equal(resolveAppBaseUrl({
    appBaseUrl: 'http://localhost:3001',
    renderExternalUrl: 'https://z-namibia.onrender.com',
    nodeEnv: 'production'
  }), 'https://z-namibia.onrender.com');
  assert.equal(resolveAppBaseUrl({
    appBaseUrl: 'https://shop.example.com/path',
    renderExternalUrl: 'https://z-namibia.onrender.com',
    nodeEnv: 'production'
  }), 'https://shop.example.com');
});

test('production public app URLs must be configured and use HTTPS', () => {
  assert.equal(resolveAppBaseUrl({ nodeEnv: 'production' }), null);
  assert.equal(resolveAppBaseUrl({ appBaseUrl: 'http://shop.example.com', nodeEnv: 'production' }), null);
  assert.equal(resolveAppBaseUrl({ appBaseUrl: 'https://shop.example.com', nodeEnv: 'production' }), 'https://shop.example.com');
});

test('pending orders can be cancelled before the reservation expires', () => {
  const order = {
    paymentStatus: 'pending',
    reservationExpiresAt: new Date(Date.now() + 60_000),
    reservationsReleasedAt: null
  };

  assert.equal(canCancelOrder(order), true);
});

test('paid orders can still be cancelled when the seller has not approved them yet', () => {
  const order = {
    paymentStatus: 'paid',
    sellerOrders: [{ approvalStatus: 'pending' }, { approvalStatus: 'pending' }]
  };

  assert.equal(canCancelOrder(order), true);
});

test('orders cannot be cancelled after the seller accepts or rejects them', () => {
  const order = {
    paymentStatus: 'paid',
    sellerOrders: [{ approvalStatus: 'accepted' }, { approvalStatus: 'rejected' }]
  };

  assert.equal(canCancelOrder(order), false);
});

test('auto approval marks seller orders as accepted immediately', () => {
  assert.equal(resolveSellerApprovalState(true), 'accepted');
  assert.equal(resolveSellerApprovalState(false), 'pending');
});

test('buyer display names are included for seller order cards', () => {
  assert.equal(getBuyerDisplayName({ buyerId: { name: 'Lerato Ndlovu' } }), 'Lerato Ndlovu');
  assert.equal(getBuyerDisplayName({ buyerId: null }), 'Customer');
});

test('support requests normalize valid topics and trim messages', () => {
  assert.deepEqual(normalizeSupportRequest({ topic: 'delivery', message: '  My parcel has not arrived.  ' }), {
    topic: 'delivery',
    message: 'My parcel has not arrived.'
  });
});

test('support requests reject invalid topics and message lengths', () => {
  assert.throws(() => normalizeSupportRequest({ topic: 'unknown', message: 'This is a valid length message.' }), { statusCode: 400 });
  assert.throws(() => normalizeSupportRequest({ topic: 'refund', message: 'short' }), { statusCode: 400 });
});

test('support routing is derived from the selected topic, never a submitted category', () => {
  const message = 'Please help me with this request.';
  const request = normalizeSupportRequest({ topic: 'delayed_payout', category: 'general', message });
  assert.deepEqual(request, { topic: 'delayed_payout', message });
  assert.equal(getSupportCategory(request.topic), 'financial');
  assert.equal(getSupportCategory('banking_details'), 'financial');
  assert.equal(getSupportCategory('transaction_failure'), 'financial');
  assert.equal(getSupportCategory('rejected_business_application'), 'identity');
  assert.equal(getSupportCategory('document_upload_failure'), 'identity');
  assert.equal(getSupportCategory('account_reinstatement'), 'identity');
  assert.equal(getSupportCategory('listing_storefront'), 'general');
  assert.equal(getSupportCategory('platform_navigation'), 'general');
  assert.equal(getSupportCategory('delivery'), 'general');
});

test('moderator support queries are restricted to general categories', () => {
  const moderatorFilter = getSupportRequestVisibilityFilter(false);
  assert.deepEqual(moderatorFilter.$or[0], { category: 'general' });
  assert.deepEqual(moderatorFilter.$or[1].topic.$in, [
    'delivery', 'refund', 'return', 'item_issue', 'other', 'listing_storefront', 'platform_navigation'
  ]);
  assert.deepEqual(getSupportRequestVisibilityFilter(true), {});
});

test('listing report signals prioritize confirmed buyers without hiding shop-owner reports from moderators', () => {
  assert.equal(getListingReportCredibilityPoints({ verifiedBuyer: true }), 25);
  assert.equal(getListingReportCredibilityPoints(), 5);
  assert.equal(getListingReportCredibilityPoints({ verifiedBuyer: true, sellerReporter: true }), 0);
  assert.equal(shouldAutoHideListing(49), false);
  assert.equal(shouldAutoHideListing(50), true);
  assert.equal(shouldRestoreReportHiddenListing('report_threshold', 49), true);
  assert.equal(shouldRestoreReportHiddenListing('report_threshold', 50), false);
  assert.equal(shouldRestoreReportHiddenListing('moderator', 0), false);
  assert.equal(isListingReportBlocked(2), false);
  assert.equal(isListingReportBlocked(3), true);
});

test('seller auto-hold requires three distinct listings crossing the threshold within 48 hours', () => {
  const now = new Date('2026-11-09T12:00:00.000Z');
  const event = (productId, hoursAgo) => ({
    productId,
    triggeredAt: new Date(now.getTime() - hoursAgo * 60 * 60 * 1000)
  });
  assert.equal(shouldAutoRestrictSeller([event('a', 1), event('b', 2)], now), false);
  assert.equal(shouldAutoRestrictSeller([event('a', 1), event('a', 2), event('b', 3)], now), false);
  assert.equal(shouldAutoRestrictSeller([event('a', 1), event('b', 2), event('c', 47)], now), true);
  assert.equal(shouldAutoRestrictSeller([event('a', 1), event('b', 2), event('c', 49)], now), false);
  const priorTrigger = new Date(now.getTime() - 30 * 60 * 1000);
  assert.equal(shouldAutoRestrictSeller([event('a', 1), event('b', 2), event('c', 3)], now, priorTrigger), false);
  assert.equal(shouldAutoRestrictSeller([
    event('a', 0.4),
    event('b', 0.3),
    event('c', 0.2)
  ], now, priorTrigger), true);
  assert.equal(isSellerAutoRestricted({
    sellerRestrictionStatus: 'temp_hold',
    sellerRestrictedUntil: new Date(now.getTime() + 1000)
  }, now), true);
  assert.equal(isSellerAutoRestricted({
    sellerRestrictionStatus: 'temp_hold',
    sellerRestrictedUntil: new Date(now.getTime() - 1000)
  }, now), false);
  assert.equal(isSellerAutoRestricted({ sellerRestrictionStatus: 'banned' }, now), true);
});

test('public suspension appeals normalize account email and validate the three fields', () => {
  const appeal = normalizeSuspensionAppeal({
    accountEmail: '  USER@Example.COM ',
    reason: '  I believe this suspension was a mistake and request a review.  ',
    referenceId: '  SHOP-123  '
  });
  assert.deepEqual(appeal, {
    accountEmail: 'user@example.com',
    reason: 'I believe this suspension was a mistake and request a review.',
    referenceId: 'SHOP-123'
  });
  assert.equal(normalizeSuspensionAppeal({
    accountEmail: 'user@example.com',
    reason: 'I would like the suspension decision reviewed again.'
  }).accountEmail, appeal.accountEmail);
  assert.throws(() => normalizeSuspensionAppeal({
    accountEmail: 'not-an-email',
    reason: 'I believe this suspension was a mistake.'
  }), { statusCode: 400 });
  assert.throws(() => normalizeSuspensionAppeal({
    accountEmail: 'user@example.com',
    reason: 'Too short'
  }), { statusCode: 400 });
  assert.throws(() => normalizeSuspensionAppeal({
    accountEmail: 'user@example.com',
    reason: 'I believe this suspension was a mistake.',
    referenceId: 'x'.repeat(101)
  }), { statusCode: 400 });
});

test('appeal review can reactivate an account only while resolving the appeal', () => {
  assert.deepEqual(normalizeSuspensionAppealReview({
    status: 'resolved',
    reactivateAccount: true
  }), { status: 'resolved', reactivateAccount: true });
  assert.deepEqual(normalizeSuspensionAppealReview({ status: 'in_review' }), {
    status: 'in_review',
    reactivateAccount: false
  });
  assert.throws(() => normalizeSuspensionAppealReview({
    status: 'in_review',
    reactivateAccount: true
  }), { statusCode: 400 });
  assert.throws(() => normalizeSuspensionAppealReview({
    status: 'resolved',
    reactivateAccount: 'true'
  }), { statusCode: 400 });
});

test('appeal status lookup requires a valid short-lived sign-in token', () => {
  assert.equal(normalizeSuspensionAppealStatusEmail({ accountEmail: ' USER@Example.COM ' }), 'user@example.com');
  assert.deepEqual(normalizeSuspensionAppealStatusAccess({
    accountEmail: ' USER@Example.COM ',
    verificationToken: 'a'.repeat(64)
  }), { accountEmail: 'user@example.com', verificationToken: 'a'.repeat(64) });
  assert.throws(() => normalizeSuspensionAppealStatusEmail({ accountEmail: 'not-an-email' }), { statusCode: 400 });
  assert.throws(() => normalizeSuspensionAppealStatusAccess({
    accountEmail: 'user@example.com',
    verificationToken: 'bad-token'
  }), { statusCode: 403 });
  assert.throws(() => normalizeSuspensionAppealStatusAccess({
    accountEmail: 'user@example.com',
    verificationToken: ''
  }), { statusCode: 403 });
});

test('support triage suggests a likely issue and editable template without auto-responding', () => {
  const triage = getSupportTriage('delivery', 'My package is late and delivery is delayed.');
  assert.deepEqual({
    likelyIssue: triage.likelyIssue,
    confidence: triage.confidence,
    confidenceLabel: triage.confidenceLabel
  }, {
    likelyIssue: 'Delivery is late or delayed',
    confidence: 80,
    confidenceLabel: 'High'
  });
  assert.match(triage.suggestedResponse, /We will check/);
  assert.equal(getSupportTriage('delivery', 'Please help me with my order.').confidenceLabel, 'Low');
  assert.match(getSupportTriage('delivery', 'My package is late; tracking issue.').likelyIssue, /Needs review/);
  assert.equal(getSupportTriage('unknown', 'An issue'), null);
});

test('suspension appeal triage suggests a likely issue and neutral review reply', () => {
  const triage = getSupportTriage('account_reinstatement', 'My account was suspended after an unauthorized login and I think it was hacked.');
  assert.deepEqual({
    likelyIssue: triage.likelyIssue,
    confidence: triage.confidence,
    confidenceLabel: triage.confidenceLabel
  }, {
    likelyIssue: 'Account security or unauthorized access concern',
    confidence: 80,
    confidenceLabel: 'High'
  });
  assert.match(triage.suggestedResponse, /review the account activity/);

  const unclearAppeal = getSupportTriage('account_reinstatement', 'My account has been suspended and I am asking for a review.');
  assert.equal(unclearAppeal.likelyIssue, 'Appeal reason needs manual review');
  assert.equal(unclearAppeal.confidenceLabel, 'Low');

  const mixedAppeal = getSupportTriage('account_reinstatement', 'My listing was removed and my account was hacked.');
  assert.match(mixedAppeal.likelyIssue, /Needs review/);
  assert.equal(mixedAppeal.confidenceLabel, 'Low');
});

test('password reset credentials require a valid token and password length', () => {
  const token = 'a'.repeat(64);
  assert.deepEqual(normalizePasswordResetInput({ token, password: 'strongpass1' }), { token, password: 'strongpass1' });
  assert.throws(() => normalizePasswordResetInput({ token: 'bad-token', password: 'strongpass1' }), { statusCode: 400 });
  assert.throws(() => normalizePasswordResetInput({ token, password: 'short' }), { statusCode: 400 });
});

test('profile updates validate required names, optional phone numbers, and known towns', () => {
  assert.deepEqual(normalizeProfileInput({
    name: '  Alex Nam ',
    phone: '+264 81 123 4567',
    town: 'Windhoek'
  }), {
    name: 'Alex Nam',
    phone: '+264 81 123 4567',
    town: 'Windhoek'
  });
  assert.deepEqual(normalizeProfileInput({ name: 'Alex', phone: '', town: '' }), {
    name: 'Alex',
    phone: '',
    town: ''
  });
  assert.throws(() => normalizeProfileInput({ name: ' ', phone: '', town: '' }), { statusCode: 400 });
  assert.throws(() => normalizeProfileInput({ name: 'Alex', phone: 'not a phone', town: '' }), { statusCode: 400 });
  assert.throws(() => normalizeProfileInput({ name: 'Alex', phone: '1-------', town: '' }), { statusCode: 400 });
  assert.throws(() => normalizeProfileInput({ name: 'Alex', phone: '', town: 'Mars' }), { statusCode: 400 });
});

test('email verification tokens require a 64-character lowercase hex token', () => {
  assert.equal(isValidEmailVerificationToken('a'.repeat(64)), true);
  assert.equal(isValidEmailVerificationToken('A'.repeat(64)), false);
  assert.equal(isValidEmailVerificationToken('short'), false);
});

test('seller access and checkout require a verified email, including for legacy accounts without the field', () => {
  assert.equal(isEmailVerified({ emailVerified: true }), true);
  assert.equal(isEmailVerified({ emailVerified: false }), false);
  assert.equal(isEmailVerified({}), false);
  assert.equal(isEmailVerified(null), false);
});

test('production mock payments require an explicit testing opt-in', () => {
  assert.doesNotThrow(() => assertProductionPaymentConfiguration('development', 'mock'));
  assert.throws(() => assertProductionPaymentConfiguration('production', 'mock', true, false), /ALLOW_MOCK_PAYMENTS_IN_PRODUCTION=true/);
  assert.doesNotThrow(() => assertProductionPaymentConfiguration('production', 'mock', false));
  assert.doesNotThrow(() => assertProductionPaymentConfiguration('production', 'mock', true, true));
  assert.doesNotThrow(() => assertProductionPaymentConfiguration('production', 'live'));
});

test('production admin access requires both the configured email and user id', () => {
  const userId = '64b64c9b8e4a4b9e8f412345';
  const user = { _id: userId, email: 'admin@example.com', emailVerified: true };
  assert.equal(isAdminUser(user, 'admin@example.com', ''), false);
  assert.equal(isAdminUser(user, 'admin@example.com', userId), true);
  assert.equal(isAdminUser({ ...user, email: 'other@example.com' }, 'admin@example.com', userId), false);
  assert.equal(isConfiguredAdminIdentity({ ...user, emailVerified: false }, 'admin@example.com', userId), true);
  assert.equal(isAdminUser({ ...user, emailVerified: false }, 'admin@example.com', userId), false);
  assert.throws(() => assertProductionAdminConfiguration('production', 'admin@example.com', ''), /ADMIN_USER_ID/);
  assert.throws(() => assertProductionAdminConfiguration('production', 'admin@example.com', userId), /ADMIN_EMAIL=z@gmail\.com/);
  assert.doesNotThrow(() => assertProductionAdminConfiguration('production', 'z@gmail.com', userId));
  assert.doesNotThrow(() => assertProductionAdminConfiguration('development', '', ''));
});

test('moderator and sandbox roles are isolated from super-admin access', () => {
  const moderator = { _id: '64b64c9b8e4a4b9e8f412345', email: 'helper@example.com', emailVerified: true, role: 'moderator' };
  const sandbox = { _id: '64b64c9b8e4a4b9e8f412346', email: 'sandbox@z.com', role: 'sandbox' };
  assert.equal(isModeratorUser(moderator), true);
  assert.equal(isAdminUser(moderator, 'admin@example.com', moderator._id), false);
  assert.equal(getPublicRole(moderator), 'moderator');
  assert.equal(isLocalMongoUri('mongodb://127.0.0.1:27017/z'), true);
  assert.equal(isLocalMongoUri('mongodb://localhost:27017/z'), true);
  assert.equal(isLocalMongoUri('mongodb+srv://cluster.example.com/z'), false);
  assert.equal(isSandboxUser(sandbox, { nodeEnv: 'development', sandboxEmail: 'sandbox@z.com', mongodbUri: 'mongodb://127.0.0.1:27017/z' }), true);
  assert.equal(isSandboxUser(sandbox, { nodeEnv: 'production', sandboxEmail: 'sandbox@z.com', mongodbUri: 'mongodb://127.0.0.1:27017/z' }), false);
  assert.equal(isSandboxUser(sandbox, { nodeEnv: 'development', sandboxEmail: 'sandbox@z.com', mongodbUri: 'mongodb://db.example.com/z' }), false);
});

test('platform commission input accepts only finite percentages from zero through one hundred', () => {
  for (const rate of [0, 0.01, 10, 100]) assert.equal(isValidCommissionRatePercent(rate), true);
  for (const rate of [-0.01, 100.01, NaN, Infinity, '10', null]) assert.equal(isValidCommissionRatePercent(rate), false);
});

test('image URLs must use HTTPS', () => {
  assert.equal(validateImageUrl('https://images.example.com/item.jpg'), true);
  assert.equal(validateImageUrl('http://images.example.com/item.jpg'), false);
  assert.equal(validateImageUrl('javascript:alert(1)'), false);
});

test('image uploads require bytes matching the declared image type', () => {
  assert.equal(hasValidImageSignature({ mimetype: 'image/jpeg', buffer: Buffer.from([0xff, 0xd8, 0xff]) }), true);
  assert.equal(hasValidImageSignature({ mimetype: 'image/png', buffer: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) }), true);
  assert.equal(hasValidImageSignature({ mimetype: 'image/jpeg', buffer: Buffer.from('not an image') }), false);
});

test('payout simulation advances held, eligible, then paid after two delays', () => {
  const eligibleAt = new Date('2026-10-27T12:00:00.000Z');
  const sellerOrder = { fulfillmentStatus: 'delivered', payoutStatus: 'held', payoutEligibleAt: eligibleAt };
  assert.equal(resolvePayoutStatus(sellerOrder, new Date(eligibleAt.getTime() - 1), 10_000, true), 'held');
  assert.equal(resolvePayoutStatus(sellerOrder, eligibleAt, 10_000, true), 'eligible');
  assert.equal(resolvePayoutStatus({ ...sellerOrder, payoutStatus: 'eligible' }, new Date(eligibleAt.getTime() + 9_999), 10_000, true), 'eligible');
  assert.equal(resolvePayoutStatus({ ...sellerOrder, payoutStatus: 'eligible' }, new Date(eligibleAt.getTime() + 10_000), 10_000, true), 'paid');
});

test('manual payout mode never auto-advances eligible payouts to paid', () => {
  const eligibleAt = new Date('2026-10-27T12:00:00.000Z');
  const sellerOrder = { fulfillmentStatus: 'delivered', payoutStatus: 'eligible', payoutEligibleAt: eligibleAt };
  assert.equal(resolvePayoutStatus(sellerOrder, new Date(eligibleAt.getTime() + 60_000), 10_000, false), 'eligible');
});
