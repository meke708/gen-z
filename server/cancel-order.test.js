const test = require('node:test');
const assert = require('node:assert/strict');

const {
  canCancelOrder,
  resolveSellerApprovalState,
  resolveAppBaseUrl,
  getBuyerDisplayName,
  normalizeSupportRequest,
  buildSellerMarketBenchmarks,
  normalizePasswordResetInput,
  normalizeProfileInput,
  isValidEmailVerificationToken,
  isEmailVerified,
  assertProductionPaymentConfiguration,
  isAdminUser,
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

test('production cannot start with the mock payment adapter', () => {
  assert.doesNotThrow(() => assertProductionPaymentConfiguration('development', 'mock'));
  assert.throws(() => assertProductionPaymentConfiguration('production', 'mock', true), /MOCK_PAYMENTS_ENABLED=false/);
  assert.doesNotThrow(() => assertProductionPaymentConfiguration('production', 'mock', false));
  assert.doesNotThrow(() => assertProductionPaymentConfiguration('production', 'live'));
});

test('production admin access requires both the configured email and user id', () => {
  const userId = '64b64c9b8e4a4b9e8f412345';
  const user = { _id: userId, email: 'admin@example.com' };
  assert.equal(isAdminUser(user, 'admin@example.com', ''), false);
  assert.equal(isAdminUser(user, 'admin@example.com', userId), true);
  assert.equal(isAdminUser({ ...user, email: 'other@example.com' }, 'admin@example.com', userId), false);
  assert.throws(() => assertProductionAdminConfiguration('production', 'admin@example.com', ''), /ADMIN_USER_ID/);
  assert.doesNotThrow(() => assertProductionAdminConfiguration('development', '', ''));
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
