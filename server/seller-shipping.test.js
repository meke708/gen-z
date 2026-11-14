const test = require('node:test');
const assert = require('node:assert/strict');
const { isSellerOrderShippingNeeded } = require('./server');

test('accepted processing seller orders need shipping even when shipping is free', () => {
  assert.equal(isSellerOrderShippingNeeded({
    approvalStatus: 'accepted',
    fulfillmentStatus: 'processing',
    shippingNAD: 0
  }), true);
});

test('seller orders are not marked as needing shipping before acceptance or after shipment', () => {
  assert.equal(isSellerOrderShippingNeeded({
    approvalStatus: 'pending',
    fulfillmentStatus: 'awaiting_payment'
  }), false);
  assert.equal(isSellerOrderShippingNeeded({
    approvalStatus: 'accepted',
    fulfillmentStatus: 'shipped'
  }), false);
  assert.equal(isSellerOrderShippingNeeded({
    approvalStatus: 'rejected',
    fulfillmentStatus: 'disputed'
  }), false);
});
