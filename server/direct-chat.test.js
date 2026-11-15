const test = require('node:test');
const assert = require('node:assert/strict');
const {
  MAX_CHAT_MESSAGE_LENGTH,
  normalizeChatMessage,
  getChatParticipantRole,
  getChatParticipantImageUrl,
  isChatParticipantOnline,
  createChatProductTag,
  getConversationProductTag,
  getMergedChatConversationState
} = require('./direct-chat');

test('chat messages are trimmed and line endings are normalized', () => {
  assert.equal(normalizeChatMessage('  Hello\r\nthere  '), 'Hello\nthere');
});

test('chat messages reject empty, non-string, and oversized input', () => {
  assert.equal(normalizeChatMessage(' \n '), null);
  assert.equal(normalizeChatMessage(42), null);
  assert.equal(normalizeChatMessage('x'.repeat(MAX_CHAT_MESSAGE_LENGTH + 1)), null);
});

test('chat access is limited to the buyer and the owning seller', () => {
  const conversation = { buyerId: { _id: 'buyer-1' } };
  assert.equal(getChatParticipantRole(conversation, 'buyer-1', 'seller-1'), 'buyer');
  assert.equal(getChatParticipantRole(conversation, 'seller-1', { _id: 'seller-1' }), 'seller');
  assert.equal(getChatParticipantRole(conversation, 'other-1', 'seller-1'), null);
});

test('buyer conversations use the seller storefront image while seller views use buyer initials', () => {
  const conversation = { shopId: { coverImageUrl: 'https://images.example/shop.jpg' } };
  assert.equal(getChatParticipantImageUrl(conversation, 'buyer'), 'https://images.example/shop.jpg');
  assert.equal(getChatParticipantImageUrl(conversation, 'seller'), '');
  assert.equal(getChatParticipantImageUrl({}, 'buyer'), '');
});

test('chat presence is online only while its heartbeat has not expired', () => {
  const presence = new Map([['user-1', 5000]]);
  assert.equal(isChatParticipantOnline(presence, 'user-1', 4999), true);
  assert.equal(isChatParticipantOnline(presence, 'user-1', 5000), false);
  assert.equal(isChatParticipantOnline(presence, 'user-2', 4999), false);
  assert.equal(isChatParticipantOnline(null, 'user-1', 4999), false);
});

test('product tags retain only the product details shown in chat', () => {
  assert.deepEqual(createChatProductTag({
    _id: 'product-1',
    title: 'Market basket',
    imageUrl: '',
    priceNAD: 125
  }), {
    productId: 'product-1',
    title: 'Market basket',
    imageUrl: '',
    priceNAD: 125
  });
});

test('conversation product tags remain visible and fall back to tags on existing messages', () => {
  const savedTag = { title: 'Market basket' };
  assert.equal(getConversationProductTag({ productTag: savedTag }, null), savedTag);
  assert.equal(getConversationProductTag({}, { productTag: savedTag }), savedTag);
  assert.equal(getConversationProductTag({}, {}), null);
});

test('merged conversations keep the earliest id, latest product, and summed unread counts', () => {
  const merged = getMergedChatConversationState([
    {
      _id: 'older',
      createdAt: '2025-01-01T00:00:00Z',
      productId: 'product-1',
      lastMessageAt: '2025-01-02T00:00:00Z',
      lastMessageText: 'First product',
      buyerUnreadCount: 2,
      sellerUnreadCount: 1,
      productTag: { productId: 'product-1' }
    },
    {
      _id: 'newer',
      createdAt: '2025-02-01T00:00:00Z',
      productId: 'product-2',
      lastMessageAt: '2025-02-02T00:00:00Z',
      lastMessageText: 'Second product',
      buyerUnreadCount: 3,
      sellerUnreadCount: 4,
      productTag: { productId: 'product-2' }
    }
  ]);

  assert.equal(merged.canonicalId, 'older');
  assert.deepEqual(merged.duplicateIds, ['newer']);
  assert.equal(merged.updates.productId, 'product-2');
  assert.equal(merged.updates.lastMessageText, 'Second product');
  assert.equal(merged.updates.buyerUnreadCount, 5);
  assert.equal(merged.updates.sellerUnreadCount, 5);
  assert.deepEqual(merged.updates.productTag, { productId: 'product-2' });
});
