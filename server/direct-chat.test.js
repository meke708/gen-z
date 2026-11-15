const test = require('node:test');
const assert = require('node:assert/strict');
const {
  MAX_CHAT_MESSAGE_LENGTH,
  normalizeChatMessage,
  getChatParticipantRole,
  createChatProductTag,
  getConversationProductTag
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
