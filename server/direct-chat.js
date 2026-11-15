const MAX_CHAT_MESSAGE_LENGTH = 2000;

function normalizeChatMessage(value) {
  if (typeof value !== 'string') return null;
  const message = value.replace(/\r\n?/g, '\n').trim();
  return message && message.length <= MAX_CHAT_MESSAGE_LENGTH ? message : null;
}

function getChatParticipantRole(conversation, userId, shopOwnerId) {
  const participantId = String(userId || '');
  const buyerId = conversation?.buyerId?._id || conversation?.buyerId;
  const ownerId = shopOwnerId?._id || shopOwnerId;
  if (participantId && String(buyerId || '') === participantId) return 'buyer';
  if (participantId && String(ownerId || '') === participantId) return 'seller';
  return null;
}

function createChatProductTag(product) {
  return {
    productId: product._id,
    title: product.title,
    imageUrl: product.imageUrl || '',
    priceNAD: product.priceNAD
  };
}

function getConversationProductTag(conversation, taggedMessage) {
  return conversation?.productTag || taggedMessage?.productTag || null;
}

module.exports = {
  MAX_CHAT_MESSAGE_LENGTH,
  normalizeChatMessage,
  getChatParticipantRole,
  createChatProductTag,
  getConversationProductTag
};
