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

function getChatParticipantImageUrl(conversation, role) {
  if (role !== 'buyer') return '';
  const imageUrl = conversation?.shopId?.coverImageUrl;
  return typeof imageUrl === 'string' ? imageUrl : '';
}

function isChatParticipantOnline(presenceUsers, userId, now = Date.now()) {
  if (!presenceUsers || !userId) return false;
  const expiresAt = presenceUsers.get(String(userId));
  return typeof expiresAt === 'number' && expiresAt > now;
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

function getMergedChatConversationState(conversations) {
  if (!Array.isArray(conversations) || conversations.length < 2) {
    throw new TypeError('At least two conversations are required to merge.');
  }

  const timestamp = (value) => {
    const time = new Date(value || 0).getTime();
    return Number.isFinite(time) ? time : 0;
  };
  const byCreation = [...conversations].sort((a, b) =>
    timestamp(a.createdAt) - timestamp(b.createdAt) || String(a._id).localeCompare(String(b._id))
  );
  const byActivity = [...conversations].sort((a, b) =>
    timestamp(b.lastMessageAt) - timestamp(a.lastMessageAt)
      || timestamp(b.updatedAt) - timestamp(a.updatedAt)
      || String(a._id).localeCompare(String(b._id))
  );
  const latestTagged = byActivity.find((conversation) => conversation.productTag);
  const canonical = byCreation[0];
  const duplicateIds = byCreation.slice(1).map((conversation) => conversation._id);
  const operationKey = [canonical._id, ...duplicateIds].map(String).sort().join(':');

  return {
    canonicalId: canonical._id,
    duplicateIds,
    operationKey,
    updates: {
      productId: byActivity[0].productId || canonical.productId,
      lastMessageText: byActivity[0].lastMessageText || '',
      lastMessageAt: byActivity[0].lastMessageAt || null,
      lastMessageSenderId: byActivity[0].lastMessageSenderId || null,
      buyerUnreadCount: conversations.reduce((total, conversation) => total + (Number(conversation.buyerUnreadCount) || 0), 0),
      sellerUnreadCount: conversations.reduce((total, conversation) => total + (Number(conversation.sellerUnreadCount) || 0), 0),
      productTag: latestTagged?.productTag || null
    }
  };
}

module.exports = {
  MAX_CHAT_MESSAGE_LENGTH,
  normalizeChatMessage,
  getChatParticipantRole,
  getChatParticipantImageUrl,
  isChatParticipantOnline,
  createChatProductTag,
  getConversationProductTag,
  getMergedChatConversationState
};
