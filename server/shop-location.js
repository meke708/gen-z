function normalizeShopStreetAddress(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.normalize('NFKC');
  if (/[<>\u0000-\u001f\u007f]/.test(normalized)) return null;
  const address = normalized.trim().replace(/\s+/g, ' ');
  if (!address) return '';
  if (address.length > 200) return null;
  return address;
}

function getPublicShopStreetAddress(shop) {
  return shop?.showAddressPublicly && typeof shop.streetAddress === 'string'
    ? shop.streetAddress
    : '';
}

module.exports = { normalizeShopStreetAddress, getPublicShopStreetAddress };
