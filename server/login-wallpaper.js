const DEFAULT_LOGIN_WALLPAPER = Object.freeze({
  productIds: [],
  rotatePromotions: true,
  topLine: 'Independent shops · Right here at home',
  headline: 'Good things, made',
  headlineAccent: 'close to home.',
  description: 'Discover independent Namibian shops, thoughtful local finds, and the people who make them.',
  caption: '',
  footerLeft: 'Shop local',
  footerRight: 'Made for Namibia',
  imageX: 50,
  imageY: 50,
  overlay: 0
});

const TEXT_LIMITS = Object.freeze({
  topLine: 120,
  headline: 90,
  headlineAccent: 90,
  description: 280,
  caption: 160,
  footerLeft: 40,
  footerRight: 40
});

function normalizeLoginWallpaper(input = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { error: 'Enter valid login wallpaper settings.' };
  }
  if (!Array.isArray(input.productIds) || input.productIds.length > 24
    || input.productIds.some((id) => typeof id !== 'string' || !/^[a-f\d]{24}$/i.test(id))
    || new Set(input.productIds).size !== input.productIds.length) {
    return { error: 'Choose a valid list of promoted products.' };
  }
  if (typeof input.rotatePromotions !== 'boolean') {
    return { error: 'Choose whether selected products should rotate.' };
  }
  if (!input.rotatePromotions && input.productIds.length > 1) {
    return { error: 'Choose only one promoted product when rotation is disabled.' };
  }
  if (!input.productIds.length) {
    return { error: 'Select at least one promoted product for the login wallpaper.' };
  }
  const result = {};
  for (const [field, maxLength] of Object.entries(TEXT_LIMITS)) {
    const value = input[field];
    if (typeof value !== 'string') {
      return { error: `Enter valid text for ${field}.` };
    }
    const normalized = value.trim();
    if (normalized.length > maxLength) {
      return { error: `${field} must be ${maxLength} characters or fewer.` };
    }
    if (['topLine', 'headline', 'headlineAccent'].includes(field) && !normalized) {
      return { error: `Enter text for ${field}.` };
    }
    result[field] = normalized;
  }

  for (const field of ['imageX', 'imageY']) {
    if (typeof input[field] !== 'number' || !Number.isFinite(input[field]) || input[field] < 0 || input[field] > 100) {
      return { error: `${field} must be between 0 and 100.` };
    }
    result[field] = Math.round(input[field]);
  }
  if (typeof input.overlay !== 'number' || !Number.isFinite(input.overlay) || input.overlay < 0 || input.overlay > 0.6) {
    return { error: 'overlay must be between 0 and 0.6.' };
  }
  result.overlay = Math.round(input.overlay * 100) / 100;
  result.productIds = input.productIds;
  result.rotatePromotions = input.rotatePromotions;
  return { settings: result };
}

module.exports = { DEFAULT_LOGIN_WALLPAPER, normalizeLoginWallpaper };
