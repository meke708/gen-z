const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeLoginWallpaper } = require('./login-wallpaper');

function validInput() {
  return {
    productIds: ['64b64c9b8e4a4b9e8f412345'],
    rotatePromotions: true,
    topLine: 'Local finds',
    headline: 'Good things',
    headlineAccent: 'close to home',
    description: 'Made here',
    caption: 'A little local joy',
    footerLeft: 'Shop local',
    footerRight: 'Made for Namibia',
    imageX: 48.6,
    imageY: 72.2,
    overlay: 0.2
  };
}

test('login wallpaper settings trim copy and normalize image controls', () => {
  const result = normalizeLoginWallpaper({
    ...validInput(),
    headline: '  Good things  '
  });
  assert.deepEqual(result, {
    settings: {
      ...validInput(),
      headline: 'Good things',
      imageX: 49,
      imageY: 72,
      overlay: 0.2
    }
  });
});

test('login wallpaper settings accept only one selected product without rotation', () => {
  const productIds = ['64b64c9b8e4a4b9e8f412345'];
  const result = normalizeLoginWallpaper({ ...validInput(), productIds, rotatePromotions: false });
  assert.deepEqual(result.settings.productIds, productIds);
  assert.equal(result.settings.rotatePromotions, false);
});

test('login wallpaper settings reject multiple selected products without rotation', () => {
  const productIds = ['64b64c9b8e4a4b9e8f412345', '64b64c9b8e4a4b9e8f412346'];
  const result = normalizeLoginWallpaper({ ...validInput(), productIds, rotatePromotions: false });
  assert.match(result.error, /only one promoted product/);
});

test('login wallpaper settings reject invalid text and control values', () => {
  assert.match(normalizeLoginWallpaper({ ...validInput(), productIds: ['invalid'] }).error, /list of promoted products/);
  assert.match(normalizeLoginWallpaper({ ...validInput(), productIds: [] }).error, /Select at least one/);
  assert.match(normalizeLoginWallpaper({ ...validInput(), productIds: ['64b64c9b8e4a4b9e8f412345', '64b64c9b8e4a4b9e8f412345'] }).error, /list of promoted products/);
  assert.match(normalizeLoginWallpaper({ ...validInput(), rotatePromotions: 'yes' }).error, /rotate/);
  assert.match(normalizeLoginWallpaper({ ...validInput(), caption: 'x'.repeat(161) }).error, /160 characters/);
  assert.match(normalizeLoginWallpaper({ ...validInput(), imageX: 101 }).error, /imageX/);
  assert.match(normalizeLoginWallpaper({ ...validInput(), overlay: 0.61 }).error, /overlay/);
  assert.match(normalizeLoginWallpaper({ ...validInput(), headline: null }).error, /headline/);
  assert.match(normalizeLoginWallpaper({ ...validInput(), headline: '  ' }).error, /Enter text/);
  assert.equal(normalizeLoginWallpaper({ ...validInput(), caption: '' }).settings.caption, '');
  assert.match(normalizeLoginWallpaper(null).error, /valid login wallpaper/);
});
