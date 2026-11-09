const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, 'wishlist-sync.js'), 'utf8');

function createWishlistSync(localValues, accountWishlist) {
  const calls = [];
  const localStorage = {
    getItem(key) {
      return localValues.get(key) || null;
    },
    setItem(key, value) {
      localValues.set(key, value);
    }
  };
  const window = {
    addEventListener() {},
    clearTimeout() {},
    dispatchEvent() {},
    setTimeout() {
      return 1;
    }
  };
  const fetch = async (url, options = {}) => {
    calls.push({ url, options });
    const body = options.body ? JSON.parse(options.body) : null;
    if (url === '/api/auth/status') {
      return { ok: true, json: async () => ({ user: { id: 'buyer-1' } }) };
    }
    if (url === '/api/account/wishlist' && options.method === 'PUT') {
      accountWishlist.ids = body.ids;
      return { ok: true, json: async () => ({ ids: accountWishlist.ids }) };
    }
    if (url === '/api/account/wishlist') {
      return { ok: true, json: async () => ({ ids: accountWishlist.ids, products: [] }) };
    }
    const id = url.split('/').pop();
    if (url.startsWith('/api/account/wishlist/') && options.method === 'POST') {
      accountWishlist.ids = [...new Set([...accountWishlist.ids, id])];
      return { ok: true, json: async () => ({ ids: accountWishlist.ids }) };
    }
    if (url.startsWith('/api/account/wishlist/') && options.method === 'DELETE') {
      accountWishlist.ids = accountWishlist.ids.filter((entry) => entry !== id);
      return { ok: true, json: async () => ({ ids: accountWishlist.ids }) };
    }
    throw new Error(`Unexpected wishlist request: ${url}`);
  };

  vm.runInNewContext(source, {
    AbortController,
    CustomEvent: class CustomEvent {},
    fetch,
    localStorage,
    window
  });
  return { sync: window.ZWishlistSync, calls };
}

test('wishlist sync imports a guest list into the account on first login', async () => {
  const guestId = '0123456789abcdef01234567';
  const accountId = '1123456789abcdef01234567';
  const localValues = new Map([
    ['z_wishlist', JSON.stringify([guestId])]
  ]);
  const accountWishlist = { ids: [accountId] };
  const { sync, calls } = createWishlistSync(localValues, accountWishlist);

  await sync.initialize();

  assert.equal(JSON.stringify(sync.readWishlist()), JSON.stringify([accountId, guestId]));
  assert.equal(JSON.stringify(accountWishlist.ids), JSON.stringify([accountId, guestId]));
  assert.equal(calls.filter((call) => call.options.method === 'PUT').length, 1);
});

test('same-account wishlist refresh respects products removed from the account', async () => {
  const removedId = '0123456789abcdef01234567';
  const retainedId = '1123456789abcdef01234567';
  const localValues = new Map([
    ['z_wishlist_owner', 'buyer-1'],
    ['z_wishlist', JSON.stringify([removedId, retainedId])]
  ]);
  const { sync } = createWishlistSync(localValues, { ids: [retainedId] });

  await sync.initialize();

  assert.equal(JSON.stringify(sync.readWishlist()), JSON.stringify([retainedId]));
});

test('signed-in wishlist toggle adds and removes only the selected product remotely', async () => {
  const id = '0123456789abcdef01234567';
  const localValues = new Map([
    ['z_wishlist_owner', 'buyer-1'],
    ['z_wishlist', '[]']
  ]);
  const accountWishlist = { ids: [] };
  const { sync, calls } = createWishlistSync(localValues, accountWishlist);

  await sync.initialize();
  sync.toggle(id);
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(JSON.stringify(accountWishlist.ids), JSON.stringify([id]));

  sync.toggle(id);
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(JSON.stringify(accountWishlist.ids), JSON.stringify([]));
  assert.deepEqual(calls.map((call) => call.options.method).filter(Boolean), ['POST', 'DELETE']);
});
