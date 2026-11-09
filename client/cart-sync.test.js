const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync(require('node:path').join(__dirname, 'cart-sync.js'), 'utf8');

function createCartSync(localValues, accountCart) {
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
    if (url === '/api/account/cart' && options.method === 'PUT') {
      accountCart.items = body.items;
      return { ok: true, json: async () => ({ items: accountCart.items }) };
    }
    if (url === '/api/account/cart') {
      return { ok: true, json: async () => ({ items: accountCart.items }) };
    }
    throw new Error(`Unexpected cart request: ${url}`);
  };

  vm.runInNewContext(source, {
    AbortController,
    CustomEvent: class CustomEvent {},
    fetch,
    localStorage,
    window
  });
  return { sync: window.ZCartSync, calls };
}

test('refreshing a synced cart does not add matching device and account quantities', async () => {
  const id = '0123456789abcdef01234567';
  const localValues = new Map([
    ['z_cart_owner', 'buyer-1'],
    ['z_cart', JSON.stringify([{ id, quantity: 2 }])]
  ]);
  const accountCart = { items: [{ id, quantity: 2 }] };

  for (let refresh = 0; refresh < 4; refresh += 1) {
    const { sync, calls } = createCartSync(localValues, accountCart);
    await sync.initialize();
    assert.equal(JSON.stringify(sync.readCart()), JSON.stringify([{ id, quantity: 2 }]));
    assert.equal(accountCart.items[0].quantity, 2);
    assert.equal(calls.filter((call) => call.options.method === 'PUT').length, 0);
  }
});

test('refreshing a synced cart does not restore a product removed on another device', async () => {
  const removedId = '0123456789abcdef01234567';
  const keptId = '1123456789abcdef01234567';
  const localValues = new Map([
    ['z_cart_owner', 'buyer-1'],
    ['z_cart', JSON.stringify([
      { id: removedId, quantity: 1 },
      { id: keptId, quantity: 2 }
    ])]
  ]);
  const accountCart = { items: [{ id: keptId, quantity: 2 }] };
  const { sync, calls } = createCartSync(localValues, accountCart);

  await sync.initialize();

  assert.equal(JSON.stringify(sync.readCart()), JSON.stringify([{ id: keptId, quantity: 2 }]));
  assert.equal(JSON.stringify(accountCart.items), JSON.stringify([{ id: keptId, quantity: 2 }]));
  assert.equal(calls.filter((call) => call.options.method === 'PUT').length, 0);
});

test('cart merge keeps the higher quantity for a product while preserving new products', () => {
  const id = '0123456789abcdef01234567';
  const secondId = '1123456789abcdef01234567';
  const { sync } = createCartSync(new Map(), { items: [] });

  assert.equal(JSON.stringify(sync.mergeCarts(
    [{ id, quantity: 1 }],
    [{ id, quantity: 2 }, { id: secondId, quantity: 1 }]
  )), JSON.stringify([
    { id, quantity: 2 },
    { id: secondId, quantity: 1 }
  ]));
});
