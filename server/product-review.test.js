const test = require('node:test');
const assert = require('node:assert/strict');
const { getProductBasicDataIssues, getProductReviewDecision } = require('./product-review');

const trustedSeller = {
  sellerEmailVerified: true,
  sellerAccountSuspicious: false
};

function validSafeProduct(overrides = {}) {
  return {
    title: 'Wool coat',
    description: 'Warm locally made clothing.',
    category: 'Clothing',
    imageUrls: ['https://images.example.test/coat.jpg'],
    priceNAD: 850,
    stock: 3,
    ...overrides
  };
}

test('complete products in ordinary categories auto-approve without a seller history threshold', () => {
  for (const category of ['Clothing', 'Shoes', 'Books', 'Furniture', 'Homeware', 'Electronics', 'Beauty', 'Fashion', 'Art & Crafts', 'New category']) {
    assert.deepEqual(getProductReviewDecision({
      sellerEmailVerified: true,
      product: validSafeProduct({ category })
    }), { reviewStatus: 'approved', reviewReasons: [] }, category);
  }
});

test('missing basic listing data is rejected with specific reasons', () => {
  const decision = getProductReviewDecision({
    ...trustedSeller,
    product: validSafeProduct({
      title: '',
      description: '',
      category: '',
      imageUrls: [],
      priceNAD: 0,
      stock: 0
    })
  });
  assert.equal(decision.reviewStatus, 'rejected');
  assert.equal(decision.reviewReasons.length, 6);
});

test('basic product data issues can block manual approval until corrected', () => {
  const issues = getProductBasicDataIssues({
    title: '',
    description: 'Details',
    category: 'Clothing',
    imageUrls: [],
    priceNAD: 10,
    stock: 1
  });
  assert.deepEqual(issues, ['Product title is missing.', 'At least one product image is required.']);
});

test('suspicious seller accounts and unverified seller emails are rejected', () => {
  assert.equal(getProductReviewDecision({
    sellerEmailVerified: true,
    sellerAccountSuspicious: true,
    product: validSafeProduct()
  }).reviewStatus, 'rejected');
  assert.equal(getProductReviewDecision({
    sellerEmailVerified: false,
    product: validSafeProduct()
  }).reviewStatus, 'rejected');
});

test('restricted categories are rejected while ordinary categories auto-approve', () => {
  for (const category of [
    'Health & Medicines (NMRC)',
    'Health',
    'Pharmacy',
    'Telecom / Wi-Fi / Bluetooth (CRAN)',
    'Telecommunications',
    'Food & Agriculture',
    'Food',
    'Second-hand clothes',
    'Used clothing'
  ]) {
    const decision = getProductReviewDecision({
      sellerEmailVerified: true,
      product: validSafeProduct({ category })
    });
    assert.equal(decision.reviewStatus, 'rejected', category);
    assert.ok(decision.reviewReasons.some((reason) => /cannot be listed|cannot be published/.test(reason)), category);
  }
});

test('restricted terms in titles or descriptions are rejected', () => {
  for (const phrase of [
    'pills', 'drug', 'medication', 'supplements', 'prescription', 'controlled substance', 'narcotics',
    'CBD', 'cannabis', 'marijuana', 'cocaine', 'heroin', 'meth', 'fentanyl', 'opioid',
    'Wi-Fi', 'Bluetooth', 'raw meat', 'weapon', 'firearm', 'ammunition', 'fireworks',
    'tobacco', 'vape', 'alcohol', 'beer', 'counterfeit', 'knock-off', 'stolen phone',
    'ivory', 'rhino horn', 'pangolin scales', 'honey', 'live plants', 'wheat', 'raw hides',
    'used tyres', 'uncut diamonds', 'recalled toy', 'second-hand clothes', 'used clothing'
  ]) {
    const descriptionDecision = getProductReviewDecision({
      sellerEmailVerified: true,
      product: validSafeProduct({ description: `Includes ${phrase}.` })
    });
    assert.equal(descriptionDecision.reviewStatus, 'rejected', phrase);
    assert.ok(descriptionDecision.reviewReasons.some((reason) => /cannot be listed|cannot be published/.test(reason)), phrase);
    const titleDecision = getProductReviewDecision({
      sellerEmailVerified: true,
      product: validSafeProduct({ title: `Includes ${phrase}` })
    });
    assert.equal(titleDecision.reviewStatus, 'rejected', phrase);
  }
});

test('ordinary product language is not matched as a partial restricted term', () => {
  const decision = getProductReviewDecision({
    sellerEmailVerified: true,
    product: validSafeProduct({
      title: 'Drugstore Novelty Mug',
      description: 'Wireless charger, glass painting, and golden coloured finish.'
    })
  });
  assert.equal(decision.reviewStatus, 'approved');
});

test('product price is treated as NAD and no tax is added', () => {
  const product = validSafeProduct({ priceNAD: 100 });
  const decision = getProductReviewDecision({ ...trustedSeller, product });
  assert.equal(decision.reviewStatus, 'approved');
  assert.equal(product.priceNAD, 100);
});

test('null or missing product payloads fail gracefully instead of crashing', () => {
  assert.deepEqual(getProductBasicDataIssues(null), [
    'Product title is missing.',
    'Product description is missing.',
    'Product category is missing.',
    'At least one product image is required.',
    'Price must be greater than N$ 0.00.',
    'Stock must be greater than zero.'
  ]);
  assert.equal(getProductReviewDecision(null).reviewStatus, 'rejected');
  assert.equal(getProductReviewDecision({ sellerEmailVerified: true, product: null }).reviewStatus, 'rejected');
  assert.equal(getProductReviewDecision({ sellerEmailVerified: true, product: undefined }).reviewStatus, 'rejected');
});
