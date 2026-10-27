const test = require('node:test');
const assert = require('node:assert/strict');
const { answerKnownShopQuestion, buildAssistantMessages, isAssistantModelReady, requestShopAssistantAnswer } = require('./shop-assistant');

const shop = {
  name: 'Oshakati Phones',
  description: 'Mobile phones and accessories.',
  town: 'Oshakati',
  shippingRates: { localNAD: 30 }
};

test('assistant context includes shop ratings, product images, and the real order workflow', () => {
  const messages = buildAssistantMessages({
    shop,
    products: [{ title: 'Phone A', description: 'New phone', priceNAD: 1200, stock: 2, category: 'Electronics', town: 'Oshakati', imageUrl: 'https://images.example.test/phone-a.jpg' }],
    ratingSummary: { averageRating: 3.8, reviewCount: 4 },
    history: [],
    question: 'Is Phone A available?'
  });
  const context = messages[1].content;
  assert.match(context, /Oshakati Phones/);
  assert.match(context, /Mobile phones and accessories/);
  assert.match(context, /"localNAD":30/);
  assert.match(context, /"averageRating":3.8/);
  assert.match(context, /"reviewCount":4/);
  assert.match(context, /Phone A/);
  assert.match(context, /"priceNAD":1200/);
  assert.match(context, /"stock":2/);
  assert.match(context, /"imageAvailable":true/);
  assert.match(context, /Add to cart/);
  assert.match(context, /Simulate test payment/);
  assert.match(context, /No shop-specific return/);
  assert.doesNotMatch(context, /sellerGuidance|frequentlyAskedQuestions|Warranty: 30 days/i);
  assert.doesNotMatch(context, /another shop/i);
});

test('assistant requests use the local model API without an external API key', async () => {
  let request;
  const answer = await requestShopAssistantAnswer({
    shop,
    products: [],
    question: 'Where are you based?',
    model: 'test-model:1b',
    endpoint: 'http://127.0.0.1:11434/api/chat',
    fetchImpl: async (url, options) => {
      request = { url, options };
      return { ok: true, json: async () => ({ message: { content: 'We are in Oshakati.' } }) };
    }
  });

  assert.equal(answer, 'We are in Oshakati.');
  assert.equal(request.url, 'http://127.0.0.1:11434/api/chat');
  assert.equal(request.options.headers.Authorization, undefined);
  assert.equal(JSON.parse(request.options.body).model, 'test-model:1b');
  assert.equal(JSON.parse(request.options.body).stream, false);
});

test('assistant requests report a clear error when the local model is unavailable', async () => {
  await assert.rejects(
    requestShopAssistantAnswer({ shop, products: [], question: 'Hello', fetchImpl: async () => { throw new Error('connection refused'); } }),
    { statusCode: 502, message: 'The shop assistant is temporarily unavailable. Please try again.' }
  );
});

test('model readiness requires the configured model to be installed in Ollama', async () => {
  const ready = await isAssistantModelReady({
    model: 'store-model:1b',
    baseUrl: 'http://ollama-readiness-test',
    fetchImpl: async () => ({ ok: true, json: async () => ({ models: [{ name: 'store-model:1b' }] }) })
  });
  assert.equal(ready, true);

  const missing = await isAssistantModelReady({
    model: 'missing-model:1b',
    baseUrl: 'http://ollama-missing-test',
    fetchImpl: async () => ({ ok: true, json: async () => ({ models: [] }) })
  });
  assert.equal(missing, false);
});

test('known shop questions return exact ratings, images, buying steps, and policy limits', () => {
  const products = [{ title: 'iPhone 13', imageUrl: 'https://images.example.test/iphone13.jpg' }];
  const ratingSummary = { averageRating: 3.8, reviewCount: 4 };
  assert.match(answerKnownShopQuestion({ shop, products, ratingSummary, question: 'What is the rating?' }), /3\.8 out of 5 from 4 reviews/);
  assert.match(answerKnownShopQuestion({ shop, products, ratingSummary, question: 'Do you have any image?' }), /iPhone 13/);
  assert.match(answerKnownShopQuestion({ shop, products, ratingSummary, question: 'How do I buy online?' }), /Add to cart.*checkout.*no money is charged/i);
  assert.match(answerKnownShopQuestion({ shop, products, ratingSummary, question: 'What are the terms and conditions?' }), /has not published shop-specific terms.*available at \/terms/i);
  assert.match(answerKnownShopQuestion({ shop, products, ratingSummary, question: 'Can I visit the store?' }), /no street address or walk-in store details/);
});

test('known answers do not call Ollama', async () => {
  const answer = await requestShopAssistantAnswer({
    shop,
    products: [],
    ratingSummary: { averageRating: 3.8, reviewCount: 4 },
    question: 'What is your rating?',
    fetchImpl: async () => assert.fail('known factual answers should not call Ollama')
  });
  assert.match(answer, /3\.8 out of 5/);
});

test('product questions name actual active products instead of guessing from the category', () => {
  const answer = answerKnownShopQuestion({
    shop,
    products: [{ title: 'iPhone 13', description: 'iPhone 13 smartphone', priceNAD: 12000.99, stock: 2 }],
    ratingSummary: { averageRating: 3.8, reviewCount: 4 },
    question: 'What does this shop really sell?'
  });
  assert.match(answer, /iPhone 13: iPhone 13 smartphone, N\$ 12000\.99, 2 in stock/);
});