const test = require('node:test');
const assert = require('node:assert/strict');
const { createVerificationEmail } = require('./email-templates');

test('verification email thanks the new user and provides HTML and plain-text links', () => {
  const email = createVerificationEmail({
    name: 'Amina',
    verificationUrl: 'https://z.example/verify-email?token=abc'
  });

  assert.match(email.text, /Thank you for registering with Z Namibia/);
  assert.match(email.html, /Thanks for registering, Amina!/);
  assert.match(email.html, /Verify email address/);
  assert.match(email.html, /href="https:\/\/z\.example\/verify-email\?token=abc"/);
  assert.match(email.text, /https:\/\/z\.example\/verify-email\?token=abc/);
});

test('verification email escapes user-controlled HTML values', () => {
  const email = createVerificationEmail({
    name: '<img src=x onerror=alert(1)>',
    verificationUrl: 'https://z.example/verify?token=a&next="home"'
  });

  assert.match(email.html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.doesNotMatch(email.html, /<img src=x onerror=alert\(1\)>/);
  assert.match(email.html, /token=a&amp;next=&quot;home&quot;/);
});

test('verification email matches Z branding and features a promoted marketplace listing', () => {
  const email = createVerificationEmail({
    name: 'Amina',
    verificationUrl: 'https://z.example/verify-email?token=abc',
    featuredProduct: {
      title: 'Handmade basket',
      shopName: 'Local Crafts',
      town: 'Windhoek',
      priceNAD: 180,
      imageUrl: 'https://images.example/basket.jpg',
      url: 'https://z.example/product/product-123'
    }
  });

  assert.match(email.html, /#18382e/);
  assert.match(email.html, /#d8f36a/);
  assert.match(email.html, />Z<\/td>/);
  assert.match(email.html, /A promoted find from the Z marketplace/);
  assert.match(email.html, /Handmade basket/);
  assert.match(email.html, /N\$ 180\.00/);
  assert.match(email.html, /src="https:\/\/images\.example\/basket\.jpg"/);
  assert.match(email.html, /href="https:\/\/z\.example\/product\/product-123"/);
  assert.match(email.text, /Handmade basket by Local Crafts · N\$ 180\.00/);
});

test('verification email omits a promoted listing with an unsafe URL', () => {
  const email = createVerificationEmail({
    name: 'Amina',
    verificationUrl: 'https://z.example/verify-email?token=abc',
    featuredProduct: {
      title: 'Unsafe listing',
      url: 'javascript:alert(1)'
    }
  });

  assert.doesNotMatch(email.html, /Unsafe listing/);
  assert.doesNotMatch(email.html, /javascript:/);
});
