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

test('verification email uses Z branding without promotional content', () => {
  const email = createVerificationEmail({
    name: 'Amina',
    verificationUrl: 'https://z.example/verify-email?token=abc'
  });

  assert.match(email.html, /#18382e/);
  assert.match(email.html, /#d8f36a/);
  assert.match(email.html, />Z<\/td>/);
  assert.match(email.html, /NAMIBIA/);
  assert.doesNotMatch(email.html, />Z NAMIBIA</);
  assert.doesNotMatch(email.html, /A promoted find|View product|Handmade basket/);
  assert.doesNotMatch(email.text, /Sponsored find|Handmade basket/);
});
