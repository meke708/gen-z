const test = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes } = require('crypto');
const {
  decryptKycDocument,
  detectKycDocumentMime,
  encryptKycDocument,
  getKycEncryptionKey,
  isKycStorageConfigured
} = require('./kyc-storage');

test('KYC document signatures identify supported file types, not MIME claims', () => {
  assert.equal(detectKycDocumentMime(Buffer.from('%PDF-1.7')), 'application/pdf');
  assert.equal(detectKycDocumentMime(Buffer.from([0xff, 0xd8, 0xff, 0x00])), 'image/jpeg');
  assert.equal(detectKycDocumentMime(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])), 'image/png');
  assert.equal(detectKycDocumentMime(Buffer.from('RIFF0000WEBP')), 'image/webp');
  assert.equal(detectKycDocumentMime(Buffer.from('not a document')), null);
});

test('KYC encryption round-trips and detects tampering', () => {
  const key = randomBytes(32);
  const document = Buffer.from('%PDF-1.7 private business document');
  const envelope = encryptKycDocument(document, key);
  assert.notDeepEqual(envelope, document);
  assert.deepEqual(decryptKycDocument(envelope, key), document);
  envelope[envelope.length - 1] ^= 0x01;
  assert.throws(() => decryptKycDocument(envelope, key));
});

test('KYC encryption key must be configured as a base64 32-byte key', () => {
  assert.throws(() => getKycEncryptionKey(''), /not configured/);
  assert.throws(() => getKycEncryptionKey(Buffer.from('short').toString('base64')), /32-byte/);
  assert.equal(getKycEncryptionKey(randomBytes(32).toString('base64')).length, 32);
});

test('production KYC requires both a valid key and durable storage', () => {
  const key = randomBytes(32).toString('base64');
  assert.equal(isKycStorageConfigured({ nodeEnv: 'production', durableStorage: false, encodedKey: key }), false);
  assert.equal(isKycStorageConfigured({ nodeEnv: 'production', durableStorage: true, encodedKey: '' }), false);
  assert.equal(isKycStorageConfigured({ nodeEnv: 'production', durableStorage: true, encodedKey: key }), true);
  assert.equal(isKycStorageConfigured({ nodeEnv: 'development', durableStorage: false, encodedKey: key }), true);
});