const { createCipheriv, createDecipheriv, randomBytes } = require('crypto');

const envelopeHeader = Buffer.from('ZKYC1');
const ivLength = 12;
const authTagLength = 16;

function getKycEncryptionKey(encodedKey = process.env.KYC_ENCRYPTION_KEY) {
  if (typeof encodedKey !== 'string' || !encodedKey.trim()) {
    throw new Error('KYC document storage is not configured.');
  }
  const key = Buffer.from(encodedKey, 'base64');
  if (key.length !== 32 || key.toString('base64').replace(/=+$/, '') !== encodedKey.trim().replace(/=+$/, '')) {
    throw new Error('KYC_ENCRYPTION_KEY must be a base64-encoded 32-byte key.');
  }
  return key;
}

function detectKycDocumentMime(buffer) {
  if (!Buffer.isBuffer(buffer)) return null;
  if (buffer.subarray(0, 5).toString('ascii') === '%PDF-') return 'application/pdf';
  if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return 'image/jpeg';
  if (buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  if (buffer.subarray(0, 4).toString('ascii') === 'RIFF' && buffer.subarray(8, 12).toString('ascii') === 'WEBP') return 'image/webp';
  return null;
}

function encryptKycDocument(documentBuffer, key = getKycEncryptionKey()) {
  if (!Buffer.isBuffer(documentBuffer) || !documentBuffer.length) throw new Error('KYC document is empty.');
  const iv = randomBytes(ivLength);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(documentBuffer), cipher.final()]);
  return Buffer.concat([envelopeHeader, iv, cipher.getAuthTag(), ciphertext]);
}

function decryptKycDocument(envelope, key = getKycEncryptionKey()) {
  const minimumLength = envelopeHeader.length + ivLength + authTagLength + 1;
  if (!Buffer.isBuffer(envelope) || envelope.length < minimumLength || !envelope.subarray(0, envelopeHeader.length).equals(envelopeHeader)) {
    throw new Error('Encrypted KYC document is invalid.');
  }
  let offset = envelopeHeader.length;
  const iv = envelope.subarray(offset, offset += ivLength);
  const authTag = envelope.subarray(offset, offset += authTagLength);
  const ciphertext = envelope.subarray(offset);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

module.exports = { decryptKycDocument, detectKycDocumentMime, encryptKycDocument, getKycEncryptionKey };