const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeAdminNotificationInput } = require('./server');

test('admin notifications normalize all-account sends without selected recipients', () => {
  assert.deepEqual(normalizeAdminNotificationInput({
    title: '  Service update  ',
    message: '  The service will be unavailable briefly.  ',
    audience: 'all',
    destination: 'account'
  }), {
    title: 'Service update',
    message: 'The service will be unavailable briefly.',
    audience: 'all',
    destination: 'account',
    recipientIds: []
  });
});

test('admin notifications deduplicate valid selected account IDs', () => {
  const accountId = '507f1f77bcf86cd799439011';
  assert.deepEqual(normalizeAdminNotificationInput({
    title: 'Update',
    message: 'Please check your account.',
    audience: 'selected',
    destination: 'seller',
    recipientIds: [accountId, accountId]
  }), {
    title: 'Update',
    message: 'Please check your account.',
    audience: 'selected',
    destination: 'seller',
    recipientIds: [accountId]
  });
});

test('admin notifications accept all and selected account audiences', () => {
  for (const audience of ['all', 'selected']) {
    const recipientIds = audience === 'selected' ? ['507f1f77bcf86cd799439011'] : [];
    assert.deepEqual(normalizeAdminNotificationInput({
      title: 'Update',
      message: 'Please check your account.',
      audience,
      recipientIds
    }), {
      title: 'Update',
      message: 'Please check your account.',
      audience,
      destination: 'both',
      recipientIds
    });
  }
});

test('admin notifications default to both destinations and reject unknown destinations', () => {
  assert.equal(normalizeAdminNotificationInput({
    title: 'Update',
    message: 'Please check your account.',
    audience: 'all'
  }).destination, 'both');
  assert.match(normalizeAdminNotificationInput({
    title: 'Update',
    message: 'Please check your account.',
    audience: 'all',
    destination: 'unknown'
  }).error, /Choose the account dashboard, seller workspace, or both/);
});

test('admin notifications reject invalid audience, content, and recipient lists', () => {
  const base = { title: 'Update', message: 'Message', audience: 'selected' };
  assert.match(normalizeAdminNotificationInput({ ...base, audience: 'unknown' }).error, /all accounts or selected accounts/);
  assert.match(normalizeAdminNotificationInput({ ...base, audience: 'buyers' }).error, /all accounts or selected accounts/);
  assert.match(normalizeAdminNotificationInput({ ...base, audience: 'sellers' }).error, /all accounts or selected accounts/);
  assert.match(normalizeAdminNotificationInput({ ...base, title: ' ' }).error, /Enter a title/);
  assert.match(normalizeAdminNotificationInput({ ...base, message: 'x'.repeat(1001) }).error, /Enter a title/);
  assert.match(normalizeAdminNotificationInput({ ...base, recipientIds: [] }).error, /Select between 1 and 100/);
  assert.match(normalizeAdminNotificationInput({ ...base, recipientIds: ['invalid'] }).error, /Select between 1 and 100/);
  assert.match(normalizeAdminNotificationInput({
    title: 'Update',
    message: 'Message',
    audience: 'all',
    recipientIds: ['507f1f77bcf86cd799439011']
  }).error, /Individual accounts can only be included/);
});
