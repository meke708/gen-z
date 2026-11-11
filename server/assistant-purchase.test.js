const test = require('node:test');
const assert = require('node:assert/strict');
const { isAssistantPlanPaid } = require('./server');

test('assistant access requires a completed purchase, not an old test activation', () => {
  assert.equal(isAssistantPlanPaid({ assistantPlanActive: true }), false);
  assert.equal(isAssistantPlanPaid({
    assistantPlanActive: true,
    assistantPlanPaidAt: new Date('2026-01-01T00:00:00.000Z')
  }), true);
  assert.equal(isAssistantPlanPaid({
    assistantPlanActive: false,
    assistantPlanPaidAt: new Date('2026-01-01T00:00:00.000Z')
  }), false);
});
