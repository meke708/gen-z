# Credential and Wallet Readiness Review

**Verdict: Not ready for real-money operations.**

This review covers account credential handling and wallet/payment behavior in
the current repository. It is a focused code review, not a penetration test,
provider approval, or compliance assessment. Secret values were not reviewed.

## Findings

| # | Severity | File | Lines | Finding | Confidence |
|---|----------|------|-------|---------|------------|
| 1 | HIGH | [README.md](README.md), [server/payment-adapter.js](server/payment-adapter.js), [server/server.js](server/server.js) | README 87; adapter 53-59; server 1824, 4562 | **Real-money readiness blocker.** The configured DPO integration is sandbox-only, mock payments do not move funds, and payout requests report `fundsMoved: false`. Wallet amounts must not be presented as redeemable customer funds until live payment and payout rails, settlement reconciliation, and refund/chargeback handling are implemented and tested. | 9/10 |
| 2 | MEDIUM | [server/server.js](server/server.js) | 1393-1407, 1932-1972, 2086-2115 | **Automatic balance correction can act without review.** On an authenticated interaction, a mismatch can be corrected to the latest ledger balance when ledger totals appear internally consistent. A missing earlier ledger entry or legitimate adjustment could still make that ledger an incomplete source of truth, so the correction could change a valid balance. | 9/10 |

## Controls observed

- Passwords use per-user random salts and `scrypt`, with timing-safe comparison.
- Session tokens are stored as hashes; sessions expire and can be revoked. Cookies
  use `HttpOnly`, `SameSite=Lax`, and `Secure` in production.
- Login and registration are rate-limited; password reset clears existing sessions.
- Wallet mutations use MongoDB transactions, conditional balance checks, and
  unique transaction references.
- DPO sandbox checkout verifies the result server-to-server and checks payment
  amount and currency before settlement.

## Before accepting real customer funds

1. Keep production in test-only mode until approved live payment and payout
   integrations, refunds, chargebacks, settlement reconciliation, and failure
   recovery are implemented and tested.
2. Make balance discrepancies review-only, or require a separately authorized,
   append-only adjustment with a clear audit trail before changing a balance.
3. Add MFA for privileged accounts and step-up verification for sensitive wallet
   and payout actions.
4. Verify database backup and restore procedures and test authentication and
   money flows in a non-customer-facing staging environment.
