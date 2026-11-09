# Z Namibia

Z Namibia is a marketplace prototype with buyer accounts, wishlists and synchronized carts, seller storefronts, product listings and paid promotion campaigns, order management, business verification, and a local shop assistant.

## Requirements

- Node.js 20 or newer
- MongoDB
- Ollama for local shop-assistant responses

## Local setup

1. Install server dependencies:

   ```powershell
   cd server
   npm install
   Copy-Item .env.example .env
   ```

2. Configure `server/.env`. For local development, keep `MONGODB_URI` pointed at the local MongoDB instance. Set `ADMIN_USER_ID` to the verified account ID for `ADMIN_EMAIL` to enable the owner portal.
3. Install and start Ollama, then download the configured model:

   ```powershell
   ollama pull llama3.2:3b
   ```

4. Start the server:

   ```powershell
   npm run dev
   ```

5. Open `http://localhost:3001`.

Run the server tests from the project root with `npm --prefix server test`.

## Login notification network details

Login notifications always store the client IP reported by Express. If the server is behind a reverse proxy, set `TRUST_PROXY_HOPS` to the exact number of trusted proxies so Express can safely resolve `X-Forwarded-For`; do not trust forwarded headers from untrusted clients.

Country, city, and network provider are resolved offline using MaxMind City and ASN `.mmdb` databases. Obtain databases under the applicable MaxMind license and set `GEOIP_CITY_DATABASE_PATH` and `GEOIP_ASN_DATABASE_PATH` in `server/.env` to their paths (relative paths are resolved from `server/`). If a database is not configured or does not contain a match, that field is shown as unavailable. No login IP is sent to a third-party lookup service.

## Private KYC storage

KYC uploads are encrypted and stored under `server/private/kyc/`, which is excluded from Git. Before accepting submissions, set `KYC_ENCRYPTION_KEY` in `server/.env` to a new base64-encoded 32-byte key:

```powershell
node -p "require('crypto').randomBytes(32).toString('base64')"
```

Keep this key in a secret manager or password manager, separately from any encrypted-document backups. Do not commit it. Losing the key makes documents that have not yet been reviewed unreadable.

## Deployment notes

- A free-tier Render Blueprint is provided in `render.yaml`. Create the service from the private GitHub repository and supply the prompted secret environment variables in Render. Free instances may spin down and use ephemeral filesystems, so treat this as a preview deployment, not a production storefront.
- Create a production MongoDB database separately and set `MONGODB_URI`. Production startup requires `ADMIN_EMAIL=z@gmail.com` and the matching verified account ID in `ADMIN_USER_ID`. The configured email and ID must both match; there is no override key.
- The Super Admin manages moderator roles from `/admin/accounts`; only verified accounts can be promoted, and no more than three moderators can be active. Moderators can review new shops, new product listings, listing reports, and general marketplace support requests. New general support requests create in-dashboard notifications for all active moderators so they can pull work from the shared inbox. Financial and verification/identity support, payouts, user management, KYC, platform fees, and commission revenue remain Super Admin-only.
- Listing reports are unique per reporter and product and rate-limited. Completed, paid buyer orders for the reported product add 25 priority points; other buyers add 5; active shop owners need to provide details and add 0 points. At 50 pending points a listing is temporarily hidden for review, while all reports remain visible to moderators. Dismissing a report recalculates the score and automatically restores listings hidden by the report threshold when their score falls below 50; moderator-hidden listings stay hidden until manually restored. Three reports dismissed as unfounded pause further reporting for that account; the restriction is explicit rather than silently dropping reports. Super Admins can open an account activity page to review recent sign-ins, orders, reports, support, appeals, and transparent report-priority signals; these indicators are not proof of fraud or fraud probabilities. Suspension appeals and support requests show rule-based likely-issue suggestions and draft replies; these are triage aids, not measured probabilities or automated decisions. Moderation, account suspension/reactivation, and seller access suspension/reactivation decisions retain the acting moderator/admin ID and are shown in their respective admin dashboards.
- Automatic seller holds are triggered when three distinct listings from one shop first reach 50 pending report points within a rolling 48-hour window. The shop is hidden and the seller is restricted for 24 hours: new listings, inventory changes, and payouts pause, while sign-in, buyer activity, and existing order fulfillment remain available. The hold and triggering listings appear in the Admin Moderation Queue; a Super Admin can release the hold or confirm a permanent seller-only restriction. Expired holds release automatically, and the same threshold events cannot repeatedly re-trigger a hold. Reports are signals for review, not proof of fraud; buyers are never automatically suspended by this rule.
- New shops and product listings are hidden until approved. Existing shops and listings remain approved. Rejected listings can be edited and resubmitted; sellers should contact support to appeal a rejected shop profile.
- The Super Admin can change the platform commission at `/admin/platform`. The setting is stored in MongoDB, bounded from 0% to 100%, and applies only to newly created orders. New orders store their commission rate and calculated commission amounts as snapshots; historical orders are not recalculated. The revenue figure is the sum of commissions on paid orders.
- A development sandbox user is created only when the configured `SANDBOX_EMAIL` registers against a loopback MongoDB URI with `NODE_ENV` other than `production`. The sandbox role does not grant moderation or Super Admin access and cannot be activated against a hosted database.
- KYC uploads are disabled on the free Blueprint because local files are not durable. To enable them later, configure durable private storage, set `KYC_STORAGE_DURABLE=true` and `KYC_STORAGE_DIR`, and keep `KYC_ENCRYPTION_KEY` backed up separately from the documents.
- The shop assistant needs a reachable Ollama service with the configured model. Set `AI_OLLAMA_URL` to a private, reachable endpoint; do not expose the Ollama port publicly. Until configured, assistants remain unavailable.
- Configure image uploads and password reset email using the `CLOUDINARY_*` and `SMTP_*` settings. Render supplies the public service URL for reset and verification links automatically; set `APP_BASE_URL` only when using a custom HTTPS domain.
- The Blueprint disables mock checkout in production by default. To test orders on a non-customer-facing Render deployment, set `MOCK_PAYMENTS_ENABLED=true` and `ALLOW_MOCK_PAYMENTS_IN_PRODUCTION=true` in that service's environment, then redeploy. Mock checkout only records simulated payments; it does not charge money. Turn it off before accepting real customers. Configure a real payment adapter before accepting live payments; this repository currently has no live payment adapter.
- Product promotions are currently N$50 for 7 days and use the simulated test-payment flow only. No money is charged; in production this flow requires the mock-payment testing opt-in described above.
- Sellers can view promotion impressions, clicks, click-through rates, and a 30-day daily trend at `/sell/promotions`. An impression is recorded after a promoted card or dashboard banner is at least half visible; counts are deduplicated per anonymous browser session, campaign, placement, and UTC day. Raw IP addresses are not collected for promotion analytics.
- The Terms page is a draft and still requires legal review, operator contact details, and a separate Privacy Policy before launch.
- The public help and FAQ page is available at `/support`. Signed-in users can submit general, financial, or verification requests and track responses. Financial and verification topics are classified by the server and excluded from moderator support queries.
- Suspended users are sent to `/account-suspended` after a successful password check. That sign-in issues a 10-minute appeal token so they can check for an existing appeal and submit without depending on email delivery; the token is consumed on submission. The page clearly says when a request is already awaiting review and prevents duplicate submissions. Appeals are rate-limited, limited to one active appeal per normalized email, and visible only to the Super Admin in the support inbox. The Super Admin may resolve an appeal and reactivate the account together from that queue; resolving without reactivation remains available. Checking status or submitting an appeal does not automatically reinstate accounts.
- The support inbox uses built-in topic and keyword rules to suggest a likely issue, an explicitly heuristic confidence estimate, and an editable response template. These suggestions are not statistically calibrated and are never sent automatically; an authorized reviewer must choose and save any response.
