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

2. Configure `server/.env`. At minimum, set `MONGODB_URI` and `PORT`.
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
- Create a MongoDB database separately and set `MONGODB_URI`. The app also requires `ADMIN_EMAIL` and the matching MongoDB user ID in `ADMIN_USER_ID` before production startup.
- KYC uploads are disabled on the free Blueprint because local files are not durable. To enable them later, configure durable private storage, set `KYC_STORAGE_DURABLE=true` and `KYC_STORAGE_DIR`, and keep `KYC_ENCRYPTION_KEY` backed up separately from the documents.
- The shop assistant needs a reachable Ollama service with the configured model. Set `AI_OLLAMA_URL` to a private, reachable endpoint; do not expose the Ollama port publicly. Until configured, assistants remain unavailable.
- Configure image uploads and password reset email using the `CLOUDINARY_*` and `SMTP_*` settings. Render supplies the public service URL for reset and verification links automatically; set `APP_BASE_URL` only when using a custom HTTPS domain.
- The Blueprint disables mock checkout in production by default. To test orders on a non-customer-facing Render deployment, set `MOCK_PAYMENTS_ENABLED=true` and `ALLOW_MOCK_PAYMENTS_IN_PRODUCTION=true` in that service's environment, then redeploy. Mock checkout only records simulated payments; it does not charge money. Turn it off before accepting real customers. Configure a real payment adapter before accepting live payments; this repository currently has no live payment adapter.
- Product promotions are currently N$50 for 7 days and use the simulated test-payment flow only. No money is charged; in production this flow requires the mock-payment testing opt-in described above.
- Sellers can view promotion impressions, clicks, click-through rates, and a 30-day daily trend at `/sell/promotions`. An impression is recorded after a promoted card or dashboard banner is at least half visible; counts are deduplicated per anonymous browser session, campaign, placement, and UTC day. Raw IP addresses are not collected for promotion analytics.
- The Terms page is a draft and still requires legal review, operator contact details, and a separate Privacy Policy before launch.
