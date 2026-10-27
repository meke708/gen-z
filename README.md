# Z Namibia

Z Namibia is a marketplace prototype with buyer accounts, seller storefronts, product listings, order management, business verification, and a local shop assistant.

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
- Configure image uploads and password reset email using the `CLOUDINARY_*` and `SMTP_*` settings. Set `APP_BASE_URL` to the final HTTPS Render URL.
- The Blueprint disables mock checkout in production. Configure a real payment adapter before accepting live payments; this repository currently has no live payment adapter.
- The Terms page is a draft and still requires legal review, operator contact details, and a separate Privacy Policy before launch.
