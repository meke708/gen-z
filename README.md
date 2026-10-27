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

- Deploy the Node server with a managed MongoDB database.
- The shop assistant needs a reachable Ollama service and the configured model. Set `AI_OLLAMA_URL` to that service; avoid exposing the Ollama port publicly.
- Use persistent private storage for `server/private/kyc/` if pending KYC submissions must survive restarts or redeployments. Back up encrypted files separately from `KYC_ENCRYPTION_KEY`.
- Configure image uploads and email only when needed using the `CLOUDINARY_*` and `SMTP_*` settings.
- Checkout currently uses mock payments. Configure a real payment adapter before accepting real payments or deploying checkout as a production service.
- The Terms page is a draft and still requires legal review, operator contact details, and a separate Privacy Policy before launch.
