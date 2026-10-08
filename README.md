# TakaTrack

Personal money manager (installable PWA) with username/password accounts. No email, no verification.

- Frontend: `public/index.html` (single file, no build step)
- Backend: Vercel serverless functions in `api/` (`auth.js`, `data.js`)
- Database: Upstash Redis (REST), added from the Vercel Marketplace
- Passwords: scrypt hashes. Sessions: signed HttpOnly cookie, 30 days.

## Deploy on Vercel

1. Push this folder to a GitHub repo (or run `npx vercel` inside it).
2. Import the repo in Vercel. Framework preset: **Other**. No build command needed.
3. In the project, open **Storage** and add **Upstash for Redis** (Marketplace). This adds
   `KV_REST_API_URL` and `KV_REST_API_TOKEN` to the project. (`UPSTASH_REDIS_REST_URL` /
   `UPSTASH_REDIS_REST_TOKEN` also work.)
4. Open **Settings > Environment Variables** and add `AUTH_SECRET` with a random string of 32+
   characters. Generate one with: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
5. Redeploy so the new variables apply.

Open the site, tap **Sign up**, choose a username and password. On a phone, use the browser menu
**Add to Home Screen** (Chrome shows an Install prompt) to get the app icon.

## Notes

- Signup is open to anyone with the URL. Each account only sees its own data.
- Login attempts are rate limited per IP and username (10 per 15 minutes).
- There is no password reset (no email). Users can export a JSON backup from Settings.
- Local development: `npx vercel dev` with the same environment variables in `.env.local`.
# sampay
