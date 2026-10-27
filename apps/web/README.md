# Dragon Shield web application

Next.js App Router frontend for the Cyber Dragon MVP. The scanner uses a server-side proxy to the FastAPI service, so the browser never needs the API URL.

## Run locally

Start the API from `services/threat-api` (see repository README).

```bash
cd apps/web
cp .env.example .env.local
npm install
npm run dev
```

Open http://localhost:3000. Run `npm run lint` for TypeScript checks and `npm run build` for a production build.

## Deploy

Deploy `apps/web` as a Next.js application and configure server-only `THREAT_API_URL` to a separately deployed HTTPS FastAPI endpoint. **Do not** set the URL to `localhost` in production unless the API runs in the same deployment environment. The API currently has no production abuse-rate limits; configure them at your ingress before a public launch.

No login, database, AI provider, or reputation API is needed for this MVP. Results are advisory only.
