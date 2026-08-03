# Binayah Estate — landing page

Standalone lead-capture landing page for **binayahestate.com**. Built for email
campaigns: a subscription form that feeds Binayah's shared leads/newsletter pool,
plus prominent links through to the main site, **binayah.ae**.

- `index.html` — the page (static)
- `assets/` — hero + interior imagery
- `api/subscribe.js` — serverless subscribe endpoint (writes encrypted rows to
  the shared `marketreportsubscriptions` collection, `source: binayahestate-landing`)

## Deploy

Hosted on Vercel. Pushes to `main` auto-deploy.

### Env vars (set in Vercel project)

- `MONGODB_URI` — shared Atlas cluster
- `ENCRYPTION_KEY` — 64-hex AES-256-GCM key (must match binayah-properties)
- `HMAC_KEY` — 64-hex blind-index key (must match binayah-properties)
- `ENCRYPTION_KEYS_OLD` — optional, comma-separated retired keys

Subscriptions appear in the existing Binayah Leads / Newsletter dashboard.
