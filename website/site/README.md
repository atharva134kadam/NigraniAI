# NigraniAI website (static)

The public NigraniAI website: plain HTML, CSS and JavaScript. No build step, nothing to install.

| File | What it is |
|---|---|
| `index.html` | Home: hero with a live product illustration, the problem, all 11 tools (filterable), three spotlights (explainable anomalies, tamper-evident evidence, layered PII detection), how it works, the DPDP Act explained (roles, duties → tools, breach clocks, penalties, countdown to 13 May 2027, FAQ), pricing (setup · hosted · self-hosted, plan tiers without prices), demo booking |
| `company.html` | Company: mission, vision, story, principles, team (placeholders), contact (placeholders) |
| `css/style.css` | Brand system and every section, responsive down to phones, respects reduced motion |
| `js/main.js` | Navigation, scroll reveals, tool filter, hero animation, countdown, cookie banner, booking form |
| `js/config.js` | Supabase URL and **anon** key for demo bookings |
| `assets/` | Logo, round eye mark, favicon |

## Run locally

```bash
cd site
python3 -m http.server 3011
# open http://localhost:3011
```

## Demo bookings (Supabase)

The form posts straight to the Supabase REST API, table `demo_bookings` (schema in `../supabase/schema.sql`).
Row Level Security allows the anon key to **insert** a booking and nothing else, so the key is safe in
the browser. A hidden field stops simple bots. Bookings appear in Supabase → Table editor → `demo_bookings`.

## Before going live

Fill in the placeholders on `company.html` (team names and roles, email, office address), shown in
amber: search for `class="ph"`.

## Deploy

Any static host works (GitHub Pages, Netlify, Cloudflare Pages, S3, or the NigraniAI server's nginx):
upload the contents of this folder.
