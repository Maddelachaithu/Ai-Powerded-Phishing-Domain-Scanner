# Sentinel Domain Watch

A brand-protection tool that detects likely phishing / typosquat domains
targeting a given brand — modeled on real threat-intelligence products like
CloudSEK's XVigil, built entirely on free, public, no-auth-required data
sources.

Live demo: <add your Vercel URL here>
Backend API docs: <add your Render URL here>/docs


## What it does

Give it a domain (e.g. examplebank.com) and it will:

* Generate ~100+ realistic typosquat variants using techniques real attackers
use — character omission, duplication, adjacent-keyboard substitution,
transposition, homoglyphs (o→0, i→1, etc.), hyphenation, TLD swaps,
and suspicious prefixes (login-, secure-, verify-)
* Check which variants are actually registered and live, using DNS
resolution and Certificate Transparency logs (crt.sh) — no scanning or
visiting of the flagged domains themselves
* Pull registration metadata (date, registrar) via WHOIS for flagged domains
* Score each flagged domain 0-100 using a transparent, auditable rule set,
and label it LOW / MEDIUM / HIGH risk
* Display everything in a live dashboard with sortable, filterable results
and a full breakdown of why each domain was flagged


## Screenshots

*(add screenshots or a short screen recording here — the search flow, the
results dashboard, and an expanded risk-reasons panel are the three most
worth showing)*


## Scoring methodology

Every flagged domain starts at 0 points. Points are added per signal
detected, capped at 100:

| Signal | Points |
| :--- | :---: |
| Registered in last 30 days | `+35` |
| Registered in last 90 days (not last 30) | `+20` |
| Registered over 1 year ago | `-15` |
| Suspicious prefix present (login-, secure-, etc.) | `+25` |
| Homoglyph substitution used | `+20` |
| Character-level substitution/transposition | `+15` |
| TLD swap only, rest of name identical | `+5` |
| DNS-live and certificate confirmed | `+15` |

0–39 = LOW, 40–69 = MEDIUM, 70–100 = HIGH.

If the certificate check fails (e.g. crt.sh is temporarily unavailable),
that domain is marked with `confidence: reduced` rather than silently
scored as safe — the dashboard surfaces this separately so results aren't
mistaken for complete data.


## Tech stack

* **Backend:** Python, FastAPI, python-whois, thread-pooled DNS + crt.sh
lookups with retry/backoff
* **Frontend:** React (Vite), dark-themed dashboard UI
* **Data sources:** DNS resolution, Certificate Transparency logs (crt.sh),
WHOIS — all free and public, no API keys required
* **Testing:** pytest, 25 unit tests covering the generator, scoring engine,
and checker (with mocked network calls)


## Project structure

```
domain-scanner/
├── backend/
│   ├── main.py           # FastAPI app, /api/scan endpoint
│   ├── generator.py      # typosquat variant generation
│   ├── checker.py        # DNS + crt.sh + whois verification
│   ├── scoring.py        # risk scoring engine
│   ├── requirements.txt
│   └── tests/
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   └── components/
│   └── package.json
├── render.yaml
├── vercel.json
└── README.md
```


## Running locally

### Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

API available at `http://localhost:8000`, interactive docs at
`http://localhost:8000/docs`.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Dashboard available at `http://localhost:5173`.

### Tests

```bash
cd backend
pytest -v
```


## Deployment

Backend is deployed on Render, frontend on Vercel.

1. Deploy the backend first (Render, root directory `backend/`), leave
`FRONTEND_URL` unset initially
2. Deploy the frontend (Vercel, root directory `frontend/`), set
`VITE_API_URL` to the Render backend's URL
3. Return to Render and set `FRONTEND_URL` to the resulting Vercel URL,
which triggers a redeploy with correct CORS config

Environment variables:

| Variable | Where | Purpose |
| :--- | :--- | :--- |
| `FRONTEND_URL` | Render (backend) | Allowed CORS origin for the live frontend |
| `CRTSH_TIMEOUT_SECONDS` | Render (backend) | Timeout for Certificate Transparency lookups (default: 8) |
| `VITE_API_URL` | Vercel (frontend) | Backend API base URL |

*Note: Render's free tier spins down after inactivity — the first request
after idle time can take 30–60 seconds.*


## Design principles

* **Never interacts with flagged domains.** All checks are metadata-only
(DNS, certificate logs, WHOIS). The tool never visits, fetches content
from, or renders a flagged domain as a clickable link without a warning.
* **Auditable scoring.** Every risk score comes with a plain-language
breakdown of exactly which signals fired and how many points each
contributed — no black-box scoring.
* **Graceful degradation.** Third-party data sources (crt.sh, WHOIS) are
outside this project's control and can be slow or temporarily unavailable.
The system distinguishes "confirmed clean" from "couldn't verify" rather
than defaulting to either extreme.


## Known limitations

* `crt.sh` availability can be inconsistent; results marked `confidence: reduced` reflect this rather than being treated as false negatives
* WHOIS data format varies significantly by registrar and isn't always
parseable — registration date is treated as optional evidence, not a
required field
* Currently checks a fixed set of typosquat generation techniques; doesn't
yet cover combinatorial variants (e.g. homoglyph + hyphenation together)


## Roadmap

- [ ] Combinatorial variant generation (stacking multiple techniques)
- [ ] Scheduled re-scans with historical trend tracking
- [ ] Export results as CSV/PDF report
- [ ] Slack/email alerting for newly-flagged high-risk domains


## Why this project

Built as a hands-on exploration of brand/domain threat monitoring, modeled
on how tools like CloudSEK's XVigil approach typosquat and phishing domain
detection — using only public, legal data sources throughout.
