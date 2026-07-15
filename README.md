# Sentinel Domain Watch 🛡️

Sentinel Domain Watch is a professional-grade brand protection scanner that discovers and analyzes typosquatting, character substitution, transposition, and homoglyph domain mutations targeting a given brand. The tool performs real-time parallel DNS lookups, Certificate Transparency (CT) log analysis, and WHOIS registration audits to evaluate the phishing risk of candidate domains.

**Safety Assurance:** This tool queries only public, legal metadata sources (DNS records, crt.sh, WHOIS servers). It **never** attempts to connect to, fetch contents from, or interact directly with the mutations, ensuring complete safety for security analysts.

---

## Technical Stack
- **Backend:** Python, FastAPI, python-whois, requests, pytest
- **Frontend:** React (Vite), pure CSS custom dark-themed security dashboard

---

## Setup and Running Instructions

### Prerequisites
- Python 3.10+
- Node.js 18+

### 1. Backend Setup
1. Open a terminal and navigate to the backend directory:
   ```bash
   cd domain-scanner
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   # Windows PowerShell
   .venv\Scripts\Activate.ps1
   # macOS/Linux
   source .venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```
4. Start the FastAPI server:
   ```bash
   # From the domain-scanner directory
   .venv\Scripts\uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
   ```
   The backend API documentation will be available at `http://127.0.0.1:8000/docs`.

### 2. Running Backend Tests
Ensure that your virtual environment is active, then run:
```bash
python -m pytest
```

### 3. Frontend Setup
1. Open a new terminal and navigate to the frontend directory:
   ```bash
   cd domain-scanner/frontend
   ```
2. Install node dependencies:
   ```bash
   npm install
   ```
3. Start the Vite React development server:
   ```bash
   npm run dev
   ```
   The application dashboard will be accessible at `http://localhost:5173`.

---

## Risk Scoring Methodology

All candidate domains start with a risk score of `0` and points are added for positive indicators. The maximum total score is capped at `100`.

| Signal / Condition | Risk Score Weight | Description |
| :--- | :---: | :--- |
| **Registered in last 30 days** | `+35` | `registered_date` is within 30 days of scan time |
| **Registered in last 90 days** (but not last 30) | `+20` | `registered_date` is between 31 and 90 days of scan time |
| **Registered over 1 year ago** | `-15` | Reduces risk. Older domains are likely defensive or unrelated registrations |
| **Registered date unknown** | `+0` | Skips signal, does not reward or penalize |
| **Suspicious prefix present** | `+25` | Domain label starts with: `login-`, `secure-`, `verify-`, `account-`, `support-`, `my-`, `id-` |
| **Homoglyph substitution used** | `+20` | Domain was generated using homoglyph replacements (e.g. `o -> 0`, `a -> @`) |
| **Character substitution/transposition** | `+15` | Generated via omission, duplication, adjacent-key, or transposition techniques |
| **TLD swap only** | `+5` | rest of the label is identical, only TLD swapped. Often lower risk defensive registrations |
| **Both DNS-live AND certificate confirmed** | `+15` | DNS resolves successfully and crt.sh CT log check finds a certificate |
| **Certificate check returned "unknown"** | `0` | crt.sh query failed/timed out. Confidence is flagged as `"reduced"` in the UI |

### Risk Level Mapping
- **`0 - 39`**: LOW
- **`40 - 69`**: MEDIUM
- **`70 - 100`**: HIGH

---

## Security Safeguards
1. **No Outbound HTTP to Targets:** The backend does not send HTTP requests to flagged domains. It only resolves them using standard socket DNS and queries third-party databases (crt.sh).
2. **Warn Before Access:** The frontend details view warns the user to avoid directly visiting flagged domains, preventing accidental downloads of malicious payloads or access to active phishing forms.

---

## Deployment

### Render Backend Deploy Steps
1. Create a new Web Service on [Render](https://render.com/).
2. Connect your Git repository.
3. Configure the service settings:
   - **Root Directory:** `backend`
   - **Runtime:** `Python`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Set the following **Environment Variables**:
   - `FRONTEND_URL`: The URL of your deployed Vercel frontend (e.g., `https://sentinel-domain-watch.vercel.app`).
   - `CRTSH_TIMEOUT_SECONDS`: `8` (can be tuned if Render's network conditions require longer/shorter timeout).
5. Deploy the service.

### Vercel Frontend Deploy Steps
1. Create a new Project on [Vercel](https://vercel.com/).
2. Connect your Git repository.
3. Configure the build settings:
   - **Root Directory:** `frontend`
   - **Framework Preset:** `Vite` (automatically detected)
   - **Build Command:** `npm run build`
   - **Output Directory:** `dist`
4. Set the following **Environment Variable**:
   - `VITE_API_URL`: The URL of your deployed Render backend (e.g., `https://sentinel-domain-watch-api.onrender.com`).
5. Deploy the project.

### Recommended Deployment Order
To ensure the CORS configurations and environment variables connect correctly, follow this two-step dependency order:
1. **Deploy the backend first:** Deploy to Render and copy the generated Render backend URL (e.g., `https://sentinel-domain-watch-api.onrender.com`).
2. **Deploy the frontend:** Deploy to Vercel, adding `VITE_API_URL` set to the copied Render URL. Copy the generated Vercel frontend URL.
3. **Link frontend to backend:** Go back to your Render dashboard for the backend service, add the `FRONTEND_URL` environment variable set to the Vercel frontend URL, and trigger a redeploy of the backend.

> [!NOTE]
> The crt.sh Certificate Transparency lookup is a third-party dependency outside of our control. It may occasionally experience latency, rate limits, or temporary outages in production, same as in local testing. When it times out, the tool reports "unknown" status with reduced confidence to prevent false negatives.
