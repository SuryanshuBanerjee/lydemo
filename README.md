# LeBlanc — Demo Pipeline

Automated Prompt Enrichment and Iterative Repair for Secure LLM-Generated Code.

## Quick Start (5 minutes)

### 1. Install Python dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Install Semgrep and Bandit (if not already)

```bash
pip install semgrep bandit
```

Verify they work:
```bash
semgrep --version
bandit --version
```

### 3. Set your API keys

**Linux / Mac:**
```bash
export GEMINI_API_KEY="your-gemini-key-here"
export GROQ_API_KEY="your-groq-key-here"
```

**Windows (PowerShell):**
```powershell
$env:GEMINI_API_KEY="your-gemini-key-here"
$env:GROQ_API_KEY="your-groq-key-here"
```

**Where to get keys:**
- Gemini: https://aistudio.google.com/apikey (free tier available)
- Groq: https://console.groq.com/keys (free tier available)

### 4. Start the backend

```bash
cd backend
python app.py
```

You should see:
```
  LeBlanc Pipeline — Demo Server
  http://localhost:5000
```

### 5. Open the frontend

Just open `frontend/index.html` in your browser. That's it. No npm, no build step.

If you get CORS issues, use a simple server instead:
```bash
cd frontend
python -m http.server 3000
```
Then open http://localhost:3000

---

## How to Demo

1. Click one of the demo prompt chips (e.g. "Write a Flask endpoint for user login...")
2. Click **Run Pipeline**
3. Wait 30-60 seconds — it's running 6 LLM calls + scans
4. Results appear side by side: Gemini vs Groq
5. Click the three tabs (Plain / Enriched / Enriched + Repair) to show the difference
6. Point out:
   - **Plain tab**: vulnerabilities found, no protection
   - **Enriched tab**: Engine A's warnings visible, fewer vulns
   - **Enriched + Repair tab**: Engine C's repair timeline, vulns fixed iteratively

---

## Project Structure

```
leblanc-demo/
├── backend/
│   ├── app.py              ← Flask server (routes + orchestration)
│   ├── engine_a.py         ← Prompt enrichment (JSON keyword lookup)
│   ├── engine_b.py         ← Static analysis (Semgrep + Bandit)
│   ├── engine_c.py         ← Iterative repair loop
│   ├── llm_client.py       ← Gemini + Groq API wrappers
│   ├── database.py         ← SQLite logging
│   ├── cwe_mappings.json   ← Engine A's keyword→CWE→warning rules
│   ├── prompts.json        ← 5 demo prompts
│   └── requirements.txt
├── frontend/
│   └── index.html          ← React dashboard (single file, CDN)
└── README.md
```

---

## What Each Engine Does

**Engine A** (`engine_a.py`): Scans prompt for keywords like "mysql", "login", "upload". Looks up CWE warnings from `cwe_mappings.json`. Appends warnings to the prompt. No AI involved — pure string matching.

**Engine B** (`engine_b.py`): Saves LLM-generated code to a temp file. Runs `semgrep --config=auto --json` and `bandit -f json` on it. Parses findings into `{cwe, severity, line, message}` structs. Filters to medium+ severity only.

**Engine C** (`engine_c.py`): Takes vulnerability findings from Engine B. Builds a structured repair prompt. Sends it back to the same LLM. Re-scans the patched code. Loops up to 3 times (configurable).

---

## API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/prompts` | GET | List demo prompts |
| `/api/run` | POST | Run pipeline for one prompt + one model + one mode |
| `/api/compare` | POST | Run all modes on both models (main demo endpoint) |
| `/api/history` | GET | Retrieve all saved runs from database |

---

## Troubleshooting

**"semgrep: command not found"** — Run `pip install semgrep` and ensure your Python scripts bin is in PATH.

**"GEMINI_API_KEY not set"** — You forgot to export the environment variable. Run the export command again (it resets when you close the terminal).

**Scan finds 0 vulnerabilities** — This can happen. Some prompts + models produce clean code. Try the SQL injection prompt (P001) — it almost always triggers findings.

**"rate limit" errors from Groq** — Groq's free tier has per-minute limits. Wait 60 seconds and try again, or run one model at a time using `/api/run`.
