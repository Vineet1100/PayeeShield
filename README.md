# Biometric card & fraud analytics

A Streamlit app that simulates a payment card that only works for its owner, plus the bank-side fraud detection behind it.

I wanted to see how a few ideas from card security fit together in one place: biometric cards, dynamic CVVs, step-up authentication and transaction monitoring. So I built all three parties (card, merchants, bank) into a single app you can click through.

> **Prototype for demonstration only.** This is not a real card, bank or payment service, no real money moves, and it must not be used to process real payments or store real card data. Don't enter a real card number, password or personal details into the demo.

**Live demo: https://biometric-card-lab.onrender.com**

It runs on the free plan, so if nobody has visited for 15 minutes the first load takes about a minute while the server wakes up.

The demo is a Flask app (`web/`) with a page for each mission (pay in store, pay online, attack the card, fraud AI), plus a home page that tracks your progress, a bank server page with the log and alerts, and a how-it-works page. Every rule runs in Python on the server: the fingerprint unlock window, the TOTP codes, the approvals, the attacks, the fraud monitor and the scikit-learn model. Each visitor gets their own card and bank, kept for 2 hours, with payments stored in their own in-memory SQLite ledger. The bank server page runs the analytics SQL from `queries/` on that ledger (approval rate by channel, blocked attempts by reason, volume by hour). The page itself only draws the card, runs the hold-to-scan animation and asks the server what happened. On a Mac it asks for your real fingerprint through Touch ID (using a passkey) and sends purchase approvals as a notification on your laptop. On devices without Touch ID the sensor is simulated.

## What it does

**In store.** The card's chip stays locked until a fingerprint matches, then unlocks for 15 seconds. Tapping outside that window gets declined. On a Mac it uses the real Touch ID sensor; anywhere else the scan is simulated.

**Online.** The CVV on the card's e-ink screen is a TOTP code (RFC 6238) that changes every 2 minutes. The card and bank share a secret and each compute the code from the current time, so stolen card details stop working once the window moves on. If the CVV is valid, the bank still asks the cardholder to approve the purchase (a macOS alert, confirmed with Touch ID). The bank also refuses reused codes and blocks online payments after 3 wrong CVVs.

**Fraud monitoring.** Every attempt goes into a log, and after each one the bank looks for patterns:

- 3+ blocked attempts in the same channel within 5 minutes (pandas `groupby` + time-based `rolling`)
- an expired CVV being used, which suggests leaked card data
- a purchase the cardholder denied
- amounts far outside normal spending, using a robust z-score (median/MAD with NumPy)
- unusual combinations of amount, time of day and channel, using a scikit-learn Local Outlier Factor model trained on spending history

New alerts show up in the app and as a macOS notification. There's also a Plotly chart of each purchase against the spending history.

On the model: I started with Isolation Forest, but on five out-of-pattern test purchases it caught 2 and LOF caught all 5. The history has no night-time purchases, and tree splits only cover the range seen in training, so the forest couldn't tell that 3 AM was unusual.

## Running it

Needs Python 3.10+.

```bash
git clone https://github.com/Vineet1100/biometric-card-fraud-analytics.git
cd biometric-card-fraud-analytics
pip install -r requirements.txt
streamlit run app.py
```

Then open http://localhost:8501 in your browser (Streamlit usually opens it for you).

The app is split into pages in the sidebar: Overview (live stats and a checklist of things to try), Pay in store, Pay online, Fraud alerts (alerts and the spending chart), Transaction log (filters and CSV download) and How it works. The sidebar menu shows how many alerts and payments there are, and the settings stay underneath it on every page.

Some things to try:

- tap the card without scanning, then scan and tap again
- pay online with "Use my card" and approve the request
- pay with "Use leaked data" to trigger the stolen-data alert
- tap the locked card three times in a row
- set "Purchase time" to 3 AM in the sidebar and make a normal purchase

## Bank API and MCP server

The app keeps everything in one process. `bank/` splits the bank out into a real HTTP service, the way it would run in production, and `mcp_server/` lets AI agents use its fraud tools.

**Bank API** (FastAPI). Terminals, checkouts and the cardholder's device each sign their requests with their own key, and each can only call the endpoints its job needs. In-store payments need a cryptogram that the card only produces after a fingerprint match. Online payments need the current CVV plus the cardholder's approval. Merchants only get generic response codes; the detailed reasons go to a tokenized audit log.

```bash
pip install -r requirements-bank.txt
python -m bank.keys > .env          # fresh random keys, never committed
set -a; source .env; set +a
python -m bank                      # listens on 127.0.0.1:8080
```

**Ledger and analytics SQL.** The bank keeps every payment attempt and fraud alert in a SQLite database (`ledger.db`, owner-only, set with `BANK_LEDGER_DB`). Amounts are stored as integer cents and every query is parameterized. `queries/` has the analytics as plain SQL you can run against it:

```bash
sqlite3 -header -column ledger.db < queries/approval_rate_by_channel.sql
sqlite3 -header -column ledger.db < queries/blocked_by_reason.sql
sqlite3 -header -column ledger.db < queries/hourly_volume.sql
```

The same reports are served as JSON from `GET /v1/reports/{name}` (for example `/v1/reports/hourly_volume`) to clients with the `stats:read` scope. Only the names of files in `queries/` are accepted, so a caller can't send SQL.

**MCP server.** Gives an AI agent four read-only tools: `score_transaction`, `list_fraud_alerts`, `get_payment_stats` and `get_ledger_report` (the reports above). It can't move money or see card numbers, and its credentials can't reach the payment endpoints even if the server is compromised. Add it to an MCP client (for example Claude Desktop) like this:

```json
{
  "mcpServers": {
    "card-fraud": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "env": {
        "PYTHONPATH": "/path/to/biometric-card-fraud-analytics",
        "MCP_BANK_URL": "http://127.0.0.1:8080",
        "MCP_CLIENT_ID": "fraud-agent",
        "MCP_CLIENT_SECRET": "<from your .env>"
      }
    }
  }
}
```

## Security

[SYSTEM_DESIGN.md](SYSTEM_DESIGN.md) has the architecture, the payment flows, a STRIDE threat model and the control that stops each threat. Each control has a test that tries the attack:

```bash
pip install -r requirements-bank.txt pytest
pytest
```

On every push, GitHub Actions runs the tests, black and ruff (formatting and lint, settings in `pyproject.toml`), Bandit (insecure code), pip-audit (vulnerable dependencies) and gitleaks (leaked secrets in the full history). To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Hosting the demo

Run the Flask version on your computer. In Terminal:

```bash
cd ~/biometric-card-fraud-analytics          # go into the project folder first
python3 -m pip install -r requirements-web.txt   # installs Flask and the other packages (first time only)
python3 -m web                               # starts the app
```

When it prints `Biometric card lab running at http://127.0.0.1:8000`, open http://127.0.0.1:8000 in your browser. Press Ctrl+C in Terminal to stop it.

If something goes wrong:

| What you see | Why | Fix |
| --- | --- | --- |
| `No module named flask` (or `pyotp`, `sklearn`, `numpy`) | The packages aren't installed for the Python you're using | Run the `python3 -m pip install -r requirements-web.txt` line again, then `python3 -m web` |
| `No module named web` | Terminal isn't in the project folder | Run `cd ~/biometric-card-fraud-analytics` first |
| "Access to 127.0.0.1 was denied" (HTTP 403) | You opened port 5000, which macOS uses for AirPlay Receiver | Open http://127.0.0.1:8000 instead |
| `Address already in use` | The app (or something else) is already running on port 8000 | Stop the other one with Ctrl+C, or run `PORT=8001 python3 -m web` and open port 8001 |

It is hosted on [Render](https://render.com) from `render.yaml`, at https://biometric-card-lab.onrender.com. To set it up again from scratch:

1. Sign in to Render, click **New**, then **Blueprint**.
2. Paste `https://github.com/Vineet1100/biometric-card-fraud-analytics` under **Public Git Repository** and click **Continue**, then **Deploy Blueprint**. Render reads `render.yaml` and sets everything up, including a random `SECRET_KEY`.

To publish new changes after pushing to GitHub, open the service in Render and click **Manual Deploy**, then **Deploy latest commit**. To have every push deploy by itself instead, connect your GitHub account in Render (**Account settings**, then **Git providers**).

On the free plan the app goes to sleep after 15 minutes without visitors, so the first visit after that takes about a minute to load. It must run as one worker process (as `render.yaml` does), because each visitor's card and bank live in that process's memory.

## Project structure

```
app.py, style.css        Streamlit app (card, merchants, bank in one process)
web/                     Flask demo: pages, JSON API and per-visitor card and bank
render.yaml              Render hosting setup
bank/                    bank API: signing, authorization, fraud monitor, SQLite ledger, audit log
queries/                 analytics SQL over the ledger
mcp_server/              read-only MCP server for AI agents
tests/                   attack and payment-flow tests
SYSTEM_DESIGN.md         architecture and threat model
```

## Disclaimer

This is a student prototype built to demonstrate card-security and fraud-detection ideas. It is not a real card, bank or payment service, and it is not affiliated with any bank or card network; "NOVA BANK", the cardholder and the card number are fictional (4111 1111 1111 1111 is a standard test number). It must not be used to process real payments, store real card data or collect anyone's personal information. The software is provided "as is", without warranty of any kind, as set out in the [MIT License](LICENSE). If you build on it, you are responsible for how you use it.

The live demo is hardened for a public demo: every page shows a prototype banner and is hidden from search engines, real card numbers are refused, each visitor's data stays in memory for 2 hours and is never written to disk, requests are rate limited, and the server sends a strict Content Security Policy and other security headers.

## Limitations

It's a prototype, so a few things are simplified:

- keys come from environment variables; a real bank keeps them in an HSM or KMS
- in-store cryptograms use one HMAC key instead of EMV keys derived per card
- the device signs approvals with a shared key instead of a verified passkey signature
- the spending history is generated with NumPy, not real transaction data
- in the Flask demo, the browser reports whether Touch ID matched; a real bank would verify the passkey signature on the server
- in the Streamlit app, decline reasons are detailed on purpose; the bank API only gives merchants generic codes

SYSTEM_DESIGN.md lists everything a production deployment would add.

## License

MIT
