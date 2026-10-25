# PhishLens

A responsive phishing-risk scanner built with FastAPI and plain JavaScript/CSS. It analyzes URL structure, DNS/HTTPS, page behavior, optional threat-feed results, and optional locally trained PyTorch and XGBoost URL classifiers. Scanning uses a direct connection to a resolved public IP, validates every redirect destination, limits page responses to 1 MB, and refuses local/private targets.

> **Important:** A scan is an estimate, not a security guarantee. Do not use this tool as the sole basis for deciding whether to trust a website. Configure and operate it only in an environment where outbound scanning is permitted.

## Run locally

Python 3.10+ is recommended. From this directory:

```powershell
.\run.ps1
```

The launcher creates a virtual environment and installs dependencies on its first run. Open http://127.0.0.1:8000. The API docs are at http://127.0.0.1:8000/docs. Optional: copy `.env.example` to `.env` and add provider keys before starting.

To run manually after installing dependencies:

```powershell
python -m uvicorn main:app --reload
```

## Deploy as a web application

PhishLens is a Python web application, not a static-only site. Its FastAPI server serves the homepage, `/tools`, `/about`, `/static/*`, and `/api/*` from the same origin. Deploy it to a host that runs Python ASGI applications or Docker, and configure the repository root as the application root.

For a Python application service, install dependencies from `requirements.txt` and use this start command:

```sh
uvicorn server:app --host 0.0.0.0 --port ${PORT:-8000}
```

The root `server.py` exports the ASGI application. The included `Dockerfile` is the portable option for hosts that support containers; it listens on the host-provided `PORT` and falls back to `8000` for local use. Do not deploy this project as a static-only site: that will not run FastAPI or its API endpoints and can produce a host-generated 404 page.

Set optional provider keys such as `GOOGLE_SAFE_BROWSING_API_KEY` and `VIRUSTOTAL_API_KEY` in the hosting provider's Environment Variables; `.env` is local-only and is not deployed. The QR camera feature requires HTTPS in production. If you change `static/qr-reader-entry.js`, rebuild and commit the generated `static/qr-reader.js` with `npm run build` before deploying.

## Configuration

Copy `.env.example` to `.env`. The app works without API keys.

* `GOOGLE_SAFE_BROWSING_API_KEY`: enables the Google Safe Browsing Lookup API.
* `VIRUSTOTAL_API_KEY`: enables VirusTotal URL report lookups. Existing reports are queried; this does not submit a new scan.
* `OPENPHISH_FEED_FILE`: optional local newline-separated list of exact URLs or domain names. The default feed file is `data/known_phishing_domains.txt`.
* `SCAN_RATE_LIMIT` and `SCAN_RATE_WINDOW_SECONDS`: per-client in-memory rate limit settings.

Threat-feed lookups and RDAP require outbound network access. Optional provider failures are indicated as unavailable in the result and do not prevent local checks. The rate limiter is process-local; use a shared gateway or distributed limiter for multi-worker deployments. Avoid exposing an untrusted scanning service publicly without stricter network egress controls and operational safeguards.

## Optional deep-learning URL classifier

The CNN classifies URL byte patterns; it does not understand every page design, execute JavaScript, or guarantee detection for every website. Its quality depends on the labeled examples it is trained with. No pretrained weights or sample labels are bundled, so without your trained artifact the app reports **Not trained** and continues with its heuristic/feed checks.

Install the optional CPU-capable PyTorch dependency:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-ml.txt
```

Prepare a CSV with `url,label` columns, where labels are `safe`/`phishing` (or `0`/`1`). Include both classes, use examples you are permitted to use, remove duplicate URLs, and prefer a large, representative, recent dataset. Training and validation are separated by host (including `www` variants), and the trainer keeps the checkpoint with the lowest host-held-out validation loss. This reduces URL leakage but does not replace evaluation on a separate, recent dataset of unseen domains.

Train the local byte-level CNN:

```powershell
.\.venv\Scripts\python.exe -m app.train_model path\to\labeled_urls.csv --output models\url_cnn.pt --epochs 10
```

The trainer prints host-separated validation accuracy, precision, recall, and F1 at a `0.5` classification threshold, then saves the best CPU model checkpoint. Set `PHISHLENS_MODEL_PATH` to use a different artifact and `ML_PHISHING_THRESHOLD` (default `0.8`, accepted range `0.5`–`1`) to tune the scanner's alert threshold. The scanner exposes model status, prediction, probability, and confidence in the scan response; only a prediction at or above the configured threshold contributes to the combined risk score. A model result is one signal, not a verdict guarantee. Model errors are reported in the scan details and logs; other checks remain available.

Install the ML requirements before starting the server so the optional classifier can load. The default launcher installs only the core dependencies.

To build a Docker image with PyTorch included (larger image), use `docker build --build-arg INSTALL_ML=true -t phishlens-ml .`; the default Docker image remains lightweight and uses the heuristic/feed checks.

## Optional XGBoost URL-feature classifier

The attached feature-extraction notebook's reproducible address-bar signals are included in PhishLens's XGBoost feature extractor: IP host, `@`, the notebook's 54-character URL-length threshold, path depth, embedded `//` redirection, an `https` token in the hostname, known URL shorteners, and hostname hyphens. PhishLens also adds punycode, suspicious-TLD, sensitive-keyword, query-count, digit-count, and percent-encoding features. Its existing scanner separately checks live DNS, registration age, redirects, certificates, and page behavior.

The notebook's remaining model inputs depend on WHOIS, the retired Alexa traffic service, or fetching each training website. Those values are not fabricated or included in this URL-only model. Its exported XGBoost model expects the notebook's different 16-feature schema, and neither that artifact nor the notebook's feature CSV was provided, so the reported 86.4% test accuracy is not a PhishLens measurement. PhishLens trains a compatible model from labeled `url,label` rows instead.

Install the optional requirements (includes XGBoost and PyTorch):

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-ml.txt
```

Train the model with a representative labeled URL CSV; validation hosts are held out from training:

```powershell
.\.venv\Scripts\python.exe -m app.xgb_model path\to\labeled_urls.csv --output models\url_xgboost.json
```

Training requires at least four distinct URL hosts and both classes represented in training and validation. The trainer reports accuracy, precision, recall, and F1 for its host-separated validation set. Set `PHISHLENS_XGBOOST_MODEL_PATH` to select an artifact and `XGBOOST_PHISHING_THRESHOLD` (default `0.8`, accepted range `0.5`–`1`) to tune the alert threshold. The artifact is stored in XGBoost's JSON format rather than Python pickle. If no artifact is installed, PhishLens continues with the existing heuristics, feeds, and other optional classifier. Model metrics are dataset-specific and do not guarantee future detection quality.

## API

`POST /api/scan`

```json
{ "url": "https://example.com" }
```

Returns `verdict`, `risk_score` (1–10), `max_score` (10), triggered `checks`, `all_checks`, domain/page details, threat-feed statuses, both model statuses/predictions/confidences, and a UTC scan timestamp. Scores above 3 are Suspicious; scores of 6 or more are Phishing. A positive trained-model result, a brand-impersonation URL combined with account-related terms, or a password form posting to a different registered domain raises the score to a high-risk level. Brand checks include Amazon, Apple, Facebook, Google, Microsoft, Netflix, PayPal, SBI, HDFC, Paytm, IRCTC, and Aadhaar. Invalid URLs and private/reserved destinations return an HTTP 400 response. Excess scans return HTTP 429.

`GET /api/health` returns a health status; `GET /api/samples` returns safe and suspicious-pattern sample inputs. Sample phishing-looking addresses use the reserved `.example` domain and are not real phishing sites.

## External security tools

Password Check, QR Tools, and UPI ID Check are implemented on the PhishLens tools page. Password strength checks stay in the browser; QR creation and decoding also run locally in the browser and never open decoded content; UPI ID checks validate format only and do not verify an account or owner. The existing browser bundle is generated from the pinned npm dependencies with `npm install` and `npm run build`.

## Tests

```powershell
python -m unittest discover -s tests -v
```

## Docker

```powershell
docker build -t phishlens .
docker run --rm -p 8000:8000 --env-file .env phishlens
```

## PhishLens tools

The `/tools` page includes native SSL certificate, public DNS, safe redirect-expansion, RDAP website-age, IP reputation, and full scam-website checks. These are available through `POST /api/tools/{tool}` with a JSON body such as `{"value":"example.com"}`. Tool names are `ssl`, `dns`, `expand`, `age`, `ip-reputation`, and `scam-check`. Scanning and redirect expansion validate public destinations and block private/reserved addresses. Website age depends on RDAP availability; IP reputation uses VirusTotal and requires `VIRUSTOTAL_API_KEY`. Password strength, QR generation/reading, and UPI ID format checks run on the tools page without opening external websites.

The `/about` page explains phishing and common types, including email phishing, spear phishing, whaling, smishing, vishing, clone phishing, QR phishing, and pharming, with basic safety guidance.

## Scanner behavior and limitations

The server normalizes HTTP(S) URLs, blocks local/private/reserved addresses, resolves and validates all target IPs, then connects directly to a validated IP while retaining the hostname for HTTPS SNI/certificate validation. Redirects are limited to five and each destination is validated again. HTML responses are size-limited; a site's page checks may be unavailable if the site blocks the scanner, times out, or serves non-HTML content. Domain age depends on the public RDAP service and is not available for every domain. Brand, keyword, and TLD matches are heuristic signals and can produce false positives. The optional browser screenshot is not included.
