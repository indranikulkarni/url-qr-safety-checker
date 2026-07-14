# URL / QR Code Safety Checker

A lightweight security tool that analyzes a URL (typed in or extracted from
a QR code) and flags it as **LIKELY SAFE**, **SUSPICIOUS**, or
**LIKELY MALICIOUS** using a mix of rule-based heuristics and an optional
live threat-database lookup.

## Features

- **Typosquatting detection** — flags domains that are suspiciously close
  (edit distance) to popular sites like `google.com`, `paypal.com`, etc.
- **URL shortener detection** — flags `bit.ly`, `tinyurl.com` and similar,
  since the real destination is hidden.
- **Suspicious TLD detection** — flags high-abuse top-level domains
  (`.xyz`, `.tk`, `.top`, etc.).
- **Suspicious character patterns** — flags `@` symbols, raw IP addresses,
  punycode, excessive hyphens, URL-encoded obfuscation.
- **HTTPS check** — flags non-encrypted links.
- **QR code decoding** — upload a QR code image and it extracts + analyzes
  the embedded URL automatically.
- **Optional Google Safe Browsing API integration** — cross-check against
  Google's live database of malware/phishing sites (free API key required;
  app works fine without one, just skips this check).

## Project structure

```
url_checker/
├── app.py            # Streamlit UI - run this
├── heuristics.py      # Rule-based URL analysis (no API key needed)
├── safe_browsing.py   # Optional Google Safe Browsing API wrapper
├── qr_reader.py        # QR code image decoder
└── requirements.txt
```

## Setup

```bash
pip install -r requirements.txt
streamlit run app.py
```

The app opens in your browser at `http://localhost:8501`.

## (Optional) Enable live threat-database checks

1. Get a free API key: https://developers.google.com/safe-browsing/v4/get-started
2. Paste it into the sidebar field in the app.

Without a key, the app still works — it just relies on the heuristic
checks only.

## How the risk score works

Each heuristic check adds weighted points if triggered:

| Check                  | Weight |
|-------------------------|--------|
| Typosquatting            | 3      |
| Suspicious TLD            | 2      |
| URL shortener             | 1      |
| No HTTPS                  | 1      |
| Excess subdomains          | 1      |
| Suspicious characters (each) | 1  |

- **Score 0** → Likely Safe
- **Score 1–2** → Suspicious
- **Score 3+** → Likely Malicious

## Possible extensions (good talking points in interviews)

- Add a browser extension front-end instead of Streamlit
- Log all checked URLs to a local SQLite DB for a "history" view
- Add WHOIS lookup (domain age — brand-new domains are higher risk)
- Add screenshot preview of the destination page before visiting
- Deploy on Streamlit Community Cloud for a live demo link
