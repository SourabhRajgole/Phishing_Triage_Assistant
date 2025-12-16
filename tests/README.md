# Phishing Email Triage Assistant (Python)

Parses `.eml` files, extracts headers/URLs/attachments, computes phishing indicators, assigns an explainable risk score, and generates reports.

## Install
pip install -r requirements.txt

## Run (console only)
python -m phish_triage --eml samples\sample.eml

## Run (reports)
python -m phish_triage --eml samples\sample.eml --out-md report.md --out-pdf report.pdf --out-json analysis.json
