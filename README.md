# 🛡️ SecureLog Analyzer

A Python + Streamlit dashboard for analyzing authentication logs. Upload a CSV, view login statistics, detect repeated failed login patterns, and download a report.

## Features
- CSV upload and required-column validation
- Successful and failed login summaries
- Adjustable failed-attempt threshold
- Repeated-failure detection by source IP and username
- Charts, alert table, and downloadable report
- Fictional sample CSV for demonstration

## Run locally
```bash
python -m pip install -r requirements.txt
streamlit run app.py
```

## CSV format
Required columns: `timestamp, username, source_ip, event`.
Supported events: `FAILED_LOGIN`, `SUCCESS_LOGIN`.

## Deploy on Streamlit Community Cloud
1. Sign in at https://share.streamlit.io/ with GitHub.
2. Choose **Create app**.
3. Select repository `ap566/SecureLog-Analyzer`, branch `main`, main file `app.py`.
4. Click **Deploy** and wait for the build.
5. Copy the generated public URL.

## Architecture
CSV source → Upload and validation → Event processing → Detection rules → Risk alerts → Dashboard and report.

## Limitations and safe use
This is a batch CSV analyzer, not a live network monitor or production SIEM. It does not block IP addresses or prove compromise. Threshold alerts require human investigation. Use only logs from systems you own or are authorized to monitor. Remove passwords, tokens, personal information, and confidential data before uploading.
