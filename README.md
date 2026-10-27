# 🛡️ NetGuard-SOC: Wireless Threat, EvilTwin & Phishing Triage Dashboard

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://share.streamlit.io/)
![ISO 27001 Aligned](https://img.shields.io/badge/ISO%2FIEC%2027001%3A2022-Annex%20A%20Aligned-blue)
![CSMIC Certified](https://img.shields.io/badge/CSMIC%20Cert-CSMIC--AW--884LVR4P%20(100%25)-success)

**NetGuard-SOC** is a cloud-native, hardware-independent Security Operations Center (SOC) dashboard built with Python and Streamlit. It unifies **802.11 Wireless Intrusion Detection (EvilTwin, Deauth Floods, ESP32 Marauder Beacon Spam)**, **Phishing URL & RFC 5322 Email Header Forensics**, and **ISO/IEC 27001:2022 Incident Response Playbooks**.

## 👨‍💻 Developer & Certification Credentials
- **Developer:** Sahayaraj Nadar (Roll No: `19068`)
- **Certification:** CSMIC Cybersecurity Awareness Essentials (**Score: 100%**)
- **Certificate ID:** `CSMIC-AW-884LVR4P` (Issued: Oct 27, 2026)
- **Instructor:** Kam Ghaderi, CISSP, ISO/IEC 27001 Lead Auditor
- **Verification Link:** [https://portal.csmic.ca/training/verify](https://portal.csmic.ca/training/verify)

## 🚀 Core Modules
1. **Tab 1 — Wireless 802.11 & EvilTwin Rogue AP Detector:** Built-in synthetic 802.11 traffic generator (*Normal Office*, *EvilTwin Attack*, *ESP32 Marauder Deauth & Beacon Spam*) + CSV/JSON uploader, interactive Plotly Deauth burst timeline, and RSSI vs. Channel rogue highlighter.
2. **Tab 2 — Phishing, URL & Email Header Forensics:** Lexical Shannon entropy calculator, IDN Punycode (`xn--`) homograph detection, brand typosquatting checks, and RFC 5322 `SPF`/`DKIM`/`DMARC` + `Received` hop parser.
3. **Tab 3 — ISO/IEC 27001:2022 Triage & Playbook:** Maps active threats to Annex A controls (`A.8.20`, `A.8.23`, `A.6.3`, `A.5.24`) and exports one-click **Markdown (`.md`)** and **JSON (`.json`)** incident reports.
4. **Tab 4 — CSMIC Awareness Simulator:** 5-question interactive technical assessment with instant explanations and architecture showcase.

## 🛠️ Quick Start & Deployment
```bash
pip install -r requirements.txt
streamlit run app.py
