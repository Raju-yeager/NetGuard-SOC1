import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import math
import re
import json
from datetime import datetime, timedelta
from urllib.parse import urlparse

# ==========================================
# PAGE CONFIGURATION & DARK SOC STYLING
# ==========================================
st.set_page_config(
    page_title="NetGuard-SOC | Wireless & Phishing Triage Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    /* Main Background & Text */
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    /* Metric Cards */
    .soc-card {
        background: linear-gradient(145deg, #111827, #1e293b);
        border: 1px solid #334155;
        border-left: 4px solid #38bdf8;
        border-radius: 10px;
        padding: 18px;
        margin-bottom: 14px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
    }
    .soc-card-critical {
        border-left: 4px solid #ef4444 !important;
    }
    .soc-card-high {
        border-left: 4px solid #f97316 !important;
    }
    .soc-card-low {
        border-left: 4px solid #22c55e !important;
    }
    .metric-title {
        font-size: 0.82rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #94a3b8;
        margin-bottom: 4px;
    }
    .metric-value {
        font-size: 1.75rem;
        font-weight: 700;
        color: #f8fafc;
    }
    /* Status Badges */
    .badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 999px;
        font-size: 0.75rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .badge-critical { background-color: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
    .badge-high { background-color: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }
    .badge-medium { background-color: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid #eab308; }
    .badge-low { background-color: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid #22c55e; }
    /* Sidebar Certification Card */
    .cert-box {
        background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
        border: 1px solid #4f46e5;
        border-radius: 12px;
        padding: 16px;
        margin-top: 10px;
        box-shadow: 0 0 15px rgba(79, 70, 229, 0.25);
    }
    .cert-header {
        color: #818cf8;
        font-weight: 700;
        font-size: 0.95rem;
        margin-bottom: 8px;
        display: flex;
        align-items: center;
        gap: 6px;
    }
    .cert-detail {
        font-size: 0.82rem;
        color: #cbd5e1;
        line-height: 1.5;
    }
    .verify-btn {
        display: block;
        text-align: center;
        background-color: #4f46e5;
        color: #ffffff !important;
        text-decoration: none;
        padding: 8px 12px;
        border-radius: 6px;
        font-size: 0.8rem;
        font-weight: 600;
        margin-top: 12px;
    }
    .verify-btn:hover {
        background-color: #4338ca;
    }
</style>
""", unsafe_allow_html=True)

# ==========================================
# SESSION STATE INITIALIZATION
# ==========================================
if "wireless_df" not in st.session_state:
    st.session_state.wireless_df = pd.DataFrame()
if "wireless_alerts" not in st.session_state:
    st.session_state.wireless_alerts = []
if "phishing_alerts" not in st.session_state:
    st.session_state.phishing_alerts = []
if "last_url_result" not in st.session_state:
    st.session_state.last_url_result = None
if "last_email_result" not in st.session_state:
    st.session_state.last_email_result = None
if "quiz_submitted" not in st.session_state:
    st.session_state.quiz_submitted = False

# ==========================================
# HELPER FUNCTIONS & DETECTION ENGINES
# ==========================================
def generate_wireless_capture(scenario: str) -> pd.DataFrame:
    """Generates synthetic 802.11 packet capture logs for normal, EvilTwin, or Marauder attacks."""
    np.random.seed(42 if scenario == "Normal Office Network" else (99 if "EvilTwin" in scenario else 2026))
    base_time = datetime.now() - timedelta(minutes=15)
    rows = []

    legit_aps = [
        {"ssid": "CorpNet-5G", "bssid": "00:1A:2B:3C:4D:01", "channel": 36, "enc": "WPA3-Enterprise", "base_rssi": -58},
        {"ssid": "CorpNet-2.4G", "bssid": "00:1A:2B:3C:4D:02", "channel": 6, "enc": "WPA2-Enterprise", "base_rssi": -54},
        {"ssid": "Corp-Guest", "bssid": "00:1A:2B:3C:4D:03", "channel": 1, "enc": "WPA2-PSK", "base_rssi": -63},
        {"ssid": "SecOps-IoT", "bssid": "00:1A:2B:3C:4D:04", "channel": 11, "enc": "WPA2-PSK", "base_rssi": -68},
    ]

    # Generate baseline traffic across 60 intervals (15 seconds apart)
    for i in range(60):
        ts = base_time + timedelta(seconds=i * 15)
        for ap in legit_aps:
            rows.append({
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "ssid": ap["ssid"],
                "bssid": ap["bssid"],
                "channel": ap["channel"],
                "rssi": int(ap["base_rssi"] + np.random.randint(-4, 5)),
                "encryption": ap["enc"],
                "frame_type": np.random.choice(["Beacon", "Data", "Probe-Resp"], p=[0.6, 0.3, 0.1]),
                "deauth_count": int(np.random.choice([0, 1], p=[0.96, 0.04]))
            })

    if scenario == "EvilTwin Attack in Progress":
        for i in range(20, 55):
            ts = base_time + timedelta(seconds=i * 15)
            # Rogue AP cloning CorpNet-5G with Open / WPA2 downgrade and high RSSI
            rows.append({
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "ssid": "CorpNet-5G",
                "bssid": "DE:AD:BE:EF:00:99",
                "channel": 6,
                "rssi": int(-32 + np.random.randint(-3, 3)),
                "encryption": "Open",
                "frame_type": "Beacon",
                "deauth_count": 0
            })
            # Targeted Deauth against legitimate CorpNet-5G BSSID
            rows.append({
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "ssid": "CorpNet-5G",
                "bssid": "00:1A:2B:3C:4D:01",
                "channel": 36,
                "rssi": int(-42 + np.random.randint(-3, 3)),
                "encryption": "WPA3-Enterprise",
                "frame_type": "Deauth",
                "deauth_count": int(np.random.randint(35, 95))
            })

    elif scenario == "ESP32 Marauder Deauth Flood & Beacon Spam":
        fake_ssids = [
            "Free_Airport_WiFi", "Starbucks_Fast_5G", "FBI_Surveillance_Van",
            "CorpNet-5G-Update", "Hotel_Lounge_Free", "Tesla_Guest_WiFi",
            "DropBox_Sync_AP", "Admin_Setup_Portal", "CISCO_Rescue_AP", "Pwned_By_Marauder"
        ]
        for i in range(15, 58):
            ts = base_time + timedelta(seconds=i * 15)
            # High-rate Deauth flood across channels
            rows.append({
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "ssid": "CorpNet-2.4G",
                "bssid": "00:1A:2B:3C:4D:02",
                "channel": 6,
                "rssi": int(-38 + np.random.randint(-4, 4)),
                "encryption": "WPA2-Enterprise",
                "frame_type": "Deauth",
                "deauth_count": int(np.random.randint(80, 210))
            })
            # Beacon spam from sequential Espressif/random MACs with same OUI prefix
            for idx in range(3):
                chosen_ssid = fake_ssids[(i + idx) % len(fake_ssids)]
                rows.append({
                    "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                    "ssid": chosen_ssid,
                    "bssid": f"A4:CF:12:99:00:{(i + idx) % 89 + 10:02d}",
                    "channel": 11,
                    "rssi": int(-36 + np.random.randint(-5, 5)),
                    "encryption": "Open",
                    "frame_type": "Beacon",
                    "deauth_count": 0
                })

    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df.sort_values("timestamp").reset_index(drop=True)


def run_wireless_heuristics(df: pd.DataFrame):
    """Analyzes 802.11 capture dataframe for EvilTwin, Deauth Floods, and Beacon Spam."""
    alerts = []
    rogue_bssids = set()

    if df.empty:
        return alerts, rogue_bssids

    # 1. EvilTwin / Rogue AP Detection (Same SSID, multiple BSSIDs, encryption mismatch or abnormally strong RSSI)
    ssid_groups = df.groupby("ssid").agg(
        bssid_count=("bssid", "nunique"),
        bssids=("bssid", lambda x: list(set(x))),
        encryptions=("encryption", lambda x: list(set(x))),
        max_rssi=("rssi", "max"),
        min_rssi=("rssi", "min")
    ).reset_index()

    for _, row in ssid_groups.iterrows():
        if row["bssid_count"] > 1:
            enc_list = row["encryptions"]
            rssi_spread = row["max_rssi"] - row["min_rssi"]
            if len(enc_list) > 1 or rssi_spread >= 20:
                # Identify anomalous BSSID (Open encryption or highest RSSI)
                sub = df[df["ssid"] == row["ssid"]]
                suspect_rows = sub[(sub["encryption"] == "Open") | (sub["rssi"] > -40)]
                suspect_bssids = list(suspect_rows["bssid"].unique())
                for b in suspect_bssids:
                    rogue_bssids.add(b)
                alerts.append({
                    "timestamp": str(df["timestamp"].max()),
                    "category": "EvilTwin / Rogue AP",
                    "severity": "Critical",
                    "ssid": row["ssid"],
                    "ioc": ", ".join(suspect_bssids) if suspect_bssids else ", ".join(row["bssids"]),
                    "evidence": f"SSID '{row['ssid']}' seen on {row['bssid_count']} BSSIDs with encryption mismatch {enc_list} and max RSSI {row['max_rssi']} dBm.",
                    "iso_control": "ISO/IEC 27001:2022 Annex A.8.20 (Networks Security)"
                })

    # 2. 802.11 Deauthentication Flood Detection
    deauth_df = df[(df["frame_type"].str.lower() == "deauth") | (df["deauth_count"] >= 25)]
    if not deauth_df.empty:
        total_deauth = int(deauth_df["deauth_count"].sum())
        peak_deauth = int(deauth_df["deauth_count"].max())
        targeted_ssids = list(deauth_df["ssid"].unique())
        targeted_bssids = list(deauth_df["bssid"].unique())
        if total_deauth > 50:
            alerts.append({
                "timestamp": str(deauth_df["timestamp"].max()),
                "category": "802.11 Deauthentication Flood",
                "severity": "Critical" if peak_deauth > 60 else "High",
                "ssid": ", ".join(targeted_ssids),
                "ioc": ", ".join(targeted_bssids),
                "evidence": f"Detected {total_deauth} cumulative deauth frames (Peak burst: {peak_deauth} frames/interval) targeting {', '.join(targeted_ssids)}.",
                "iso_control": "ISO/IEC 27001:2022 Annex A.8.20 & A.5.24 (Incident Management)"
            })

    # 3. Beacon Spam Detection (High unique SSID count sharing same OUI prefix on same channel)
    df_copy = df.copy()
    df_copy["oui"] = df_copy["bssid"].apply(lambda x: ":".join(str(x).split(":")[:3]))
    oui_groups = df_copy.groupby(["oui", "channel"]).agg(
        unique_ssids=("ssid", "nunique"),
        unique_bssids=("bssid", "nunique"),
        sample_ssids=("ssid", lambda x: list(set(x))[:5])
    ).reset_index()

    for _, row in oui_groups.iterrows():
        if row["unique_ssids"] >= 5:
            spam_bssids = df_copy[(df_copy["oui"] == row["oui"]) & (df_copy["channel"] == row["channel"])]["bssid"].unique()
            for b in spam_bssids:
                rogue_bssids.add(b)
            alerts.append({
                "timestamp": str(df["timestamp"].max()),
                "category": "802.11 Beacon Spam (ESP32 Marauder Pattern)",
                "severity": "High",
                "ssid": f"{row['unique_ssids']} Fake SSIDs ({', '.join(row['sample_ssids'])}...)",
                "ioc": f"OUI Prefix {row['oui']} on Ch {row['channel']}",
                "evidence": f"{row['unique_ssids']} random SSIDs broadcasted across {row['unique_bssids']} spoofed BSSIDs under OUI {row['oui']} on Channel {row['channel']}.",
                "iso_control": "ISO/IEC 27001:2022 Annex A.8.20 & A.8.16 (Monitoring Activities)"
            })

    return alerts, rogue_bssids


def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy (bits per character) of a string."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return round(-sum((count / length) * math.log2(count / length) for count in freq.values()), 3)


def analyze_url_forensics(url: str) -> dict:
    """Performs URL entropy, Punycode/IDN homograph, typosquatting, IP-host, and redirect checks."""
    cleaned_url = url.strip()
    if not re.match(r"^[a-zA-Z]+://", cleaned_url):
        cleaned_url = "http://" + cleaned_url

    parsed = urlparse(cleaned_url)
    hostname = parsed.netloc.split(":")[0].lower()
    path_query = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")

    entropy = calculate_shannon_entropy(cleaned_url)
    domain_entropy = calculate_shannon_entropy(hostname)

    risk_score = 0
    findings = []

    # 1. Entropy Check
    if entropy > 4.35 or domain_entropy > 3.85:
        risk_score += 22
        findings.append(f"High URL/Host Shannon Entropy ({entropy} bits/char) indicative of DGA or obfuscated token payload.")

    # 2. Punycode / IDN Homograph Check
    is_punycode = "xn--" in hostname or any(ord(c) > 127 for c in hostname)
    if is_punycode:
        risk_score += 30
        findings.append(f"IDN Homograph / Punycode detected in hostname (`{hostname}`).")

    # 3. Raw IPv4 Hostname Check
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))
    if is_ip:
        risk_score += 28
        findings.append(f"Direct IPv4 address (`{hostname}`) used instead of a registered domain name.")

    # 4. Suspicious TLD Check
    suspicious_tlds = (".xyz", ".top", ".zip", ".mov", ".ru", ".tk", ".ml", ".cf", ".gq", ".click", ".work", ".support")
    has_suspicious_tld = hostname.endswith(suspicious_tlds)
    if has_suspicious_tld:
        risk_score += 20
        findings.append(f"High-risk TLD detected (`{hostname.split('.')[-1]}`).")

    # 5. Typosquatting / Brand Spoofing Heuristics
    typosquat_patterns = [
        (r"micr[0o]s[0o]ft|mircosoft|rnicrosoft", "Microsoft"),
        (r"paypa[l1I]|pay-pal", "PayPal"),
        (r"g[0o]{2}gle|goog1e", "Google"),
        (r"app[l1]e-support|icloud-verify", "Apple"),
        (r"csmic-verify|csmic-login", "CSMIC Portal")
    ]
    matched_brand = None
    for pattern, brand in typosquat_patterns:
        if re.search(pattern, hostname):
            if hostname not in ["microsoft.com", "www.microsoft.com", "paypal.com", "google.com", "apple.com", "portal.csmic.ca"]:
                matched_brand = brand
                risk_score += 28
                findings.append(f"Brand typosquatting / lookalike pattern targeting **{brand}** (`{hostname}`).")
                break

    # 6. Redirect Depth & Credential Harvesting Keywords
    redirect_markers = len(re.findall(r"(http://|https://|%2f%2f|redirect=|url=|next=|return=)", path_query.lower()))
    if "@" in cleaned_url:
        risk_score += 20
        findings.append("URL contains `@` credential-confusion symbol in authority section.")
    if redirect_markers >= 1:
        risk_score += min(25, redirect_markers * 12)
        findings.append(f"Open redirect / nested URL redirection markers detected (Depth score: {redirect_markers}).")

    phish_keywords = ["login", "verify", "update", "secure", "account", "webscr", "signin", "token", "auth", "password"]
    kw_hits = [kw for kw in phish_keywords if kw in cleaned_url.lower()]
    if len(kw_hits) >= 2:
        risk_score += 15
        findings.append(f"Credential harvesting lures present in URL: `{', '.join(kw_hits)}`.")

    risk_score = min(100, risk_score)
    if not findings:
        findings.append("No malicious lexical, homograph, or redirection indicators identified.")

    severity = "Critical" if risk_score >= 75 else ("High" if risk_score >= 50 else ("Medium" if risk_score >= 25 else "Low"))

    return {
        "url": url,
        "hostname": hostname,
        "entropy": entropy,
        "domain_entropy": domain_entropy,
        "is_punycode": is_punycode,
        "is_ip": is_ip,
        "has_suspicious_tld": has_suspicious_tld,
        "redirect_depth": redirect_markers,
        "risk_score": risk_score,
        "severity": severity,
        "findings": findings
    }


def parse_email_headers(raw_headers: str) -> dict:
    """Parses raw RFC 5322 email headers for SPF, DKIM, DMARC, From/Return-Path alignment, and Received hops."""
    from_match = re.search(r"^From:\s*(.+)$", raw_headers, re.MULTILINE | re.IGNORECASE)
    return_path_match = re.search(r"^Return-Path:\s*(.+)$", raw_headers, re.MULTILINE | re.IGNORECASE)
    reply_to_match = re.search(r"^Reply-To:\s*(.+)$", raw_headers, re.MULTILINE | re.IGNORECASE)
    subject_match = re.search(r"^Subject:\s*(.+)$", raw_headers, re.MULTILINE | re.IGNORECASE)
    auth_match = re.search(r"^Authentication-Results:\s*(.+?(?:\n\s+.+?)*)", raw_headers, re.MULTILINE | re.IGNORECASE)

    from_val = from_match.group(1).strip() if from_match else "Not Present"
    return_path_val = return_path_match.group(1).strip() if return_path_match else "Not Present"
    reply_to_val = reply_to_match.group(1).strip() if reply_to_match else "None"
    subject_val = subject_match.group(1).strip() if subject_match else "No Subject"
    auth_val = auth_match.group(1).strip() if auth_match else ""

    def extract_domain(addr_str: str) -> str:
        m = re.search(r"@([a-zA-Z0-9.\-_]+)", addr_str)
        return m.group(1).lower().strip(">") if m else ""

    from_domain = extract_domain(from_val)
    rp_domain = extract_domain(return_path_val)
    reply_domain = extract_domain(reply_to_val)

    # Extract SPF, DKIM, DMARC statuses
    spf_status = "PASS" if re.search(r"spf=pass", raw_headers, re.IGNORECASE) else (
        "FAIL / SOFTFAIL" if re.search(r"spf=(fail|softfail)", raw_headers, re.IGNORECASE) else "NONE / UNVERIFIED"
    )
    dkim_status = "PASS" if re.search(r"dkim=pass", raw_headers, re.IGNORECASE) else (
        "FAIL" if re.search(r"dkim=(fail|neutral|none)", raw_headers, re.IGNORECASE) else "NONE / UNVERIFIED"
    )
    dmarc_status = "PASS" if re.search(r"dmarc=pass", raw_headers, re.IGNORECASE) else (
        "FAIL" if re.search(r"dmarc=fail", raw_headers, re.IGNORECASE) else "NONE / UNVERIFIED"
    )

    # Extract Received hops
    received_lines = re.findall(r"^Received:\s*(.+?(?:\n\s+.+?)*)(?=\n[A-Za-z\-]+:|\Z)", raw_headers, re.MULTILINE | re.DOTALL)
    hops = []
    for idx, rec in enumerate(reversed(received_lines), start=1):
        clean_rec = " ".join(rec.split())
        ip_m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", clean_rec)
        from_host = re.search(r"from\s+([^\s]+)", clean_rec, re.IGNORECASE)
        by_host = re.search(r"by\s+([^\s]+)", clean_rec, re.IGNORECASE)
        hops.append({
            "Hop #": idx,
            "From MTA": from_host.group(1) if from_host else "Unknown",
            "By MTA": by_host.group(1) if by_host else "Unknown",
            "Origin IP": ip_m.group(0) if ip_m else "Internal/IPv6",
            "Raw Segment": clean_rec[:110] + ("..." if len(clean_rec) > 110 else "")
        })

    anomalies = []
    risk = 0
    if from_domain and rp_domain and from_domain != rp_domain:
        risk += 35
        anomalies.append(f"Header Domain Mismatch: `From` domain (`{from_domain}`) != `Return-Path` domain (`{rp_domain}`).")
    if reply_domain and from_domain and reply_domain != from_domain:
        risk += 25
        anomalies.append(f"Reply-To Redirection: `Reply-To` domain (`{reply_domain}`) diverges from `From` domain (`{from_domain}`).")
    if "FAIL" in spf_status:
        risk += 25
        anomalies.append("SPF validation failed (`spf=fail` or `softfail`): Sending server IP is unauthorized.")
    if "FAIL" in dkim_status:
        risk += 25
        anomalies.append("DKIM cryptographic signature verification failed (`dkim=fail`).")
    if "FAIL" in dmarc_status:
        risk += 30
        anomalies.append("DMARC alignment policy failed (`dmarc=fail`).")

    risk = min(100, risk)
    verdict = "Critical Spoofing / Phishing" if risk >= 70 else ("Suspicious Email Header" if risk >= 35 else "Authentic / Aligned")

    return {
        "subject": subject_val,
        "from": from_val,
        "return_path": return_path_val,
        "reply_to": reply_to_val,
        "from_domain": from_domain,
        "rp_domain": rp_domain,
        "spf": spf_status,
        "dkim": dkim_status,
        "dmarc": dmarc_status,
        "hops": hops,
        "anomalies": anomalies,
        "risk_score": risk,
        "verdict": verdict
    }


# Initialize baseline capture on first load so dashboard is immediately populated
if st.session_state.wireless_df.empty:
    st.session_state.wireless_df = generate_wireless_capture("EvilTwin Attack in Progress")
    alerts, _ = run_wireless_heuristics(st.session_state.wireless_df)
    st.session_state.wireless_alerts = alerts

# ==========================================
# SIDEBAR: BRANDING & VERIFIED CERT BADGE
# ==========================================
with st.sidebar:
    st.markdown("## 🛡️ NetGuard-SOC")
    st.caption("Wireless 802.11 Threat, EvilTwin & Phishing Triage Platform")
    st.markdown("---")

    st.markdown("""
    <div class="cert-box">
        <div class="cert-header">✅ VERIFIED DEVELOPER & CERT</div>
        <div class="cert-detail">
            <strong>Developer:</strong> Sahayaraj Nadar<br>
            <strong>Roll No:</strong> 19068<br><br>
            <strong>Certification:</strong><br>
            CSMIC Cybersecurity Awareness Essentials<br>
            <strong>Score:</strong> <span style="color:#4ade80;font-weight:700;">100%</span><br>
            <strong>Cert ID:</strong> <code>CSMIC-AW-884LVR4P</code><br>
            <strong>Issued:</strong> Oct 27, 2026<br>
            <strong>Instructor:</strong> Kam Ghaderi, CISSP, ISO/IEC 27001 Lead Auditor
        </div>
        <a class="verify-btn" href="https://portal.csmic.ca/training/verify" target="_blank">
            🔗 Verify Credential at CSMIC Portal
        </a>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### 📊 Live SOC Telemetry")
    total_w_alerts = len(st.session_state.wireless_alerts)
    total_p_alerts = len(st.session_state.phishing_alerts)
    st.metric("Active Wireless Alerts", total_w_alerts, delta="802.11 IDS Active")
    st.metric("Phishing Triage Findings", total_p_alerts, delta="CSMIC Forensics")
    st.caption("Zero-Hardware Cloud Mode • ISO/IEC 27001:2022 Aligned")

# ==========================================
# TOP HEADER BANNER
# ==========================================
st.title("🛡️ NetGuard-SOC: Wireless Threat, EvilTwin & Phishing Triage Dashboard")
st.markdown(
    "**Enterprise Security Operations Center (SOC)** — Real-time 802.11 WIDS Heuristics, EvilTwin/Marauder Detection, "
    "CSMIC Phishing Forensics & Automated ISO/IEC 27001:2022 Incident Playbooks."
)

# ==========================================
# MAIN NAVIGATION TABS
# ==========================================
tab1, tab2, tab3, tab4 = st.tabs([
    "📡 Tab 1: Wireless 802.11 & EvilTwin Detector",
    "🎣 Tab 2: Phishing, URL & Email Forensics",
    "📋 Tab 3: ISO/IEC 27001 Triage & Playbook",
    "🎓 Tab 4: CSMIC Awareness Quiz & Showcase"
])

# ==============================================================================
# TAB 1: WIRELESS 802.11 & EVILTWIN ROGUE AP DETECTOR
# ==============================================================================
with tab1:
    st.subheader("📡 802.11 Wireless Intrusion Detection System (WIDS) & Rogue AP Triage")

    ctrl_col1, ctrl_col2, ctrl_col3 = st.columns([2, 1.3, 2])
    with ctrl_col1:
        selected_scenario = st.selectbox(
            "Select Simulated 802.11 Capture Scenario:",
            [
                "EvilTwin Attack in Progress",
                "ESP32 Marauder Deauth Flood & Beacon Spam",
                "Normal Office Network"
            ]
        )
    with ctrl_col2:
        st.write("")
        st.write("")
        if st.button("⚡ Generate Simulated 802.11 Capture", use_container_width=True, type="primary"):
            st.session_state.wireless_df = generate_wireless_capture(selected_scenario)
            alerts, _ = run_wireless_heuristics(st.session_state.wireless_df)
            st.session_state.wireless_alerts = alerts
            st.toast(f"Loaded scenario: {selected_scenario}", icon="📡")

    with ctrl_col3:
        uploaded_file = st.file_uploader(
            "Or Upload Custom 802.11 Scan Log (CSV/JSON):",
            type=["csv", "json"],
            help="Required columns: timestamp, ssid, bssid, channel, rssi, encryption, frame_type, deauth_count"
        )
        if uploaded_file is not None:
            try:
                if uploaded_file.name.endswith(".csv"):
                    custom_df = pd.read_csv(uploaded_file)
                else:
                    custom_df = pd.read_json(uploaded_file)
                required_cols = {"timestamp", "ssid", "bssid", "channel", "rssi", "encryption", "frame_type", "deauth_count"}
                if required_cols.issubset(set(custom_df.columns)):
                    custom_df["timestamp"] = pd.to_datetime(custom_df["timestamp"])
                    st.session_state.wireless_df = custom_df
                    alerts, _ = run_wireless_heuristics(custom_df)
                    st.session_state.wireless_alerts = alerts
                    st.success("Custom capture analyzed successfully!")
                else:
                    st.error(f"Missing required columns. Expected: {', '.join(sorted(required_cols))}")
            except Exception as e:
                st.error(f"Error parsing uploaded file: {e}")

    w_df = st.session_state.wireless_df
    w_alerts, rogue_bssids = run_wireless_heuristics(w_df)
    st.session_state.wireless_alerts = w_alerts

    # Top Metric Cards
    total_frames = len(w_df)
    unique_ssids = w_df["ssid"].nunique() if not w_df.empty else 0
    total_deauths = int(w_df["deauth_count"].sum()) if not w_df.empty else 0
    rogue_count = len(rogue_bssids)

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f"""
        <div class="soc-card">
            <div class="metric-title">Captured 802.11 Frames</div>
            <div class="metric-value">{total_frames:,}</div>
            <span class="badge badge-low">Live Pcap Stream</span>
        </div>
        """, unsafe_allow_html=True)
    with m2:
        st.markdown(f"""
        <div class="soc-card {'soc-card-high' if unique_ssids > 6 else ''}">
            <div class="metric-title">Unique SSIDs Observed</div>
            <div class="metric-value">{unique_ssids}</div>
            <span class="badge {'badge-high' if unique_ssids > 6 else 'badge-low'}">
                {'Beacon Anomaly' if unique_ssids > 6 else 'Baseline Normal'}
            </span>
        </div>
        """, unsafe_allow_html=True)
    with m3:
        st.markdown(f"""
        <div class="soc-card {'soc-card-critical' if total_deauths > 50 else ''}">
            <div class="metric-title">802.11 Deauth Frames</div>
            <div class="metric-value">{total_deauths:,}</div>
            <span class="badge {'badge-critical' if total_deauths > 50 else 'badge-low'}">
                {'DoS Flood Active' if total_deauths > 50 else 'Nominal'}
            </span>
        </div>
        """, unsafe_allow_html=True)
    with m4:
        st.markdown(f"""
        <div class="soc-card {'soc-card-critical' if rogue_count > 0 else 'soc-card-low'}">
            <div class="metric-title">Rogue / EvilTwin BSSIDs</div>
            <div class="metric-value">{rogue_count}</div>
            <span class="badge {'badge-critical' if rogue_count > 0 else 'badge-low'}">
                {'EvilTwin / Spoof' if rogue_count > 0 else '0 Rogue APs'}
            </span>
        </div>
        """, unsafe_allow_html=True)

    # Interactive Plotly Charts
    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        time_deauth = w_df.groupby("timestamp", as_index=False)["deauth_count"].sum()
        fig_deauth = px.area(
            time_deauth,
            x="timestamp",
            y="deauth_count",
            title="📈 802.11 Management Deauthentication Burst Timeline",
            labels={"timestamp": "Capture Time", "deauth_count": "Deauth Frame Count"},
            template="plotly_dark"
        )
        fig_deauth.update_traces(line_color="#ef4444", fillcolor="rgba(239, 68, 68, 0.25)")
        fig_deauth.update_layout(
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            margin=dict(l=20, r=20, t=45, b=20),
            height=360
        )
        st.plotly_chart(fig_deauth, use_container_width=True)

    with chart_col2:
        scatter_df = w_df.copy()
        scatter_df["AP Classification"] = scatter_df["bssid"].apply(
            lambda b: "Rogue / Suspicious BSSID" if b in rogue_bssids else "Authorized / Baseline BSSID"
        )
        fig_scatter = px.scatter(
            scatter_df,
            x="channel",
            y="rssi",
            color="AP Classification",
            hover_data=["ssid", "bssid", "encryption", "frame_type"],
            color_discrete_map={
                "Rogue / Suspicious BSSID": "#ef4444",
                "Authorized / Baseline BSSID": "#38bdf8"
            },
            title="🎯 Signal Strength (RSSI dBm) vs. 802.11 Channel (Rogue AP Highlighter)",
            labels={"channel": "802.11 Channel", "rssi": "RSSI Signal (dBm)"},
            template="plotly_dark"
        )
        fig_scatter.update_traces(marker=dict(size=10, opacity=0.85, line=dict(width=1, color="#0f172a")))
        fig_scatter.update_layout(
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            margin=dict(l=20, r=20, t=45, b=20),
            height=360,
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        st.plotly_chart(fig_scatter, use_container_width=True)

    # Live Threat Triage Table
    st.markdown("#### 🚨 Automated 802.11 Heuristic Threat Triage Table")
    if w_alerts:
        alerts_df = pd.DataFrame(w_alerts)
        st.dataframe(
            alerts_df[["timestamp", "severity", "category", "ssid", "ioc", "evidence", "iso_control"]],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.success("✅ No EvilTwin, Deauth Flood, or Beacon Spam anomalies detected in current capture.")

    with st.expander("🔎 Inspect Raw 802.11 Packet Capture Log"):
        st.dataframe(w_df, use_container_width=True, hide_index=True)

# ==============================================================================
# TAB 2: PHISHING, URL & EMAIL HEADER FORENSICS (CSMIC AWARENESS MODULE)
# ==============================================================================
with tab2:
    st.subheader("🎣 Phishing, Lexical URL Entropy & Email Header Forensics")

    url_col, email_col = st.columns([1.05, 1.15])

    # ---- LEFT COLUMN: URL ENTROPY & TYPOSQUATTING ANALYZER ----
    with url_col:
        st.markdown("### 🔗 URL Entropy & Homograph Analyzer")
        preset_urls = {
            "Sample 1 (Typosquatting + Open Redirect)": "https://login.micr0soft-security-update.xyz/auth/login?redirect=http://185.220.101.45/token",
            "Sample 2 (IDN Punycode Homograph Attack)": "https://xn--pypal-4ve.com/webscr?cmd=_login-run&secure=verify",
            "Sample 3 (Direct IP + Credential Lure)": "http://193.42.33.104/icloud-verify/account/password-reset.php",
            "Sample 4 (Benign CSMIC Verification Portal)": "https://portal.csmic.ca/training/verify",
            "Sample 5 (Benign Enterprise Microsoft Portal)": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
        }
        chosen_preset = st.selectbox("Select a Preset Test URL or Edit Below:", list(preset_urls.keys()))
        url_input = st.text_input("Target URL for Deep Inspection:", value=preset_urls[chosen_preset])

        if st.button("🔍 Analyze URL Forensics", type="primary", use_container_width=True):
            res = analyze_url_forensics(url_input)
            st.session_state.last_url_result = res
            if res["risk_score"] >= 30:
                st.session_state.phishing_alerts.append({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "category": "Malicious / Phishing URL",
                    "severity": res["severity"],
                    "ioc": res["url"],
                    "evidence": "; ".join(res["findings"]),
                    "iso_control": "ISO/IEC 27001:2022 Annex A.8.23 (Web Filtering) & A.6.3 (Security Awareness)"
                })

        if st.session_state.last_url_result is None:
            st.session_state.last_url_result = analyze_url_forensics(url_input)

        u_res = st.session_state.last_url_result

        # Risk Score Gauge Chart
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=u_res["risk_score"],
            title={"text": f"Phishing URL Risk Score ({u_res['severity']})", "font": {"size": 16, "color": "#e2e8f0"}},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": "#ef4444" if u_res["risk_score"] >= 70 else ("#f97316" if u_res["risk_score"] >= 40 else "#22c55e")},
                "steps": [
                    {"range": [0, 30], "color": "rgba(34, 197, 94, 0.2)"},
                    {"range": [30, 70], "color": "rgba(249, 115, 22, 0.2)"},
                    {"range": [70, 100], "color": "rgba(239, 68, 68, 0.25)"}
                ]
            }
        ))
        fig_gauge.update_layout(
            paper_bgcolor="#111827",
            font={"color": "#e2e8f0"},
            height=250,
            margin=dict(l=20, r=20, t=45, b=15)
        )
        st.plotly_chart(fig_gauge, use_container_width=True)

        u_c1, u_c2, u_c3 = st.columns(3)
        u_c1.metric("Shannon Entropy", f"{u_res['entropy']} bits")
        u_c2.metric("Punycode / IDN", "DETECTED" if u_res["is_punycode"] else "Clean")
        u_c3.metric("Redirect Depth", u_res["redirect_depth"])

        st.markdown("**Heuristic Findings:**")
        for f in u_res["findings"]:
            if u_res["risk_score"] >= 40:
                st.warning(f"⚠️ {f}")
            else:
                st.info(f"ℹ️ {f}")

    # ---- RIGHT COLUMN: RAW EMAIL HEADER INSPECTOR ----
    with email_col:
        st.markdown("### ✉️ Raw RFC 5322 Email Header Inspector")
        default_spoofed_header = """Return-Path: <bounce-8921@mailer.darknet-drop.ru>
Received: from mail-relay.darknet-drop.ru (mail-relay.darknet-drop.ru [185.220.101.92])
    by mx.enterprise-soc.org with ESMTP id 4X992Qp01
    for <finance.director@enterprise-soc.org>; Tue, 27 Oct 2026 09:12:41 +0000
Received: from workstation-09.local (unknown [103.14.26.188])
    by mail-relay.darknet-drop.ru (Postfix) with ESMTPA id 99B10A;
    Tue, 27 Oct 2026 09:12:10 +0000
Authentication-Results: mx.enterprise-soc.org;
    spf=fail (sender IP 185.220.101.92 not authorized by microsoft.com) smtp.mailfrom=mailer.darknet-drop.ru;
    dkim=fail (signature verification failed) header.d=microsoft.com;
    dmarc=fail action=quarantine header.from=microsoft.com
From: "Microsoft 365 Security Team" <security-noreply@microsoft.com>
Reply-To: "Urgent Helpdesk" <support-verify@mircosoft-helpdesk.xyz>
To: <finance.director@enterprise-soc.org>
Subject: [URGENT] Mandatory MFA Token Re-Synchronization Required
Date: Tue, 27 Oct 2026 09:12:05 +0000
Message-ID: <20261027091205.99B10A@mail-relay.darknet-drop.ru>"""

        raw_header_input = st.text_area(
            "Paste Raw Email Headers Below:",
            value=default_spoofed_header,
            height=235
        )

        if st.button("🛡️ Parse & Validate Email Header", type="primary", use_container_width=True):
            e_res = parse_email_headers(raw_header_input)
            st.session_state.last_email_result = e_res
            if e_res["risk_score"] >= 35:
                st.session_state.phishing_alerts.append({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "category": "Spoofed Phishing Email Header",
                    "severity": "Critical" if e_res["risk_score"] >= 70 else "High",
                    "ioc": f"From: {e_res['from']} | Return-Path: {e_res['return_path']}",
                    "evidence": "; ".join(e_res["anomalies"]),
                    "iso_control": "ISO/IEC 27001:2022 Annex A.8.23, A.6.3 & A.5.24"
                })

        if st.session_state.last_email_result is None:
            st.session_state.last_email_result = parse_email_headers(raw_header_input)

        e_res = st.session_state.last_email_result

        auth1, auth2, auth3, auth4 = st.columns(4)
        auth1.metric("SPF Status", e_res["spf"])
        auth2.metric("DKIM Status", e_res["dkim"])
        auth3.metric("DMARC Policy", e_res["dmarc"])
        auth4.metric("Header Risk", f"{e_res['risk_score']}/100")

        st.markdown("**Alignment & Spoofing Forensics:**")
        if e_res["anomalies"]:
            for anom in e_res["anomalies"]:
                st.error(f"🚨 {anom}")
        else:
            st.success("✅ SPF, DKIM, DMARC, and From/Return-Path headers are properly aligned.")

        st.markdown("**Trace of `Received` MTA Hop Chain (Origin → Destination):**")
        if e_res["hops"]:
            st.dataframe(pd.DataFrame(e_res["hops"]), use_container_width=True, hide_index=True)

# ==============================================================================
# TAB 3: ISO/IEC 27001 INCIDENT TRIAGE & REMEDIATION PLAYBOOK
# ==============================================================================
with tab3:
    st.subheader("📋 ISO/IEC 27001:2022 Incident Triage & Automated Remediation Playbook")

    combined_incidents = st.session_state.wireless_alerts + st.session_state.phishing_alerts

    # ISO/IEC 27001:2022 Control Mapping Reference
    iso_mappings = [
        {
            "Detected Threat Vector": "EvilTwin / Rogue AP & SSID Cloning",
            "ISO/IEC 27001:2022 Control": "Annex A.8.20 (Networks Security) & A.8.21 (Security of Network Services)",
            "Technical Containment Playbook": "Enforce 802.1X EAP-TLS mutual authentication; enable Rogue AP containment on WLC; block spoofed BSSID at switch port."
        },
        {
            "Detected Threat Vector": "802.11 Deauthentication / Disassociation Flood",
            "ISO/IEC 27001:2022 Control": "Annex A.8.20 (Networks Security) & A.5.24 (Incident Management Planning)",
            "Technical Containment Playbook": "Mandate IEEE 802.11w Protected Management Frames (PMF / `ieee80211w=2`); migrate enterprise SSIDs to WPA3-Enterprise."
        },
        {
            "Detected Threat Vector": "ESP32 Marauder Beacon Spam",
            "ISO/IEC 27001:2022 Control": "Annex A.8.16 (Monitoring Activities) & A.7.4 (Physical Security Monitoring)",
            "Technical Containment Playbook": "Triangulate rogue OUI RSSI (-30 to -40 dBm) for physical transmitter sweep; apply WIDS threshold rate-limiting."
        },
        {
            "Detected Threat Vector": "Typosquatted / Homograph Phishing URL",
            "ISO/IEC 27001:2022 Control": "Annex A.8.23 (Web Filtering) & A.6.3 (Information Security Awareness, Education & Training)",
            "Technical Containment Playbook": "Sinkhole malicious domain on internal DNS RPZ; block Punycode (`xn--`) lookalike domains at Secure Web Gateway."
        },
        {
            "Detected Threat Vector": "SPF/DKIM/DMARC Failure & Header Spoofing",
            "ISO/IEC 27001:2022 Control": "Annex A.8.20, A.6.3 & A.5.26 (Response to Information Security Incidents)",
            "Technical Containment Playbook": "Enforce DMARC `p=reject` policy; quarantine unaligned `Return-Path` envelopes; purge message-ID from Exchange/M365 mailboxes."
        }
    ]

    st.markdown("#### 🏛️ ISO/IEC 27001:2022 Annex A Control Mapping Matrix")
    st.dataframe(pd.DataFrame(iso_mappings), use_container_width=True, hide_index=True)

    st.markdown("#### 🚨 Active Incident Queue (Aggregated from Tab 1 & Tab 2)")
    if combined_incidents:
        inc_df = pd.DataFrame(combined_incidents)
        st.dataframe(inc_df, use_container_width=True, hide_index=True)
    else:
        st.info("No active incidents queued. Run a simulated attack in Tab 1 or inspect a malicious sample in Tab 2.")

    # Step-by-Step Containment Commands
    st.markdown("#### 💻 Ready-to-Execute SOC Containment Commands")
    cmd_col1, cmd_col2 = st.columns(2)
    with cmd_col1:
        st.markdown("**1. Enforce IEEE 802.11w (PMF) & Blacklist Rogue BSSID (Linux / Hostapd / Cisco WLC):**")
        st.code("""# Enforce Protected Management Frames (802.11w) to neutralize Deauth Floods
ieee80211w=2
wpa_key_mgmt=WPA-EAP-SHA256 SAE

# Cisco IOS-XE WLC: Contain Rogue EvilTwin BSSID
wlc# config rogue ap classify malicious DE:AD:BE:EF:00:99
wlc# config rogue ap containment level 4 DE:AD:BE:EF:00:99""", language="bash")

    with cmd_col2:
        st.markdown("**2. DNS Sinkhole & Email Gateway Quarantine (BIND RPZ / PowerShell):**")
        st.code("""# DNS RPZ Sinkhole for Typosquatted / Homograph Domain
*.micr0soft-security-update.xyz CNAME rpz-drop.local.
*.xn--pypal-4ve.com             CNAME rpz-drop.local.

# Exchange Online: Purge Spoofed Phishing Message by Message-ID
New-ComplianceSearchAction -SearchName "Phish_Purge_Oct27" -Purge -PurgeType HardDelete""", language="powershell")

    # Generate Downloadable Markdown & JSON Incident Response Report
    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    highest_sev = "CRITICAL" if any(i.get("severity") == "Critical" for i in combined_incidents) else "HIGH"

    incident_json_obj = {
        "report_id": "INC-2026-19068",
        "generated_at": report_time,
        "lead_analyst": {
            "name": "Sahayaraj Nadar",
            "roll_no": "19068",
            "certification": "CSMIC Cybersecurity Awareness Essentials",
            "cert_id": "CSMIC-AW-884LVR4P",
            "instructor": "Kam Ghaderi, CISSP, ISO/IEC 27001 Lead Auditor",
            "verify_url": "https://portal.csmic.ca/training/verify"
        },
        "overall_severity": highest_sev,
        "total_incidents": len(combined_incidents),
        "incidents": combined_incidents,
        "iso_27001_controls_invoked": [
            "Annex A.8.20 - Networks Security",
            "Annex A.8.23 - Web Filtering",
            "Annex A.6.3 - Information Security Awareness, Education and Training",
            "Annex A.5.24 - Information Security Incident Management Planning and Preparation"
        ]
    }

    md_lines = [
        "# 🛡️ NetGuard-SOC Incident Response & ISO/IEC 27001 Triage Report",
        f"- **Report ID:** `INC-2026-19068`",
        f"- **Generated Timestamp:** `{report_time}`",
        f"- **Lead SOC Analyst:** Sahayaraj Nadar (Roll No: 19068)",
        f"- **Verified Credential:** CSMIC Cybersecurity Awareness Essentials (`CSMIC-AW-884LVR4P` | Score: 100%)",
        f"- **Overall Severity Rating:** **{highest_sev}**",
        "",
        "## 1. Executive Summary",
        f"NetGuard-SOC detected **{len(combined_incidents)}** high-priority security events across 802.11 wireless telemetry and phishing forensics.",
        "",
        "## 2. Indicators of Compromise (IOCs) & Triage Findings"
    ]
    for idx, inc in enumerate(combined_incidents, start=1):
        md_lines.append(
            f"{idx}. **[{inc.get('severity')}] {inc.get('category')}** — IOC: `{inc.get('ioc')}` | "
            f"Evidence: {inc.get('evidence')} | Mapped Control: *{inc.get('iso_control')}*"
        )
    md_lines.extend([
        "",
        "## 3. Mandatory Remediation Actions (ISO/IEC 27001:2022)",
        "- **Annex A.8.20 (Networks Security):** Enable 802.11w Protected Management Frames (`ieee80211w=2`) and contain Rogue BSSID `DE:AD:BE:EF:00:99`.",
        "- **Annex A.8.23 (Web Filtering):** Sinkhole identified typosquatted and Punycode domains at DNS RPZ.",
        "- **Annex A.6.3 (Security Awareness):** Conduct targeted anti-phishing and EvilTwin captive-portal training.",
        "- **Annex A.5.24 (Incident Management):** Preserve packet captures and RFC 5322 headers for forensic chain-of-custody."
    ])
    markdown_report_str = "\n".join(md_lines)

    dl_col1, dl_col2 = st.columns(2)
    with dl_col1:
        st.download_button(
            label="📥 Download Incident Response Report (.MD)",
            data=markdown_report_str,
            file_name="NetGuard_SOC_Incident_Report_INC_2026_19068.md",
            mime="text/markdown",
            use_container_width=True
        )
    with dl_col2:
        st.download_button(
            label="📥 Download Machine-Readable IOC Report (.JSON)",
            data=json.dumps(incident_json_obj, indent=2),
            file_name="NetGuard_SOC_Incident_Report_INC_2026_19068.json",
            mime="application/json",
            use_container_width=True
        )

# ==============================================================================
# TAB 4: INTERACTIVE CYBERSECURITY AWARENESS QUIZ & CERTIFICATE SHOWCASE
# ==============================================================================
with tab4:
    st.subheader("🎓 CSMIC Interactive Cybersecurity Awareness Simulator & Credential Showcase")

    quiz_col, cert_col = st.columns([1.25, 1])

    with quiz_col:
        st.markdown("#### 🧠 5-Scenario SOC & Phishing Triage Assessment")
        quiz_questions = [
            {
                "q": "1. Your laptop disconnects from 'CorpNet-5G' (WPA3-Enterprise) and auto-connects to an identically named 'CorpNet-5G' network with Open encryption and a -31 dBm signal, prompting for your Active Directory credentials in a browser captive portal. What attack is occurring?",
                "options": [
                    "A) Standard DHCP Lease Renewal",
                    "B) EvilTwin Rogue AP + 802.11 Deauthentication Attack",
                    "C) ARP Poisoning on a Wired VLAN",
                    "D) DNS Cache Snooping"
                ],
                "correct": 1,
                "explanation": "Attackers transmit forged 802.11 Deauth frames to knock clients off the legitimate BSSID and lure them onto a higher-RSSI Open EvilTwin AP hosting a credential-harvesting captive portal."
            },
            {
                "q": "2. Which IEEE 802.11 standard specifically protects management frames (Disassociate / Deauthenticate) with cryptographic integrity checks to prevent spoofed Deauth floods?",
                "options": [
                    "A) IEEE 802.11b",
                    "B) IEEE 802.11w (Protected Management Frames - PMF)",
                    "C) IEEE 802.11g",
                    "D) WEP-128 Shared Key"
                ],
                "correct": 1,
                "explanation": "IEEE 802.11w (mandated in WPA3) authenticates management frames using BIP/CMAC so attackers cannot spoof unauthenticated Deauth frames."
            },
            {
                "q": "3. During email header forensics, you observe `From: security@microsoft.com`, `Return-Path: <bounce@mailer.darknet-drop.ru>`, `spf=fail`, and `dmarc=fail`. How should the SOC classify this email?",
                "options": [
                    "A) Legitimate third-party marketing newsletter",
                    "B) Benign calendar invitation",
                    "C) Spoofed Spear-Phishing Email failing DMARC alignment",
                    "D) Encrypted S/MIME internal memo"
                ],
                "correct": 2,
                "explanation": "The envelope sender (`Return-Path`) does not align with the header `From` domain, and both SPF and DMARC authentication failed—classic indicators of direct domain spoofing."
            },
            {
                "q": "4. An employee receives an urgent SMS link to `https://xn--pypal-4ve.com/login`. What deceptive technique is the attacker using?",
                "options": [
                    "A) SQL Injection",
                    "B) IDN Homograph Attack using Punycode (`xn--`)",
                    "C) BGP Route Hijacking",
                    "D) Cross-Site Request Forgery (CSRF)"
                ],
                "correct": 1,
                "explanation": "Internationalized Domain Names (IDN) encode non-ASCII lookalike characters (e.g., Cyrillic or accented characters) using the `xn--` Punycode prefix to visually impersonate trusted brands."
            },
            {
                "q": "5. Under ISO/IEC 27001:2022 Annex A, which combination of controls directly governs Web Filtering against phishing domains and Employee Security Awareness Training?",
                "options": [
                    "A) Annex A.8.23 (Web Filtering) & Annex A.6.3 (Information Security Awareness, Education and Training)",
                    "B) Annex A.7.1 (Physical Perimeters) & Annex A.7.14 (Equipment Disposal)",
                    "C) Annex A.5.11 (Return of Assets) & Annex A.7.8 (Equipment Siting)",
                    "D) Annex A.8.13 (Information Backup) Only"
                ],
                "correct": 0,
                "explanation": "ISO/IEC 27001:2022 Annex A.8.23 addresses technical web filtering of malicious URLs, while Annex A.6.3 mandates continuous cybersecurity awareness training."
            }
        ]

        user_answers = []
        for idx, item in enumerate(quiz_questions):
            ans = st.radio(item["q"], item["options"], key=f"quiz_q_{idx}", index=0)
            user_answers.append(item["options"].index(ans))

        if st.button("✅ Submit Assessment & View Technical Explanations", type="primary", use_container_width=True):
            st.session_state.quiz_submitted = True

        if st.session_state.quiz_submitted:
            score = sum(1 for i, q in enumerate(quiz_questions) if user_answers[i] == q["correct"])
            st.markdown(f"### 🏆 Assessment Score: **{score} / 5 ({score * 20}%)**")
            for i, q in enumerate(quiz_questions):
                if user_answers[i] == q["correct"]:
                    st.success(f"**Q{i+1} Correct!** {q['explanation']}")
                else:
                    st.error(f"**Q{i+1} Incorrect.** Correct Answer: *{q['options'][q['correct']]}* — {q['explanation']}")

    with cert_col:
        st.markdown("#### 🏅 CSMIC Certification Credential Showcase")
        st.markdown("""
        <div class="soc-card" style="border-left: 4px solid #6366f1; padding: 24px;">
            <h3 style="color:#818cf8; margin-top:0;">CSMIC Cybersecurity Awareness Essentials</h3>
            <p style="color:#e2e8f0; font-size:0.95rem;">
                This certifies that <strong>Sahayaraj Nadar (Roll No: 19068)</strong> has successfully mastered
                wireless threat awareness, phishing header forensics, social engineering defense, and ISO/IEC 27001-aligned incident triage.
            </p>
            <hr style="border-color:#334155;">
            <p style="font-size:0.88rem; color:#cbd5e1; line-height:1.7;">
                📌 <strong>Candidate Name:</strong> Sahayaraj Nadar<br>
                📌 <strong>Academic Roll No:</strong> 19068<br>
                📌 <strong>Examination Score:</strong> <span class="badge badge-low">100% (Distinction)</span><br>
                📌 <strong>Certificate ID:</strong> <code>CSMIC-AW-884LVR4P</code><br>
                📌 <strong>Issue Date:</strong> October 27, 2026<br>
                📌 <strong>Lead Instructor:</strong> Kam Ghaderi, CISSP, ISO/IEC 27001 Lead Auditor<br>
                📌 <strong>Verification Portal:</strong> <a href="https://portal.csmic.ca/training/verify" target="_blank" style="color:#38bdf8;">https://portal.csmic.ca/training/verify</a>
            </p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("#### 🏗️ NetGuard-SOC System Architecture")
        st.code("""
+-------------------------------------------------------------------+
|                  NetGuard-SOC Streamlit Cloud UI                  |
|         Author: Sahayaraj Nadar (Roll No: 19068) | CSMIC          |
+-----------------+-----------------------+-------------------------+
                  |                       |
      +-----------v-----------+   +-------v-------------------+
      | Tab 1: 802.11 WIDS    |   | Tab 2: Phishing Forensics |
      | - Synthetic Pcap Gen  |   | - Shannon Entropy Engine  |
      | - EvilTwin Heuristics |   | - Punycode/IDN Detector   |
      | - Deauth Burst Alert  |   | - SPF/DKIM/DMARC Parser   |
      | - Marauder OUI Check  |   | - MTA Received Hop Trace  |
      +-----------+-----------+   +-------+-------------------+
                  |                       |
                  +-----------+-----------+
                              |
              +---------------v---------------+
              | Tab 3: ISO/IEC 27001:2022     |
              | - Annex A.8.20 / A.8.23 Map   |
              | - 802.11w & RPZ Playbooks     |
              | - MD & JSON Incident Exporter |
              +-------------------------------+
        """, language="text")
