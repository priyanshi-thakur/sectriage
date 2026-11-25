import re
from collections import Counter
from urllib.parse import urlparse
import streamlit as st

st.set_page_config(page_title="SecTriage | URL & Log Inspector", layout="centered")

st.markdown("""
<style>
    .block-container { padding-top: 2.5rem; padding-bottom: 2.5rem; max-width: 760px; }
    h1, h2, h3 { font-family: Georgia, "Times New Roman", serif; font-weight: 600; color: #1B2428; }
    p, label, .stMarkdown { font-family: "Segoe UI", system-ui, sans-serif; color: #1B2428; }
    .stButton > button {
        background-color: #2C4A52;
        color: #FFFFFF;
        border: 1px solid #2C4A52;
        border-radius: 4px;
        padding: 0.45rem 1.2rem;
        font-weight: 500;
    }
    .stButton > button:hover {
        background-color: #1F353B;
        border-color: #1F353B;
        color: #FFFFFF;
    }
    .report-box {
        border-left: 4px solid #2C4A52;
        border-top: 1px solid #DCE3E5;
        border-right: 1px solid #DCE3E5;
        border-bottom: 1px solid #DCE3E5;
        background-color: #FFFFFF;
        padding: 1.2rem;
        border-radius: 4px;
        margin-top: 1rem;
    }
    .tag {
        display: inline-block;
        padding: 2px 9px;
        font-size: 0.78rem;
        font-weight: 600;
        background-color: #E7EFEF;
        color: #2C4A52;
        border: 1px solid #B8C9CE;
        border-radius: 3px;
        text-transform: uppercase;
    }
</style>
""", unsafe_allow_html=True)

SUSPICIOUS_TLDS = {".zip", ".mov", ".xyz", ".top", ".gq", ".tk", ".ml", ".cf", ".work", ".click"}
SENSITIVE_WORDS = {"login", "verify", "update", "secure", "account", "banking", "signin", "wallet", "confirm"}

SAMPLE_LOGS = """Nov 24 09:12:01 srv01 sshd[4120]: Failed password for invalid user admin from 185.220.101.4 port 51234 ssh2
Nov 24 09:12:04 srv01 sshd[4120]: Failed password for invalid user admin from 185.220.101.4 port 51238 ssh2
Nov 24 09:12:07 srv01 sshd[4120]: Failed password for invalid user root from 185.220.101.4 port 51242 ssh2
Nov 24 09:12:11 srv01 sshd[4120]: Failed password for invalid user root from 185.220.101.4 port 51249 ssh2
Nov 24 09:12:15 srv01 sshd[4120]: Failed password for invalid user test from 185.220.101.4 port 51255 ssh2
Nov 24 09:14:22 srv01 sshd[4188]: Accepted publickey for deploy from 10.0.1.14 port 49812 ssh2
Nov 24 09:18:40 srv01 sshd[4201]: Failed password for ubuntu from 203.0.113.77 port 60112 ssh2
Nov 24 09:18:44 srv01 sshd[4201]: Failed password for ubuntu from 203.0.113.77 port 60115 ssh2"""


def evaluate_url(raw_url: str):
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    host = parsed.hostname or ""
    path_and_query = f"{parsed.path}?{parsed.query}".lower()
    findings = []
    score = 0

    if parsed.scheme == "http":
        score += 15
        findings.append("Unencrypted HTTP scheme detected.")

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        score += 35
        findings.append("Host uses a raw IPv4 address instead of a registered domain.")

    if "@" in raw_url:
        score += 30
        findings.append("Contains '@' symbol, which can obscure the true destination host.")

    if host.startswith("xn--") or ".xn--" in host:
        score += 30
        findings.append("Punycode domain detected (potential IDN homograph lookalike).")

    subdomain_count = len(host.split(".")) - 2
    if subdomain_count >= 3:
        score += 20
        findings.append(f"Deep subdomain nesting ({subdomain_count} levels).")

    if "-" in host:
        score += 10
        findings.append("Hyphenated domain name (common in typosquatting campaigns).")

    if len(raw_url) > 75:
        score += 10
        findings.append(f"Unusually long URL ({len(raw_url)} characters).")

    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 20
        findings.append("Uses a high-abuse top-level domain.")

    matched_terms = [w for w in SENSITIVE_WORDS if w in host or w in path_and_query]
    if matched_terms:
        score += 15
        findings.append(f"Credential-harvesting keywords present: {', '.join(sorted(matched_terms))}.")

    score = min(score, 100)
    if score >= 50:
        verdict = "High Risk"
    elif score >= 25:
        verdict = "Moderate Risk"
    else:
        verdict = "Low Risk"

    return score, verdict, host, findings


def parse_auth_logs(log_text: str, threshold: int):
    ip_pattern = re.compile(r"Failed password.*from\s+(\d{1,3}(?:\.\d{1,3}){3})")
    user_pattern = re.compile(r"Failed password for (?:invalid user\s+)?(\S+)")

    ip_counts = Counter()
    user_counts = Counter()
    total_failed = 0

    for line in log_text.splitlines():
        if "Failed password" in line:
            total_failed += 1
            ip_match = ip_pattern.search(line)
            user_match = user_pattern.search(line)
            if ip_match:
                ip_counts[ip_match.group(1)] += 1
            if user_match:
                user_counts[user_match.group(1)] += 1

    flagged_ips = {ip: count for ip, count in ip_counts.items() if count >= threshold}
    return total_failed, ip_counts, user_counts, flagged_ips


st.title("SecTriage")
st.caption("Static heuristic URL inspection and SSH authentication log triage.")

tab_url, tab_logs = st.tabs(["URL Inspector", "Auth Log Triage"])

with tab_url:
    target_url = st.text_input(
        "Target URL",
        value="http://secure-login.account-verify.example.xyz/signin?session=1290",
        placeholder="https://example.com"
    )
    if st.button("Inspect URL"):
        if not target_url.strip():
            st.warning("Enter a URL to inspect.")
        else:
            score, verdict, host, findings = evaluate_url(target_url)
            st.markdown(f"""
            <div class="report-box">
                <span class="tag">{verdict}</span>
                <h3 style="margin-top: 0.65rem; margin-bottom: 0.2rem;">Risk Score: {score} / 100</h3>
                <p style="color: #4E5D63; font-size: 0.9rem; margin-bottom: 0;">Extracted Host: <code>{host or 'N/A'}</code></p>
            </div>
            """, unsafe_allow_html=True)

            st.subheader("Findings")
            if findings:
                for item in findings:
                    st.write(f"- {item}")
            else:
                st.write("No heuristic anomalies detected.")

with tab_logs:
    threshold = st.number_input("Brute-force alert threshold (failed attempts per IP)", min_value=2, max_value=50, value=5)
    raw_logs = st.text_area("Paste syslog / auth.log lines", value=SAMPLE_LOGS, height=200)

    if st.button("Analyze Logs"):
        total_failed, ip_counts, user_counts, flagged_ips = parse_auth_logs(raw_logs, int(threshold))
        col1, col2, col3 = st.columns(3)
        col1.metric("Failed Attempts", total_failed)
        col2.metric("Unique Source IPs", len(ip_counts))
        col3.metric("Flagged IPs", len(flagged_ips))

        st.subheader("Flagged Source IPs")
        if flagged_ips:
            rows = [{"Source IP": ip, "Failed Attempts": cnt, "Status": "Threshold Exceeded"} for ip, cnt in flagged_ips.items()]
            st.table(rows)
        else:
            st.write("No IP addresses exceeded the failure threshold.")

        if user_counts:
            st.subheader("Targeted Accounts")
            user_rows = [{"Username": user, "Attempts": cnt} for user, cnt in user_counts.most_common(10)]
            st.table(user_rows)
