import pandas as pd
import streamlit as st
from datetime import datetime

st.set_page_config(page_title="SecureLog Analyzer", page_icon="🛡️", layout="wide")
st.title("🛡️ SecureLog Analyzer")
st.caption("Security log analysis dashboard | Defensive monitoring demo")

REQUIRED = {"timestamp", "username", "source_ip", "event"}
SAMPLE = """timestamp,username,source_ip,event
2026-11-07 09:00:00,admin,192.168.1.10,FAILED_LOGIN
2026-11-07 09:01:00,admin,192.168.1.10,FAILED_LOGIN
2026-11-07 09:02:00,admin,192.168.1.10,FAILED_LOGIN
2026-11-07 09:03:00,admin,192.168.1.10,FAILED_LOGIN
2026-11-07 09:04:00,admin,192.168.1.10,FAILED_LOGIN
2026-11-07 09:10:00,user1,192.168.1.15,SUCCESS_LOGIN
2026-11-07 09:15:00,user2,192.168.1.20,FAILED_LOGIN
2026-11-07 09:20:00,user2,192.168.1.20,SUCCESS_LOGIN"""

with st.sidebar:
    st.header("Analysis settings")
    threshold = st.slider("Failed attempts threshold", 2, 20, 5)
    st.download_button("Download sample CSV", SAMPLE, "sample_logs.csv", "text/csv", use_container_width=True)
    st.info("Analyze only logs from systems you own or are authorized to monitor.")

uploaded = st.file_uploader("Upload a CSV security log", type=["csv"])
if uploaded is None:
    st.info("Upload a CSV file or download the fictional sample CSV from the sidebar.")
    st.code("timestamp,username,source_ip,event")
    st.stop()

try:
    df = pd.read_csv(uploaded)
except Exception as exc:
    st.error(f"Could not read CSV: {exc}")
    st.stop()

df.columns = [str(c).strip().lower() for c in df.columns]
missing = REQUIRED - set(df.columns)
if missing:
    st.error("Missing required columns: " + ", ".join(sorted(missing)))
    st.stop()

for col in ["username", "source_ip", "event"]:
    df[col] = df[col].fillna("").astype(str).str.strip()
df["event"] = df["event"].str.upper()
df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
valid = df[df["event"].isin(["FAILED_LOGIN", "SUCCESS_LOGIN"])].copy()
unknown = sorted(set(df["event"]) - {"FAILED_LOGIN", "SUCCESS_LOGIN"})
if unknown:
    st.warning("Unsupported event values excluded: " + ", ".join(unknown))
if valid.empty:
    st.warning("No supported login events found.")
    st.stop()

failed = valid[valid["event"] == "FAILED_LOGIN"]
success = valid[valid["event"] == "SUCCESS_LOGIN"]
ip_counts = failed["source_ip"].value_counts()
user_counts = failed["username"].value_counts()
alerts = []
for ip, count in ip_counts.items():
    if ip and count >= threshold:
        alerts.append({"Risk":"HIGH","Type":"Repeated failed logins from IP","Indicator":ip,"Attempts":int(count),"Recommendation":"Review source and authentication logs; consider rate limiting."})
for user, count in user_counts.items():
    if user and count >= threshold:
        alerts.append({"Risk":"MEDIUM","Type":"Repeated failed logins for account","Indicator":user,"Attempts":int(count),"Recommendation":"Review account activity and authentication controls."})

a,b,c,d = st.columns(4)
a.metric("Total login events", f"{len(valid):,}")
b.metric("Successful logins", f"{len(success):,}")
c.metric("Failed logins", f"{len(failed):,}")
d.metric("Alerts generated", f"{len(alerts):,}")

left,right = st.columns(2)
with left:
    st.subheader("Login event distribution")
    st.bar_chart(valid["event"].value_counts())
with right:
    st.subheader("Top source IPs by failed attempts")
    if ip_counts.empty:
        st.info("No failed login events.")
    else:
        st.bar_chart(ip_counts.head(10))

st.subheader("Security alerts")
if alerts:
    st.dataframe(pd.DataFrame(alerts), use_container_width=True, hide_index=True)
else:
    st.success(f"No events met the configured threshold of {threshold} failed attempts.")

st.subheader("Analyzed log records")
st.dataframe(valid, use_container_width=True, hide_index=True)

report = [
    "SECURELOG ANALYZER REPORT",
    "========================",
    f"Generated: {datetime.now().isoformat(timespec='seconds')}",
    f"Threshold: {threshold}",
    f"Total events: {len(valid)}",
    f"Successful logins: {len(success)}",
    f"Failed logins: {len(failed)}",
    f"Alerts: {len(alerts)}",
    "",
    "SECURITY ALERTS"
]
for alert in alerts:
    report.append(f"[{alert['Risk']}] {alert['Type']}: {alert['Indicator']} ({alert['Attempts']} attempts)")
    report.append("Recommendation: " + alert["Recommendation"])
if not alerts:
    report.append("No events met the configured threshold.")
report += ["", "Alerts are indicators for investigation, not proof of compromise.", "Use only authorized and sanitized logs."]
st.download_button("⬇️ Download analysis report", "\n".join(report), "security_analysis_report.txt", "text/plain")
st.caption("Educational defensive-security project. Review alerts before taking action.")
