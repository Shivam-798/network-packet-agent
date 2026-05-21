import streamlit as st
import requests
import os

st.set_page_config(page_title="Network Packet Analyzer", page_icon="🛡️", layout="wide")

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
TARGET_IP = "127.0.0.1"

st.title("Network Packet Analysis Agent")
st.caption("Send attack simulations and analyze network traffic in real time")

with st.sidebar:
    st.header("Settings")
    interface = st.selectbox("Network interface", ["lo", "eth0", "wlan0"])
    target_ip = st.text_input("Target IP", value=TARGET_IP)
    packet_count = st.slider("Packet count", 10, 2000, 500)
    st.divider()
    st.caption("lo = loopback (safe local testing)")

# ── Attack buttons ────────────────────────────────────────────────
st.subheader("Attack Simulator")
col1, col2, col3, col4, col5 = st.columns(5)

def call_attack(endpoint, label):
    try:
        res = requests.post(
            f"{BACKEND_URL}/attack/{endpoint}",
            json={"target": target_ip, "count": packet_count},
            timeout=30
        )
        data = res.json()
        st.success(f"{label} sent — {data}")
    except Exception as e:
        st.error(f"Error: {e}")

with col1:
    if st.button("DDoS Attack", use_container_width=True, type="primary"):
        call_attack("ddos", "DDoS")

with col2:
    if st.button("Port Scan", use_container_width=True):
        call_attack("portscan", "Port Scan")

with col3:
    if st.button("SYN Flood", use_container_width=True):
        call_attack("synflood", "SYN Flood")

with col4:
    if st.button("Suspicious Ports", use_container_width=True):
        call_attack("suspicious", "Suspicious Ports")

with col5:
    if st.button("Normal Traffic", use_container_width=True):
        call_attack("normal", "Normal Traffic")

st.divider()

# ── Analyze button ────────────────────────────────────────────────
if st.button("Analyze Network Now", type="primary", use_container_width=True):
    with st.spinner("Agent analyzing packets..."):
        try:
            res = requests.post(
                f"{BACKEND_URL}/analyze",
                json={"interface": interface},
                timeout=60
            )
            data = res.json()

            st.subheader("Network Stats")
            stats = data.get("stats", {})
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Total Packets", stats.get("total_packets", 0))
            m2.metric("Total Bytes", f"{stats.get('total_bytes', 0):,}")
            m3.metric("Threats Found", len(data.get("threats", [])))
            m4.metric("Protocols", len(stats.get("protocols", {})))

            st.subheader("Traffic Breakdown")
            c1, c2 = st.columns(2)

            with c1:
                protocols = stats.get("protocols", {})
                if protocols:
                    st.bar_chart(protocols)
                    st.caption("Protocol distribution")

            with c2:
                top_sources = stats.get("top_sources", [])
                if top_sources:
                    src_data = {ip: count for ip, count in top_sources}
                    st.bar_chart(src_data)
                    st.caption("Top source IPs")

            st.subheader("Threat Detection")
            threats = data.get("threats", [])
            if threats:
                for threat in threats:
                    severity = threat.get("severity", "LOW")
                    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(severity, "🟢")
                    with st.expander(f"{icon} {threat['type']} — {severity}"):
                        st.write(threat.get("detail", ""))
            else:
                st.success("No threats detected")

            st.subheader("AI Summary")
            st.info(data.get("ai_summary", "No summary available"))

        except requests.exceptions.ConnectionError:
            st.error("Cannot connect to backend. Make sure uvicorn is running on port 8000.")
        except Exception as e:
            st.error(f"Error: {e}")