import streamlit as st
from model import Protocol, TrafficType, ActionTaken, AttackType, PacketType, AttackSignature, ServiertyLevel, NetworkSegment, LogSource, NetworkLogEntry
from src.service import get_device_list, get_os_list, get_browser_list, predict
import pandas as pd
import datetime


st.title("🔐 **Cyber Attack Prediction**")

st.markdown("""
    Welcome to the **Cyber Attack Prediction App**! This tool predicts whether a given network log entry represents a cyberattack.
    Please select a model, fill in the details below, or upload a file to predict multiple entries at once. 🛡️
""")

with st.container(border=True):
    st.markdown("### 📅 **Date and Time Information**")
    col1, col2 = st.columns(2)
    with col1:
        attack_date = st.date_input("Date", datetime.date(2019, 7, 6))

    with col2:
        attack_time = st.time_input("Time", datetime.time(8, 45))

with st.container(border=True):
    st.markdown("### 📦 **Packet Information**")
    col3, col4 = st.columns(2)
    with col3:
        source_ip = st.text_input("Source IP", placeholder="e.g., 192.168.1.1")
        destination_ip = st.text_input(
            "Destination IP", placeholder="e.g., 192.168.1.2")
        source_port = st.number_input(
            "Source Port", min_value=0, max_value=65535)
        destination_port = st.number_input(
            "Destination Port", min_value=0, max_value=65535)
        protocol = st.selectbox("Protocol", [p.value for p in Protocol])

    with col4:
        packet_length = st.number_input(
            "Packet Length (in bytes)", min_value=0)
        packet_type = st.selectbox(
            "Packet Type", [t.value for t in PacketType])
        traffic_type = st.selectbox(
            "Traffic Type", [t.value for t in TrafficType])


with st.container(border=True):
    st.markdown("### 🚨 **Alert Information**")
    col5, col6 = st.columns(2)
    with col5:
        ioc_detected = st.toggle("IoC Detected")
        alerts_warnings = st.toggle("Alerts or Warnings")

    with col6:
        firewall_logs = st.toggle("Firewall Log Present")
        ids_ips_alerts = st.toggle("IDS/IPS Alerts Raised")


with st.container(border=True):
    st.markdown("### 🖥️ **Device Information**")
    col7, col8 = st.columns(2)
    with col7:
        operation_system = st.selectbox(
            "Operating System", get_os_list(), index=0)
        device = st.selectbox("Device", get_device_list(), index=0)

    with col8:
        browser = st.selectbox("Browser", get_browser_list(), index=0)


with st.container(border=True):
    st.markdown("### ⚖️ **Risk Assement**")
    col9, col10 = st.columns(2)
    with col9:
        anomaly_scores = st.number_input(
            "Anomaly Scores", placeholder="e.g., high, medium, low")
        attack_signature = st.selectbox(
            "Attack Signature", [s.value for s in AttackSignature], index=0)
        action_taken = st.selectbox(
            "Action Taken", [a.value for a in ActionTaken], index=0)

    with col10:
        severity_level = st.selectbox(
            "Severity Level", [s.value for s in ServiertyLevel], index=0)


with st.container(border=True):
    st.markdown("### 🌍 **Additional Information**")
    col11, col12 = st.columns(2)

    with col11:
        network_segment = st.selectbox(
            "Network Segment", [n.value for n in NetworkSegment], index=0)

        proxy_information = st.toggle("Proxy Used")

    with col12:
        log_source = st.selectbox(
            "Log Source", [ls.value for ls in LogSource], index=0)


with st.container(border=True):
    st.markdown("### 💀 **Attack Type**")
    col5, col6 = st.columns(2)
    with col5:
        model_option = st.selectbox("Select the machine learning model for prediction:", [
                                    "Decision Tree", "Random Forest", "Logistic Regression"])

        predict_btn = st.button(label="Predict")

        if predict_btn:
            network_entry = NetworkLogEntry(
                # Date and Time Info
                attack_date=attack_date,
                attack_time=attack_time,

                # IP Packet Info
                source_ip=source_ip,
                destination_ip=destination_ip,
                source_port=source_port,
                destination_port=destination_port,
                protocol=protocol,
                packet_length=packet_length,
                packet_type=packet_type,
                traffic_type=traffic_type,

                # Alert Info
                ioc_detected=ioc_detected,
                ids_ips_alerts=ids_ips_alerts,
                alerts_warnings=alerts_warnings,
                firewall_log=firewall_logs,

                # Device Info
                operating_system=operation_system,
                browser=browser,
                device=device,

                # Risk Assement
                anomaly_scores=anomaly_scores,
                attack_signature=attack_signature,
                action_taken=action_taken,
                severity_level=severity_level,

                # Additional Informaiton
                network_segment=network_segment,
                proxy_information=proxy_information,
                log_source=log_source,
            )
            predict(network_entry)

    with col6:
        pass