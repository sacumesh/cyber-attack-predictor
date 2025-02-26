import streamlit as st
from model import Protocol, TrafficType, ActionTaken, AttackType, PacketType, AttackSignature, ServiertyLevel, OperatingSystem, Device, Browser, NetworkSegment, LogSource
import pandas as pd
import datetime


st.title("🔐 **Cyber Attack Prediction**")

st.markdown("""
    Welcome to the **Cyber Attack Prediction App**! This tool predicts whether a given network log entry represents a cyberattack.
    Please select a model, fill in the details below, or upload a file to predict multiple entries at once. 🛡️
""")

with st.container(border=True):
    st.markdown("### 📅 **Date and Time Information**")
    col1a, colb = st.columns(2)
    with col1a:
        attack_date = st.date_input("Date", datetime.date(2019, 7, 6))

    with colb:
        attack_time = st.time_input("Time", datetime.time(8, 45))

with st.container(border=True):
    st.markdown("### 📦 **Packet Information**")
    col1, col2 = st.columns(2)
    with col1:
        source_ip = st.text_input("Source IP", placeholder="e.g., 192.168.1.1")
        destination_ip = st.text_input("Destination IP", placeholder="e.g., 192.168.1.2")
        source_port = st.number_input("Source Port", min_value=0, max_value=65535)
        destination_port = st.number_input("Destination Port", min_value=0, max_value=65535)
        protocol = st.selectbox("Protocol", [p.value for p in Protocol])

    with col2:
        packet_length = st.number_input("Packet Length (in bytes)", min_value=0)
        packet_type = st.selectbox("Packet Type", [t.value for t in PacketType])
        traffic_type = st.selectbox("Traffic Type", [t.value for t in TrafficType])


with st.container(border=True):
    st.markdown("### 🚨 **Alert Information**")
    col3, col4 = st.columns(2)
    with col3:
        ioc_detected = st.toggle("IoC Detected")
        alerts_warnings = st.toggle("Alerts or Warnings")

    with col4:
        firewall_logs = st.toggle("Firewall Log Present")
        ids_ips_alerts = st.toggle("IDS/IPS Alerts Raised")


with st.container(border=True):
    st.markdown("### 🖥️ **Device Information**")
    col5a, col6a = st.columns(2)
    with col5a:
        operation_system = st.selectbox("Operating System", [o.value for o in OperatingSystem], index=0)
        operation_system = st.selectbox("Device", [d.value for d in Device], index=0)

    with col6a:
        operation_system = st.selectbox("Browser", [b.value for b in Browser], index=0)


with st.container(border=True):
    st.markdown("### ⚖️ **Risk Assement**")
    col5a1, col6a2 = st.columns(2)
    with col5a1:
        anomaly_scores = st.number_input("Anomaly Scores", placeholder="e.g., high, medium, low")
        attack_signature = st.selectbox("Attack Signature", [s.value for s in AttackSignature], index=0)
        action_taken = st.selectbox("Action Taken", [a.value for a in ActionTaken], index=0)

    with col6a2:
        severity_level = st.selectbox("Severity Level", [s.value for s in ServiertyLevel], index=0)


with st.container(border=True):
    st.markdown("### 🌍 **Additional Information**")
    col5, col6 = st.columns(2)

    with col5:
        network_segment = st.selectbox("Network Segment", [n.value for n in NetworkSegment], index=0)

        proxy_information = st.toggle("Proxy Used")

    with col6:
        log_source = st.selectbox("Log Source", [ls.value for ls in LogSource], index=0)
        pass


with st.container(border=True):
    st.markdown("### 💀 **Attack Type**")
    col5, col6 = st.columns(2)
    with col5:
        model_option = st.selectbox("Select the machine learning model for prediction:", ["Decision Tree", "Random Forest", "Logistic Regression"])

        st.button(label="Predict")

    with col6:
        pass


# Create two columns for a cleaner layout


# Collect the data into a NetworkLogEntry dataclass


# if st.button('Predict'):
#     prediction = selected_model.predict(input_data)
#     result = 'Cyberattack Detected!' if prediction == 1 else 'No Cyberattack'
#     st.write(result)
