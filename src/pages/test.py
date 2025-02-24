import streamlit as st
from model import Protocol, TrafficType, ActionTaken, AttackType
import pandas as pd



def single_prediction_form():
    col1, col2 = st.columns(2)

    with col1:
        timestamp = st.text_input('Timestamp (e.g., 2025-02-24 12:00:00)', placeholder="YYYY-MM-DD HH:MM:SS")
        source_ip = st.text_input('Source IP', placeholder="e.g., 192.168.1.1")
        destination_ip = st.text_input('Destination IP', placeholder="e.g., 192.168.1.2")
        source_port = st.number_input('Source Port', min_value=0, max_value=65535)
        destination_port = st.number_input('Destination Port', min_value=0, max_value=65535)
        protocol = st.selectbox('Protocol', [p.value for p in Protocol])

    with col2:
        packet_length = st.number_input('Packet Length (in bytes)', min_value=0)
        packet_type = st.text_input('Packet Type (e.g., SYN, ACK)', placeholder="e.g., SYN")
        traffic_type = st.selectbox('Traffic Type', [t.value for t in TrafficType])
        payload_data = st.text_area('Payload Data', height=80, placeholder="Detailed information about the packet's payload...")

    st.markdown("### ⚠️ **Attack Information**")

    # Grouping attack-related inputs
    col3, col4 = st.columns(2)

    with col3:
        malware_indicators = st.text_input('Malware Indicators', placeholder="e.g., trojan")
        anomaly_scores = st.text_input('Anomaly Scores', placeholder="e.g., high, medium, low")
        attack_type = st.selectbox('Attack Type', [t.value for t in AttackType], index=0)
        attack_signature = st.text_input('Attack Signature', placeholder="e.g., DDoS signature")

    with col4:
        alerts_warnings = st.text_input('Alerts or Warnings', placeholder="e.g., unusual traffic detected")
        action_taken = st.selectbox('Action Taken', [a.value for a in ActionTaken], index=0)
        severity_level = st.text_input('Severity Level', placeholder="e.g., high, medium, low")
        user_information = st.text_input('User Information', placeholder="e.g., admin")
        device_information = st.text_input('Device Information', placeholder="e.g., server1")

    st.markdown("### 🌍 **Additional Information**")

    # Additional information related to network/log
    network_segment = st.text_input('Network Segment', placeholder="e.g., DMZ")
    geo_location_data = st.text_input('Geo Location Data', placeholder="e.g., USA")
    proxy_information = st.text_input('Proxy Information', placeholder="e.g., Proxy X")
    firewall_logs = st.text_input('Firewall Logs', placeholder="e.g., blocked IPs")
    ids_ips_alerts = st.text_input('IDS/IPS Alerts', placeholder="e.g., suspicious login attempt")
    pass



def batch_prediction_form():
    st.markdown("### 📂 **Upload CSV File with Multiple Log Entries**")
    uploaded_file = st.file_uploader("Choose a CSV file", type="csv")

    if uploaded_file is not None:
        # Read the CSV file into a DataFrame
        df = pd.read_csv(uploaded_file)
        
        # Show the first few rows of the uploaded CSV for confirmation
        st.write("### Preview of Uploaded CSV:", df.head())

st.title('🔐 **Cyber Attack Prediction**')

st.markdown("""
    Welcome to the **Cyber Attack Prediction App**! This tool predicts whether a given network log entry represents a cyberattack.
    Please select a model, fill in the details below, or upload a file to predict multiple entries at once. 🛡️
""")

model_option = st.selectbox(
    'Select the machine learning model for prediction:',
    ['Decision Tree', 'Random Forest', 'Logistic Regression']
    )

prediction_option = st.radio(
        "Choose input method:",
        ('Single Log Prediction', 'Multiple Log Prediction (File Upload)')
    )


if prediction_option == 'Single Log Prediction':
    single_prediction_form()
else:
    batch_prediction_form()


# Create two columns for a cleaner layout


# Collect the data into a NetworkLogEntry dataclass


# if st.button('Predict'):
#     prediction = selected_model.predict(input_data)
#     result = 'Cyberattack Detected!' if prediction == 1 else 'No Cyberattack'
#     st.write(result)