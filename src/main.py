import streamlit as st
import datetime
from model import (
    Protocol,
    TrafficType,
    ActionTaken,
    PacketType,
    AttackSignature,
    ServiertyLevel,
    NetworkSegment,
    LogSource,
    NetworkLogEntry,
    Device,
    OperatingSystem,
    Browser,
)
from service import predict_attack_type, is_valid_ip


def cyber_attack_dashboard():
    @st.dialog("🛡️ Attack Type")
    def display_attack_type(attack_type):
        # Dictionary mapping attack types to emojis
        attack_emojis = {"Intrusion": "🔓", "DDoS": "🌐", "Malware": "💻"}

        # Display the attack type with its emoji
        if attack_type in attack_emojis:
            attack_text = f"<h1 style='text-align: center; font-size: 40px;'>{attack_emojis[attack_type]} {attack_type}</h1>"
            st.markdown(attack_text, unsafe_allow_html=True)
        else:
            unknown_attack_text = "<h1 style='text-align: center; font-size: 40px; color: red;'>⚠️ Unknown attack type. Please enter a valid attack type.</h1>"
            st.markdown(unknown_attack_text, unsafe_allow_html=True)

    @st.dialog("❌")
    def invalid_dialog(msg):
        st.markdown(msg)

    st.title("🔐 **Cyber Attack Prediction**")

    st.markdown("""
        🛡️ Welcome to the **Cyber Attack Prediction App**! This tool predicts whether a given network log entry represents a cyberattack. 
    """)

    with st.container(border=True):
        st.markdown("### 📅 **Date and Time Information**")
        col1, col2 = st.columns(2)
        with col1:
            attack_date = st.date_input(
                "Date",
                datetime.date(2020, 1, 1),
                min_value=datetime.datetime(2020, 1, 1),
                max_value=datetime.datetime(2023, 12, 31),
            )

        with col2:
            attack_time = st.time_input("Time", datetime.time(8, 45))

    with st.container(border=True):
        st.markdown("### 📦 **Packet Information**")
        col3, col4 = st.columns(2)
        with col3:
            source_ip = st.text_input("Source IP", placeholder="e.g., 192.168.1.1")
            destination_ip = st.text_input(
                "Destination IP", placeholder="e.g., 192.168.1.2"
            )
            source_port = st.number_input(
                "Source Port", min_value=1025, max_value=65535, value=None
            )
            destination_port = st.number_input(
                "Destination Port", min_value=1025, max_value=65535, value=None
            )
            protocol = st.selectbox("Protocol", [p.value for p in Protocol])

        with col4:
            packet_length = st.number_input(
                "Packet Length (in bytes)", min_value=0, max_value=1500, value=None
            )
            packet_type = st.selectbox("Packet Type", [t.value for t in PacketType])
            traffic_type = st.selectbox("Traffic Type", [t.value for t in TrafficType])

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
                "Operating System", [o.value for o in OperatingSystem], index=0
            )
            device = st.selectbox("Device", [d.value for d in Device], index=0)

        with col8:
            browser = st.selectbox("Browser", [b.value for b in Browser], index=0)

    with st.container(border=True):
        st.markdown("### ⚖️ **Risk Assement**")
        col9, col10 = st.columns(2)
        with col9:
            anomaly_scores = st.number_input(
                "Anomaly Scores", min_value=100, max_value=100
            )
            attack_signature = st.selectbox(
                "Attack Signature", [s.value for s in AttackSignature], index=0
            )
            action_taken = st.selectbox(
                "Action Taken", [a.value for a in ActionTaken], index=0
            )

        with col10:
            severity_level = st.selectbox(
                "Severity Level", [s.value for s in ServiertyLevel], index=0
            )

    with st.container(border=True):
        st.markdown("### 🌍 **Additional Information**")
        col11, col12 = st.columns(2)

        with col11:
            network_segment = st.selectbox(
                "Network Segment", [n.value for n in NetworkSegment], index=0
            )

            proxy_information = st.toggle("Proxy Used")

        with col12:
            log_source = st.selectbox(
                "Log Source", [ls.value for ls in LogSource], index=0
            )

    with st.container(border=True):
        st.markdown("### 💀 **Attack Type**")
        col5, col6 = st.columns(2)
        with col5:
            predict_btn = st.button(label="Predict")

            if predict_btn:
                if not is_valid_ip(source_ip):
                    invalid_dialog(
                        "⚠️ Invalid Source IP, The source IP address is invalid. Please enter a valid IP address (e.g., 192.168.1.1). Loopback addresses (127.x.x.x) are not allowed."
                    )
                    return

                if not is_valid_ip(destination_ip):
                    invalid_dialog(
                        "⚠️ Invalid Destination IP, The destination IP address is invalid. Please enter a valid IP address (e.g., 192.168.1.2). Loopback addresses (127.x.x.x) are not allowed."
                    )
                    return

                if not source_port:
                    invalid_dialog(
                        "⚠️ No Source Port found, please enter a Source Port."
                    )
                    return

                if not destination_port:
                    invalid_dialog(
                        "⚠️ No Destination Port found, please enter a Destination Port."
                    )
                    return

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
                attack_type = predict_attack_type(network_entry)
                display_attack_type(attack_type)

        with col6:
            pass


def main():
    cyber_attack_dashboard()


if __name__ == "__main__":
    main()
