import pandas as pd
from dataclasses import dataclass
from enum import Enum
from datetime import datetime


class AttackType(Enum):
    DDOS = "DDoS"
    MALWARE = "Malware"
    INTRUSION = "Intrusion"


class TrafficType(Enum):
    HTTP = "HTTP"
    FTP = "FTP"
    DNS = "DNS"


class Protocol(Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"


class PacketType(Enum):
    CONTROL = "Control"
    DATA = "Data"


class AttackSignature(Enum):
    PATTERN_A = "Known Pattern A"
    PATTERN_B = "Known Pattern B"


class ActionTaken(Enum):
    BLOCKED = "Blocked"
    IGNORED = "Ignored"
    LOGGED = "Logged"


class ServiertyLevel(Enum):
    HIGH = "High"
    LOW = "Low"
    MEDIUM = "Medium"


class NetworkSegment(Enum):
    SEGMENT_A = "Segment A"
    SEGMENT_B = "Segment B"
    SEGMENT_C = "Segment C"


class LogSource(Enum):
    SERVER = "Server"
    FIREWALL = "Firewall"


class MalwareIndicators(Enum):
    IOC_DETECTED = "IoC Detected"
    NO_DETECTION = "No Detection"


class FirewallLog(Enum):
    LOG_DATA = "Log Data"
    NO_LOG_DATA = "No Log Data"


class AlertsWarnings(Enum):
    NO_ALERT_TRIGGERED = "No Alert Triggered"
    ALERT_TRIGGERED = "Alert Triggered"


class IDS_IPS_Alerts(Enum):
    NO_ALERT_DATA = "No Alert Data"
    ALERT_DATA = "Alert Data"


class Is_Proxy_Used(Enum):
    YES = "Yes"
    NO = "No"


class Device(Enum):
    PC = "PC"
    MOBILE = "mobile"
    TABLET = "tablet"


class OperatingSystem(Enum):
    WINDOWS = "Windows"
    LINUX = "Linux"
    MAC_OS = "Mac OS"
    IOS = "iOS"
    ANDROID = "Android"


class Browser(Enum):
    CHROME = "Chrome"
    OPERA = "Opera"
    INTERNET_EXPLORER = "IE"
    FIREFOX = "Firefox"
    SAFARI = "Safari"
    MOBILE_SAFARI = "Mobile Safari"


@dataclass(frozen=True)
class NetworkLogEntry:
    # Date and Time Info
    attack_date: datetime
    attack_time: datetime

    # IP Packet Info
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    packet_length: int
    packet_type: str
    traffic_type: str

    # Alert Info
    ioc_detected: str
    ids_ips_alerts: str
    alerts_warnings: str
    firewall_log: str

    # Device Info
    operating_system: str
    browser: str
    device: str

    # Risk Assement
    anomaly_scores: str
    attack_signature: str
    action_taken: str
    severity_level: str

    # Additional Informaiton
    network_segment: str
    proxy_information: str
    log_source: str


class NetworkFeatureExtractor(object):
    ANOMALY_SCORES_MEAN = 50.113473
    ANOMALY_SCORES_STD_DEV = 28.853598

    PACKET_LENGTH_MEAN = 781.452725
    PACKET_LENGTH_STD_DEV = 416.044192

    SEVERITY_LEVEL_ORD_DICT = {"Low": 0, "Medium": 1, "High": 2}

    ORD_ATTACK_TYPE_DICT = {0: "DDoS", 1: "Malware", 2: "Intrusion"}

    PACKET_LENGTH_RANGES = {
        "bins": [0, 64, 512, 1023, 1499, float("inf")],
        "labels": ["Small", "Medium", "Large", "Very Large", "Huge"],
    }

    PORT_CATEGORIES = {
        # -1 ensures ports < 0 are handled
        "bins": [-1, 1023, 49151, 65535, float("inf")],
        "labels": ["SystemPorts", "UserPorts", "Dynamic", "Unknown"],
    }

    IP_CLASSES = {
        "bins": [0, 126, 191, 223, 239, 255],
        "labels": ["Class A", "Class B", "Class C", "Class D", "Class E"],
    }

    MODEL_FEATURE_NAMES_IN = [
        "Alerts/Warnings_No Alert Triggered",
        "Browser_Firefox",
        "Browser_IE",
        "Browser_Mobile Safari",
        "Browser_Opera",
        "Browser_Safari",
        "Destination Port Category_UserPorts",
        "Device_mobile",
        "Device_tablet",
        "Log Source_Server",
        "Packet Length",
        "Packet Length Category_Huge",
        "Packet Length Category_Large",
        "Packet Length Category_Medium",
        "Packet Length Category_Very Large",
    ]

    def __init__(self, network_log: NetworkLogEntry):
        self.network_log = network_log

    def extract(self):
        nt_log = self.network_log

        month = nt_log.attack_date.month
        year = nt_log.attack_date.year
        hour = nt_log.attack_time.hour
        day_of_week = nt_log.attack_date.weekday()

        raw_features = {
            "Protocol": nt_log.protocol,
            "Packet Length": self.z_packet_length(nt_log.packet_length),
            "Packet Type": nt_log.packet_type,
            "Traffic Type": nt_log.traffic_type,
            "Malware Indicators": type(self).label_malware_indicators(
                nt_log.ioc_detected
            ),
            "Anomaly Scores": self.z_anomaly_scores(nt_log.anomaly_scores),
            "Alerts/Warnings": type(self).label_alerts_warnings(nt_log.alerts_warnings),
            "Attack Signature": nt_log.attack_signature,
            "Action Taken": nt_log.action_taken,
            "Severity Level": self.ord_severity_level(nt_log.severity_level),
            "Network Segment": nt_log.network_segment,
            "Firewall Logs": type(self).label_firewall_logs(nt_log.firewall_log),
            "IDS/IPS Alerts": type(self).label_ids_ips_alerts(nt_log.ids_ips_alerts),
            "Log Source": nt_log.log_source,
            "Source IP Class": self.get_ip_class(nt_log.source_ip),
            "Destination IP Class": self.get_ip_class(nt_log.destination_ip),
            "OS": nt_log.operating_system,
            "Browser": nt_log.browser,
            "Device": nt_log.device,
            "Source Port Category": self.categorize_port(nt_log.source_port),
            "Destination Port Category": self.categorize_port(nt_log.destination_port),
            "Year": year,
            "Month": month,
            "Hour": hour,
            "DayOfWeek": day_of_week,
            "Packet Length Category": self.categorize_packet_length(
                nt_log.packet_length
            ),
            "Is Proxy Used": self.label_proxy_info(nt_log.proxy_information),
        }

        encoded_features = {
            f"{k}_{v}" if isinstance(v, str) else k: 1 if isinstance(v, str) else v
            for k, v in raw_features.items()
        }

        model_input_features = {
            f: encoded_features.get(f, 0) for f in self.MODEL_FEATURE_NAMES_IN
        }

        df = pd.DataFrame([model_input_features])

        return df

    @classmethod
    def get_ip_class(cls, ip_address: str):
        first_octet = int(ip_address.split(".")[0])

        category = pd.cut(
            [first_octet], bins=cls.IP_CLASSES["bins"], labels=cls.IP_CLASSES["labels"]
        )

        return category[0]

    @classmethod
    def label_attack_type(cls, value: int):
        attack_type = cls.ORD_ATTACK_TYPE_DICT.get(value)
        return attack_type

    @classmethod
    def categorize_port(cls, port: int):
        category = pd.cut(
            [port],
            bins=cls.PORT_CATEGORIES["bins"],
            labels=cls.PORT_CATEGORIES["labels"],
        )

        return category[0]

    @classmethod
    def categorize_packet_length(cls, value: int):
        category = pd.cut(
            [value],
            bins=cls.PACKET_LENGTH_RANGES["bins"],
            labels=cls.PACKET_LENGTH_RANGES["labels"],
        )

        return category[0]

    @classmethod
    def z_anomaly_scores(cls, value: float):
        if cls.ANOMALY_SCORES_MEAN == 0:
            return 0
        z_value = (value - cls.ANOMALY_SCORES_MEAN) / cls.ANOMALY_SCORES_STD_DEV

        return z_value

    @classmethod
    def z_packet_length(cls, value: float):
        if cls.PACKET_LENGTH_STD_DEV == 0:
            return 0
        z_value = (value - cls.PACKET_LENGTH_MEAN) / cls.PACKET_LENGTH_STD_DEV

        return z_value

    @classmethod
    def ord_severity_level(cls, value: str):
        ord_value = cls.SEVERITY_LEVEL_ORD_DICT.get(value, None)

        return ord_value

    @staticmethod
    def label_proxy_info(value: str):
        result = Is_Proxy_Used.YES if value else Is_Proxy_Used.NO

        return result.value

    @staticmethod
    def label_malware_indicators(value):
        result = (
            MalwareIndicators.IOC_DETECTED if value else MalwareIndicators.NO_DETECTION
        )

        return result.value

    @staticmethod
    def label_alerts_warnings(value):
        result = (
            AlertsWarnings.ALERT_TRIGGERED
            if value
            else AlertsWarnings.NO_ALERT_TRIGGERED
        )

        return result.value

    @staticmethod
    def label_firewall_logs(value):
        result = FirewallLog.LOG_DATA if value else FirewallLog.NO_LOG_DATA

        return result.value

    @staticmethod
    def label_ids_ips_alerts(value):
        result = IDS_IPS_Alerts.ALERT_DATA if value else IDS_IPS_Alerts.NO_ALERT_DATA

        return result.value
