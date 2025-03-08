from dataclasses import dataclass
from typing import Optional
from enum import Enum
from datetime import datetime


# Define an Enum for Attack Types
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


class ABC(object):
    __columns = {
        "Hour",
        "Month",
        "Alert Count",
        "Is Proxy Used_0",
        "Is Proxy Used_1",
        "Packet Length Category_Huge",
        "Packet Length Category_Large",
        "Packet Length Category_Medium",
        "Packet Length Category_Small",
        "Packet Length Category_Very Large",
        "Network Segment_Segment A",
        "Network Segment_Segment B",
        "Network Segment_Segment C",
        "Anomaly Scores",
        "Action Taken",
    }

    def __init__(self, network_log: NetworkLogEntry):

        column_dict = {col: None for col in self.__columns}

        column_dict["Hour"] = network_log.attack_time.hour
        column_dict["Month"] = network_log.attack_date.month
        column_dict["Alert Count"] = 6
        column_dict["Is Proxy Used_0"] = None
        column_dict["Is Proxy Used_1"] = None
        column_dict["Packet Length Category_Huge"] = None
        column_dict["Packet Length Category_Large"] = None
        column_dict["Packet Length Category_Medium"] = None
        column_dict["Packet Length Category_Small"] = None
        column_dict["Packet Length Category_Very Large"] = None
        column_dict["Network Segment_Segment A"] = None
        column_dict["Network Segment_Segment B"] = None
        column_dict["Network Segment_Segment C"] = None
        column_dict["Anomaly Scores"] = None
        column_dict["Action Taken"] = None
