import dataclasses
from typing import Optional
from enum import Enum


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


class OperatingSystem(Enum):
    WINDOWS = "Windows"
    LINUX = "Linux"
    MAC_OS_X = "Mac OS X"
    ANDROID = "Android"
    IOS = "iOS"


class Browser(Enum):
    OPERA = "Opera"
    INTERNET_EXPLORER = "IE"
    CHROME = "Chrome"
    SAFARI = "Safari"
    FIREFOX = "Firefox"
    MOBILE_SAFARI = "Mobile Safari"
    FIREFOX_MOBILE = "Firefox Mobile"
    CHROME_MOBILE_IOS = "Chrome Mobile iOS"
    FIREFOX_IOS = "Firefox iOS"


class Device(Enum):
    PC = "PC"
    MAC = "Mac"
    GENERIC_SMARTPHONE = "Generic Smartphone"
    IPOD = "iPod"
    IPHONE = "iPhone"
    IPAD = "iPad"
    GENERIC_TABLET = "Generic Tablet"
    LG_UG = "LG UG"


@dataclasses.dataclass
class NetworkLogEntry:
    Hour: int
    Year: int
    Month: int
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    packet_length: int
    packet_type: str
    traffic_type: str
    payload_data: str
    severity_level: Optional[ServiertyLevel]
    network_segment: Optional[NetworkSegment]
    malware_indicators: Optional[str] = None
    anomaly_scores: Optional[str] = None
    alerts_warnings: Optional[str] = None
    attack_type: Optional[str] = None
    attack_signature: Optional[AttackSignature] = None
    action_taken: Optional[ActionTaken] = None
    proxy_information: Optional[str] = None
    firewall_logs: Optional[str] = None
    ids_ips_alerts: Optional[str] = None
