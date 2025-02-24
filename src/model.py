import dataclasses
import typing
from enum import Enum

# Define an Enum for Attack Types
class AttackType(Enum):
    DDoS = "DDoS"
    Malware = "Malware"
    Intrusion = "Intrusion"

class TrafficType(Enum):
    HTTP = "HTTP"
    FTP = "FTP"
    DNS = "DNS"

class Protocol(Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"


class ActionTaken(Enum):
    BLOCKED = "BlOCKED"



@dataclasses.dataclass
class NetworkLogEntry:
    timestamp: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    packet_length: int
    packet_type: str
    traffic_type: str
    payload_data: str
    malware_indicators: typing.Optional[str] = None
    anomaly_scores: typing.Optional[str] = None
    alerts_warnings: typing.Optional[str] = None
    attack_type: typing.Optional[str] = None
    attack_signature: typing.Optional[str] = None
    action_taken: typing.Optional[str] = None
    severity_level: typing.Optional[str] = None
    user_information: typing.Optional[str] = None
    device_information: typing.Optional[str] = None
    network_segment: typing.Optional[str] = None
    geo_location_data: typing.Optional[str] = None
    proxy_information: typing.Optional[str] = None
    firewall_logs: typing.Optional[str] = None
    ids_ips_alerts: typing.Optional[str] = None
