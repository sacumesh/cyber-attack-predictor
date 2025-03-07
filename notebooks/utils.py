from uaparser import UAParser as parse_ua
import pandas as pd
from enum import Enum


# Enum for information types
class InfoType(Enum):
    OS = "OS"
    BROWSER = "Browser"
    DEVICE = "Device"


class PacketLengthCategorizer:
    # Class variables (shared across all instances of the class)
    bins = [0, 64, 512, 1023, 1499, float('inf')]
    labels = ['Small', 'Medium', 'Large', 'Very Large', 'Huge']

    @classmethod
    def categorize_packet_length(cls, packet_length: str) -> str:
        try:
            packet_length = int(packet_length)
        except ValueError:
            raise ValueError(f"Invalid packet length: {packet_length}")

        # Use pd.cut to categorize packet_length into the bins
        category = pd.cut([packet_length], bins=cls.bins,
                          labels=cls.labels, right=False)

        return category[0]  # Return the category label for the packet length


def extract_device_information(device_info: str, info_type: InfoType) -> str:
    device_info = device_info
    parsed_ua = parse_ua(device_info)

    if info_type == InfoType.OS:
        return _extract_os(parsed_ua)
    elif info_type == InfoType.BROWSER:
        return _extract_browser(parsed_ua)
    elif info_type == InfoType.DEVICE:
        return _extract_device(parsed_ua)
    else:
        raise ValueError(f"Unsupported InfoType: {info_type}")


def is_after_support_end(attack_year: int, end_support_year) -> int:
    return 1 if attack_year >= end_support_year else 0


def categorize_port(port: int):
    if 0 <= port <= 1023:
        return 'SystemPorts'
    elif 1024 <= port <= 49151:
        return 'UserPorts'
    elif 49152 <= port <= 65535:
        return 'Dynamic'
    else:
        return 'Unknow'


def _extract_os(parsed_ua) -> str:
    os_name = parsed_ua.os['name']
    os_version = parsed_ua.os['version']
    version = os_version.split(".")[0]  # Get the major version
    return f"{os_name} {version}"


def _extract_browser(parsed_ua) -> str:
    browser_name = parsed_ua.browser['name']
    browser_version = parsed_ua.browser['version']
    version = browser_version.split(".")[0]  # Get the major version
    return f"{browser_name} {version}"


def _extract_device(parsed_ua) -> str:
    device_type = parsed_ua.device['type']
    if device_type is None:
        device_type = "computer"
    return device_type
