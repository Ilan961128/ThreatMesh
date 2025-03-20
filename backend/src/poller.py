import subprocess
import ipaddress
from datetime import timedelta
from requests import post
from requests.exceptions import RequestException
from loguru import logger
from src.collected_data import CollectedData

POLL_PORT = 6612
POLL_URL = "http://{ip_address}:{port}/"
TIMEOUT = timedelta(seconds=20)  # Keep 20s timeout since client takes time

def is_host_alive(ip_address: str) -> bool:
    """
    Check if a host is reachable using ICMP ping in Windows.
    Returns:
        bool: True if host is online, False otherwise.
    """
    try:
        # Convert IP from integer if needed
        if isinstance(ip_address, int):
            ip_address = str(ipaddress.ip_address(ip_address))

        logger.info(f"[DEBUG] Checking reachability for {ip_address}...")

        result = subprocess.run(
            ["ping", "-n", "1", "-w", "1000", ip_address],  # Windows ping command
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        logger.info(f"[DEBUG] Ping result for {ip_address}: {result.stdout.strip()}")

        if "Reply from" in result.stdout:
            logger.info(f"[✓] Host {ip_address} is reachable.")
            return True
        else:
            logger.warning(f"[!] Host {ip_address} is NOT reachable.")
            return False

    except Exception as e:
        logger.error(f"[!] Error checking host {ip_address}: {e}")
        return False

def poll_endpoint(ip_address: str):
    """
    Poll endpoint PC to collect system data.
    Args:
        ip_address (str): IP address of remote PC
    Returns:
        CollectedData: Data about the PC
    """
    try:
        # Convert integer to proper IP string if necessary
        if isinstance(ip_address, int):
            ip_address = str(ipaddress.IPv4Address(ip_address))

        url = POLL_URL.format(ip_address=ip_address, port=POLL_PORT)
        response = post(url, json={"command": "SCAN"}, timeout=TIMEOUT.total_seconds())
        response.raise_for_status()

        return CollectedData(**response.json()["data"])

    except (RequestException, KeyError, ValueError, RuntimeError) as e:
        logger.error(f"[!] Error polling < {ip_address} > : {str(e)}")
        raise