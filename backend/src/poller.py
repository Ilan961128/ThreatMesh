import subprocess
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
    Check if a host is reachable using ICMP ping.
    Returns:
        bool: True if host is online, False otherwise.
    """
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip_address],  # Linux/macOS
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        return result.returncode == 0  # If return code is 0, the host is up
    except Exception:
        return False

def poll_endpoint(ip_address: str) -> CollectedData:
    """
    Poll endpoint PC to collect system data.
    Args:
        ip_address (str): IP address of remote PC
    Raises:
        RequestException, KeyError
    Returns:
        CollectedData: Data about the PC
    """

    # Step 1: Check if IP is reachable
    if not is_host_alive(ip_address):
        logger.warning(f"[!] Skipping {ip_address}: Host is unreachable (ping failed)")
        raise RuntimeError(f"Host {ip_address} is not reachable")

    # Step 2: Poll if the host is alive
    try:
        url = POLL_URL.format(ip_address=ip_address, port=POLL_PORT)
        response = post(url, json={"command": "SCAN"}, timeout=TIMEOUT.total_seconds())
        response.raise_for_status()
        return CollectedData(**response.json()["data"])

    except (RequestException, KeyError) as e:
        logger.error(f"[!] Error polling < {ip_address} > : {str(e)}")
        raise
