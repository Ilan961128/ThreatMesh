import ipaddress
from datetime import datetime

def is_ipaddress(ip_address: str) -> bool:
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

def is_date(date: str) -> bool:
    try:
        datetime.strptime(date, r"%d%m%Y")
        return True
    except ValueError:
        return False