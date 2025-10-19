# firewall_toolkit.py
from ipaddress import ip_address
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

ALLOWLIST = {"192.168.1.1", "10.0.0.1"}
DENYLIST = {"203.0.113.42"}  # example public IP

def is_valid_ip(addr: str) -> bool:
    try:
        ip_address(addr)
        return True
    except ValueError:
        return False

def apply_firewall_rules(ip: str) -> str:
    if not is_valid_ip(ip):
        logging.warning("Invalid IP provided: %s", ip)
        return "invalid"
    if ip in ALLOWLIST:
        logging.info("Allowing traffic from %s", ip)
        # call system firewall: e.g., nftables/iptables wrapper
        return "allowed"
    if ip in DENYLIST:
        logging.info("Blocking traffic from %s", ip)
        # call system firewall
        return "blocked"
    logging.info("Default policy applied to %s", ip)
    return "default"

if __name__ == "__main__":
    for ip in ["192.168.1.1", "10.0.0.1", "203.0.113.42", "not-an-ip"]:
        result = apply_firewall_rules(ip)
        print(ip, "->", result)
