import argparse
import ipaddress
import logging


def network_args(string: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """
    Аргумент типа для сетевых адресов в формате CIDR. Возвращает объект ip_network.
    """
    try:
        return ipaddress.ip_network(string)
    except ValueError:
        msg = f"{string} is not a network address in CIDR format."
        logging.error(msg)
        raise argparse.ArgumentTypeError(msg)
