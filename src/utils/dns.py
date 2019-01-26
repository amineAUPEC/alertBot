import socket
import logging
from netaddr import IPNetwork, IPAddress, AddrFormatError

logger = logging.getLogger("alertBot.dns")


def get_hostname(ip: str):
    """ Reverse DNS """
    try:
        dns = socket.gethostbyaddr(ip)
        if not dns:
            return None

        try:
            if IPAddress(ip) in (IPNetwork("192.168.0.0/16") or IPNetwork("10.0.0.0/8") or IPNetwork("172.16.0.0/12")):
                logger.debug("IP %s is a rfc1918 address")
                return dns[0].split(".")[0]
            else:
                return dns[0]
        except AddrFormatError as e:
            logger.exception(msg=f"Error parsing receiving IP. Is {ip} an IP?", exc_info=True)
            raise e

    except socket.herror as e:
        logger.warning("No DNS found for %s. %s", ip, e)
        return None
