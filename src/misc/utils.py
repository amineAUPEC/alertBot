import socket
import logging
from netaddr import IPAddress, AddrFormatError


logger = logging.getLogger("alertBot.utils")


def get_hostname(ip: str) -> str:
    """ Reverse DNS """
    try:
        dns = socket.gethostbyaddr(ip)
        if not dns:
            return "No rv DNS"

        if IPAddress(ip):
            return dns[0]

    except socket.herror as e:
        logger.warning("No DNS found for %s. %s", ip, e)
        return "No rv DNS"
    except AddrFormatError as e:
        logger.exception(msg=f"Error parsing receiving IP. Is {ip} an IP?", exc_info=True)
        raise e


def url_sanitizer(url: str) -> str:
    logger.debug("URl before sanitizing: %s", url)

    sanitized_url = url.replace("http", "hxxp").replace("https", "hxxps").replace(".", "[.]")
    logger.debug("URl after sanitizing: %s", sanitized_url)
    return sanitized_url

