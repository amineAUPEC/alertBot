from src.notify.notify import NotifyInterface
import logging
import requests
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

logger = logging.getLogger("alertBot.webhook")


class Webhook(NotifyInterface):
    def __init__(self, config):
        self.dest = config.destinations
        self.url = config.url

    def sendalert(self, msg, title):
        payload = {
            "destinations": self.dest,
            "message": msg,
            "title": title
        }

        r = requests.post(url=self.url, json=payload)
        if r.status_code != 200:
            logger.warning("Webhook response code !=200. Status code: %d", r.status_code)
            return False
        # Return is never checked..
        return True
