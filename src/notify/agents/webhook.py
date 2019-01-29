from src.abstraction.interface import IFaceNotify
import logging
import requests
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

logger = logging.getLogger("alertBot.webhook")


class Webhook(IFaceNotify):
    def __init__(self, config):
        # self.dest = config.destinations
        self.url = config.url

    def send_notification(self, msg, title: str):
        payload = {
            # "destinations": self.dest,
            "message": msg,
            "title": title
        }

        r = requests.post(url=self.url, json=payload)
        if r.status_code != 200:
            logger.warning("Webhook response code !=200. Status code: %d", r.status_code)
            return False
        return True
