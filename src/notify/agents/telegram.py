from src.abstraction.interface import IFaceNotify
import logging
import requests
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

logger = logging.getLogger("alertBot.telegram")


class Telegram(IFaceNotify):
    '''Telegram notification class'''

    def __init__(self, config):
        self.TOKEN = config.token
        self.CHAT_ID = config.chat_id

    def sendMessage(self, msg):
        '''Send Telegram message'''

        url = "https://api.telegram.org/bot{token}/sendMessage".format(token=self.TOKEN)
        parms = {
            "chat_id": self.CHAT_ID,
            "text": msg,

        }

        result = requests.get(url, params=parms)
        if result.json()["ok"] is False:
            # Debug something went wring
            logging.error("Telegram notification went bad..")
            #raise Exception("Telegram notification went bad..")
            return False

        return True

    def send_alert(self, msg, title):
        '''Uses the String representation of the message object to format the message'''

        # title = f"{title} Event\n"

        return self.sendMessage(title + str(msg))
