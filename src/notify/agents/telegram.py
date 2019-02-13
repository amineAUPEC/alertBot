from src.abstraction.interface import IFaceNotify
import logging
import requests
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

logger = logging.getLogger("alertBot.telegram")


class Telegram(IFaceNotify):
    """ Telegram notification class """

    def __init__(self, config):
        self.token = config.token
        self.chat_id = config.chat_id
        self.blacklisted_fields = config.blackListedFields  # List
        self.url = f"https://api.telegram.org/bot{self.token}/sendMessage"

    def send_telegram_message(self, msg: str) -> bool:
        """ Send Telegram message """

        params = {
            "chat_id": self.chat_id,
            "text": msg
        }

        result = requests.get(self.url, params=params)
        logger.debug(result.url)

        json_response = result.json()
        if json_response["ok"] is False:
            # Debug something went wring
            logger.debug(result.text)
            logging.error("Telegram notification went bad..")
            logger.error("Telegram Response: %s", json_response)
            return False

        return True

    def send_notification(self, msg, title: str):
        """ Uses the String representation of the message object to send Telegram message """
        telegram_message = "Empty msg, wtf!?"
        # Since we want in some cases to just send a normal 'string' message or
        # generate the message by supplied dictionary we need to check the 'msg' arg type and go from there..
        if isinstance(msg, dict):
            formatted_message = "\n".join(f"{field_name.title()}: {value}" for field_name, value in msg.items()
                                          if field_name not in self.blacklisted_fields)  # join() ends

            # telegram_message = "AlertBot\n\n" + title + formatted_message
            telegram_message = f"AlertBot\n== {title} ==\n{formatted_message}"
        else:
            # Send a 'normal' string message
            # telegram_message = title + msg
            telegram_message = f"AlertBot\n== {title} ==\n{msg}"

        return self.send_telegram_message(telegram_message)
