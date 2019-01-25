from src.notify.notify import NotifyInterface
import logging
import requests
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()


logger = logging.getLogger("alertBot.discord")


class Discord(NotifyInterface):
    def __init__(self, config):
        self.URL = config.webhookUrl
        self.DATA = {}

    def sendDiscordMessage(self):
        result = requests.post(self.URL, json=self.DATA)
        if result.status_code == 204:
            # debug logger
            return True

        elif result.status_code == 429:
            # This could be "catched" and queued -- future work..
            logger.warning("Too many request aka rate limited")
            return False
        else:
            logging.error("Error on Discord post message: ", result.content)

    def sendalert(self, msg, title):
        # Set the username of the discord post and format message
        msg_maxlen = 2000
        if len(msg) >= msg_maxlen:  # max allowed lenght
            msg = "".join(msg[:msg_maxlen-50] + "<msg too long for discord>")

        self.DATA['content'] = "```%s```" % str(msg)
        self.DATA['username'] = title

        return self.sendDiscordMessage()


