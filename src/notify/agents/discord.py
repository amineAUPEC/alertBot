from src.abstraction.interface import IFaceNotify
import logging
import requests
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

logger = logging.getLogger("alertBot.discord")


class Discord(IFaceNotify):
    """ Discord notification class
        https://discordapp.com/developers/docs/resources/webhook#webhook-object
    """
    def __init__(self, discord_config):
        self.discord_url = discord_config.webhookUrl  # str - url
        self.use_embed = discord_config.useEmbed  # Bool
        self.blacklisted_fields = discord_config.blackListedFields  # List
        self.msg_max_len = 2000

    def _send_discord_message(self, data: dict) ->bool:
        """ Simply sends the Discord message using Discord API """
        result = requests.post(self.discord_url, json=data)
        if result.status_code == 204:
            logger.debug("Discord post message succeeded")
            return True

        elif result.status_code == 429:
            # This could be 'catched' and queued -- future work..
            logger.warning("Too many request aka we got rate limited")
            logger.debug("json response: %s", result.json())
            return False
        else:
            logging.error("Error on Discord post message: %s", result.content)
            return False

    def _generate_embeded(self, msg: dict, title: str) -> dict:
        """ Generate Discord embed message. See Discord API for more info. """
        snort_img = "https://blog.rapid7.com/content/images/kk-img/2017/01/thumb-snort.jpg"
        suricata_img = "https://idsips.files.wordpress.com/2015/10/suri-400x400.png?w=300"
        avatar_url = "https://www.actiontec.com/wp-content/uploads/2018/04/hacker-300x215.jpg"
        icon_url = avatar_url  # just a default icon..
        if "snort" in title.lower():
            icon_url = snort_img
        elif "suricata" in title.lower():
            icon_url = suricata_img

        webhook_obj = {
            "username": "AlertBot",
            "avatar_url": avatar_url,
            "embeds": []
        }
        embed = {
            "color": 16711680,
            "author": {
                "name": title,
                "icon_url": icon_url
            },
            "fields": []
        }

        fields = []
        for k, v in msg.items():
            if k not in self.blacklisted_fields:
                fields.append({
                    "name": k.title(),
                    "value": v
                })
        embed["fields"] = fields
        webhook_obj["embeds"].append(embed)

        return webhook_obj

    def _check_message_len(self, message: str) -> str:
        """ Discord message max length is 2000 (chars?)"""
        fixed_message = message
        if len(message) >= self.msg_max_len:  # max allowed length
            logger.debug(f"Discord message is over max len '{self.msg_max_len}'. Formatting..")
            fixed_message = "".join(message[:self.msg_max_len-50] + "<msg too long for discord>")

        return fixed_message

    def send_alert(self, msg, title: str):
        """ The callable 'send message' function used by the interface """
        msg_data_obj = {}
        # Since we want in some cases to just send a normal 'string' message or
        # generate the message by supplied dictionary we need to check the 'msg' arg type and go from there..
        if isinstance(msg, dict):
            # If embed message is enabled we create an embed message.
            if self.use_embed:
                msg_data_obj = self._generate_embeded(msg, title)
            else:
                formatted_message = "\n".join(f"{field_name.title()}: {value}" for field_name, value in msg.items()
                                              if field_name not in self.blacklisted_fields)  # join() ends

                msg_data_obj['content'] = "```== %s ==\n%s```" % (title, self._check_message_len(formatted_message))
                msg_data_obj['username'] = "AlertBot"
        else:
            # Send a 'normal' string message in a 'code block'
            msg_data_obj['content'] = "```== %s ==\n%s```" % (title, self._check_message_len(msg))
            msg_data_obj['username'] = "AlertBot"

        return self._send_discord_message(data=msg_data_obj)

