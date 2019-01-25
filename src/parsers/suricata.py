import re
import json
import datetime
import logging

logger = logging.getLogger("alertBot.suricata")


class Suricata:

    def __init__(self):
        # Copied from snort. Needs to be checked..
        self.pattern = re.compile(
            r"(?P<time>\d+\/\d+\/\d+-\d+:\d+:\d+\.\d+)\s,"  # time
            r"(?P<sid>\d+,\d+),"  # Signature SID
            r"(?P<rev>\d+),"  # Revision - ??
            r"\"(?P<name>.*?)\","  # Alert name
            r"(?P<proto>TCP|UDP|ICMP|.?),"  # Protocol
            r"(?P<src>\d+\.\d+\.\d+\.\d+),"  # Src IP
            r"(?P<src_port>\d+|.?),"  # Src port
            r"(?P<dst>\d+\.\d+\.\d+\.\d+),"  # Dst IP
            r"(?P<dst_port>\d+|.?),"  # Dst port
            r"\d+,"  # Unknown stuff
            r"(?P<class>[a-zA-Z0-9-_ ]+),"  # Alert class
            r"(?P<pri>\d+)"  # Priority
        )

    def eve_json(self, line: str):
        alert = json.loads(line)

        # since eve.json dont always contains alerts..
        if alert["event_type"] != "alert":
            # not an alert..
            logger.debug("not an alert - event_type: %s", alert["event_type"])
            return None

        # try:
        new_alert = {
            "time": datetime.datetime.strptime(alert['timestamp'][:-5],
                                               "%Y-%m-%dT%H:%M:%S.%f").strftime("%Y-%m-%d %H:%M:%S"),
            "name": alert['alert']['signature'],
            "src": alert['src_ip'],
            "src_port": alert['src_port'],
            "dst": alert['dest_ip'],
            "dst_port": alert['dest_port'],
            "proto": alert['proto'],
            "action": alert["alert"]["action"],
            "payload": alert['payload'] if alert['payload'] else ""
        }

        # Request by alex.. thanks for messy code..
        try:
            new_alert["hostname"] = alert["http"]["hostname"]
        except KeyError as ke:
            logger.debug("Alert dont contain http hostname field..")

        try:
            new_alert["url"] = alert["http"]["url"]
        except KeyError as ke:
            logger.debug("Alert dont contain http url field..")

        try:
            new_alert["http_refer"] = alert["http"]["http_refer"]
        except KeyError as ke:
            logger.debug("Alert dont contain http http_refer field..")

        try:
            new_alert["http_method"] = alert["http"]["http_method"]
        except KeyError as ke:
            logger.debug("Alert dont contain http http_method field..")

        try:
            new_alert["http_user_agent"] = alert["http"]["http_user_agent"]
        except KeyError as ke:
            logger.debug("Alert dont contain http http_method field..")

        return new_alert

        #except KeyError as ke:
        #    logger.error(ke)
        #    logger.debug(line)

    def full_log(self, line: str) -> dict:
        # Parse snort version 2 alerts/logs

        try:
            match = self.pattern.match(line)
            if not match:
                # Send notification when nothing matches..
                logger.error(f"No match for line. This should not happen! \n{line}")
                exit(1)

            return match.groupdict()

        except re.error as rexerror:
            logger.error(rexerror)
            exit(1)

    def fast_log(self, line: str) -> dict:
        pass
