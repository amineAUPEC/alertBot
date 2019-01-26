import re
import json
import datetime
import logging

from src.notify import Notification

logger = logging.getLogger("alertBot.suricata")


class Suricata:
    """ Suricata parser class """

    def __init__(self, notify_enabled=False, dateformat: str = ""):
        # Copied from snort. Needs to be checked..
        self._pattern_full = re.compile(
            r"(?P<time>\d+\/\d+\/\d+-\d+:\d+:\d+\.\d+)\s,"  # time
            r"(?P<gid>\d+),"  # Signature GID
            r"(?P<sid>\d+),"  # Signature SID
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
        self._pattern_fast = re.compile(
            r"(?P<time>\d{2}\/\d{2}\/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
            r"\[\*\*\]\s+\[\d+:(?P<sid>\d+):(?P<revision>\d+)\] "
            r"(?P<name>.+) \[\*\*\]\s+(\[Classification: (?P<classtype>.+)\] )?"
            r"\[Priority: (?P<priority>\d+)\] \{(?P<protocol>[:a-zA-Z0-9_-]+)\} "
            r"(?P<src>.+) \-\> (?P<dest>.+)"
        )

        # Output date format - see datetime for formatting options
        self._dateformat = "%Y-%m-%d %H:%M:%S.%f"
        if dateformat:
            self._dateformat = dateformat

        self.isNotify_enabled = notify_enabled

    def eve_json(self, line: str):
        """ Eve.json 'parser' """

        alert = json.loads(line)

        # Since eve.json don't always contains alerts..
        try:
            if alert["event_type"] != "alert":
                logger.debug("Event_type is not 'alert': %s", alert["event_type"])
                return None
        except KeyError:
            # Some Suricata alerts don't have 'event_type'. Suricata trash that we dont care about any way..
            logger.debug("Line did not contain 'event_type'. %s", line)
            return None

        new_alert = {
            "time": datetime.datetime.strptime(alert['timestamp'][:-5],
                                               "%Y-%m-%dT%H:%M:%S.%f").strftime(self._dateformat),
            "name": alert['alert']['signature'],
            "src": alert['src_ip'],
            "src_port": alert['src_port'],
            "dest": alert['dest_ip'],
            "dest_port": alert['dest_port'],
            "proto": alert['proto'],
            "action": alert["alert"]["action"],
            "payload": alert['payload'] if alert['payload'] else ""
        }

        # Request by alex.. thanks for messy code..
        try:
            new_alert["hostname"] = alert["http"]["hostname"]
        except KeyError:
            logger.debug("Alert dont contain http hostname field..")

        try:
            new_alert["url"] = alert["http"]["url"]
        except KeyError:
            logger.debug("Alert dont contain http url field..")

        try:
            new_alert["http_refer"] = alert["http"]["http_refer"]
        except KeyError:
            logger.debug("Alert dont contain http http_refer field..")

        try:
            new_alert["http_method"] = alert["http"]["http_method"]
        except KeyError:
            logger.debug("Alert dont contain http http_method field..")

        try:
            new_alert["http_user_agent"] = alert["http"]["http_user_agent"]
        except KeyError:
            logger.debug("Alert dont contain http http_method field..")

        return new_alert

    def full_log(self, line: str) -> dict:
        """ Parse Suricata 'full' logs """
        return NotImplemented

    def fast_log(self, line: str) -> dict:
        """ Parse Suricata 'fast' logs """
        # Not really tested...
        try:
            match = self._pattern_fast.match(line)
            if not match:
                # Send notification when nothing matches..
                logger.error(f"No match for line. This should not happen! Line: %s", line)
                if self.isNotify_enabled:
                    Notification().send_notification(
                        message="No match for line. This should not happen..\n{}".format(line),
                        title="Snort Parser Error"
                    )

                return {}

            parsed_alert = match.groupdict()

            # Format time
            formatted_time = datetime.datetime.strptime(parsed_alert["time"], '%m/%d/%Y-%H:%M:%S.%f')\
                .strftime(self._dateformat)
            parsed_alert["time"] = str(formatted_time)

            return parsed_alert

        except re.error as rex_error:
            logger.error(rex_error)
            exit(1)
