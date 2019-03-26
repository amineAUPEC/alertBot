import re
import json
import datetime
import logging

from src import config
from src.misc.utils import url_sanitizer
from src.notify import Notification

logger = logging.getLogger("alertBot.suricata")


class Suricata:
    """ Suricata parser class """

    def __init__(self, dateformat: str = ""):
        # Output date format - see datetime for formatting options
        self._dateformat = "%Y-%m-%d %H:%M:%S.%f"
        if dateformat:
            self._dateformat = dateformat

        self.isNotify_enabled = config.notify.enabled

        # Copied from snort. Needs to be checked..
        self._pattern_full = re.compile(
            r"^(?P<time>\d+\/\d+\/\d+-\d+:\d+:\d+\.\d+)\s,"
            r"(?P<gid>\d+),"
            r"(?P<sid>\d+(,\d)?),"
            r"(?P<revision>\d+),"
            r"\"(?P<name>.*?)\","
            r"(?P<protocol>TCP|UDP|ICMP|.?),"
            r"(?P<src>(\d+\.\d+\.\d+\.\d+)|((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*(\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?),"
            r"(?P<src_port>\d+|.?),"
            r"(?P<dest>(\d+\.\d+\.\d+\.\d+)|((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*(\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?),"
            r"(?P<dest_port>\d+|.?),"
            r"\d+,"                 # Unknown
            r"(?P<classtype>[a-zA-Z0-9-_ ]+),"
            r"(?P<priority>\d+)$"
        )

        self._pattern_fast = re.compile(
            r"(?P<time>\d{2}\/\d{2}\/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
            r"\[\*\*\]\s+\["
            r"(?P<gid>\d+)\:"
            r"(?P<sid>\d+)\:"
            r"(?P<revision>\d+)\] "
            r"(?P<name>.+) \[\*\*\]\s+(\[Classification: (?P<classtype>.+)\] )?"
            r"\[Priority: (?P<priority>\d+)\] \{(?P<protocol>[:a-zA-Z0-9_-]+)\} "
            r"(?P<src>(\d+\.\d+\.\d+\.\d+)|((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*(\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?)"
            r"\:"
            r"(?P<src_port>\d+|.?)"
            r" \-\> "
            r"(?P<dest>(\d+\.\d+\.\d+\.\d+)|((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*(\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?)"
            r"\:"
            r"(?P<dest_port>\d+|.?)"
        )

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
            "dest": alert['dest_ip'],
            "proto": alert['proto'],
            "action": alert["alert"]["action"]
        }
        # Payload field not always there..
        try:
            new_alert["payload"] = alert['payload']
        except KeyError:
            new_alert["payload"] = ""

        # *port* fields are not always there.. Ex ICMP alerts..
        # This is resolved by setting src/dest port field default value to int(0) in Alert dataclass
        # as well as expecting KeyError
        try:
            new_alert["src_port"] = alert["src_port"]
        except KeyError:
            logger.debug("Alert dont contain src_port field..")

        try:
            new_alert["dest_port"] = alert["dest_port"]
        except KeyError:
            logger.debug("Alert dont contain dest_port field..")

        # Request by alex.. thanks for messy code..
        try:
            new_alert["hostname"] = url_sanitizer(alert["http"]["hostname"])
        except KeyError:
            logger.debug("Alert dont contain http hostname field..")

        try:
            new_alert["url"] = url_sanitizer(alert["http"]["url"])
        except KeyError:
            logger.debug("Alert dont contain http url field..")

        try:
            new_alert["http_refer"] = url_sanitizer(alert["http"]["http_refer"])
        except KeyError:
            logger.debug("Alert dont contain http http_refer field..")

        try:
            new_alert["http_method"] = alert["http"]["http_method"]
        except KeyError:
            logger.debug("Alert dont contain http http_method field..")

        try:
            new_alert["http_user_agent"] = url_sanitizer(alert["http"]["http_user_agent"])
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
                    Notification(config.notify).send_notification(
                        message="No match for line. This should not happen..\n{}".format(line),
                        title="Suricata fast_log Parser Error"
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
            raise rex_error
