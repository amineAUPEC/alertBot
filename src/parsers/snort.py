import re
import logging
import datetime

from src.notify import Notification

logger = logging.getLogger("alertBot.snort")


class Snort:
    """ Snort parser class
        Using class BC patterns should only be compiled once..
        And all snort parsers and patterns can be found at one place.
        Parsers not tested for SnortV3
    """
    def __init__(self, notify_enabled=False, dateformat: str = ""):
        # Output date format - see datetime for formatting options
        self._dateformat = "%Y-%m-%d %H:%M:%S.%f"
        if dateformat:
            self._dateformat = dateformat

        self.isNotify_enabled = notify_enabled

        self.pattern_full = re.compile(
            r"(?P<time>\d+\/\d+\/\d+-\d+:\d+:\d+\.\d+)\s,"  # time
            r"(?P<gid>\d+),"                                # Signature GID
            r"(?P<sid>\d+),"                                # Signature SID
            r"(?P<revision>\d+),"                           # Revision - ??
            r"\"(?P<name>.*?)\","                           # Alert name
            r"(?P<protocol>TCP|UDP|ICMP|.?),"               # Protocol
            r"(?P<src>\d+\.\d+\.\d+\.\d+),"                 # Src IP
            r"(?P<src_port>\d+|.?),"                        # Src port
            r"(?P<dest>\d+\.\d+\.\d+\.\d+),"                # Dst IP
            r"(?P<dest_port>\d+|.?),"                       # Dst port
            r"\d+,"                                         # Unknown stuff
            r"(?P<classtype>[a-zA-Z0-9-_ ]+),"              # Alert class
            r"(?P<priority>\d+)"                            # Priority
        )

        self._pattern_fast = re.compile(
            r"(?P<time>\d{2}\/\d{2}\/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
            r"\[\*\*\]\s+\[\d+:(?P<sid>\d+):(?P<revision>\d+)\] "
            r"(?P<name>.+) \[\*\*\]\s+(\[Classification: (?P<classtype>.+)\] )?"
            r"\[Priority: (?P<priority>\d+)\] \{(?P<protocol>[:a-zA-Z0-9_-]+)\} "
            r"(?P<src>.+) \-\> (?P<dest>.+)"
        )

    def full_log(self, line: str) -> dict:
        # Parse snort version 2 alerts/logs
        try:
            match = self.pattern_full.match(line)
            if not match:
                # Send notification when nothing matches..
                logger.error(f"No match for line. This should not happen! Line: %s", line)
                if self.isNotify_enabled:
                    Notification().send_notification(
                        message="No match for line. This should not happen..\n{}".format(line),
                        title="Snort full_log Parser Error"
                    )
                return {}

            parsed_alert = match.groupdict()
            # Format time
            formatted_time = datetime.datetime.strptime(parsed_alert["time"], "%m/%d/%y-%H:%M:%S.%f")\
                .strftime(self._dateformat)
            parsed_alert["time"] = str(formatted_time)

            return parsed_alert

        except re.error as rex_error:
            logger.error(rex_error)
            exit(1)

    def fast_log(self):
        return NotImplemented
