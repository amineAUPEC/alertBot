import json
import munch
import os
import time
import logging
import datetime

from src import config
from src.parsers import Suricata, Snort
from src.notify import SendNotification
from src.filtering import AlertFilter
from src.pcap.alertPcap import get_alert_pcap
from src.utils.dns import get_hostname

log_level = {
    "info": logging.INFO,
    "warn": logging.WARN,
    "critical": logging.CRITICAL,
    "debug": logging.DEBUG
}

set_loglevel = config.logging.level

# create logger
logger = logging.getLogger("alertBot")
logger.setLevel(log_level[set_loglevel])

# create file handler which logs even debug messages
fh = logging.FileHandler('alertBot.log')
fh.setLevel(log_level[set_loglevel])

# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(log_level[set_loglevel])

# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%Y:%m:%d %H:%M:%S')
fh.setFormatter(formatter)
ch.setFormatter(formatter)

# add the handlers to the logger
logger.addHandler(fh)
logger.addHandler(ch)

# file state for alerts
state_file = "fileState.json"
if not os.path.isfile(state_file) or os.path.getsize(state_file) == 0:
    # Create file state with default values
    # This is dirty and should be fixed..
    logger.info("fileState.json do not exist or is empty. Creating default..")

    default_state = {}
    default_state["snort"] = {}
    #default_state["snort"] = 0
    default_state["snort"][config.sensors.snort.interface] = 0
    default_state["suricata"] = {}
    default_state["suricata"][config.sensors.suricata.interface] = 0
    with open(state_file, "w") as file:
        json.dump(default_state, file)

isFilter_enabled = False
isNotify_enabled = config.notify.enabled

if config.filter.enabled:
    logger.info("Filter is enabled")

    isFilter_enabled = True
    if not os.path.isfile("filter.json"):
        logger.warning("filter.json do not exist")

        exit("Filter is enabled but does not exist.. Create file 'filter.json'")

    with open(config.filter.path, encoding="utf-8") as f:
        try:
            filter_list = json.load(f)
        except json.decoder.JSONDecodeError as je:
            logger.error("Error in 'filter.json' -> %s", je)
            logger.exception(msg="Must escape 'escape' chars in regex in 'filter.json' bc json... "
                                 "Usually solved by '\\\\'", exc_info=je)
            exit(1)

    alert_filter = AlertFilter(filter_list)
    alert_filter.validate_filter_list()

if isNotify_enabled:
    logger.info("Notification is enabled")
    notify = SendNotification()

parsers = {
    "snort": {
        "logType": {
            "full": Snort().full_log,
            "fast": Snort().fast_log
        }
    },
    "suricata": {
        "logType": {
            "evejson": Suricata().eve_json,
            "fast": Suricata().fast_log,
            "full": Suricata().full_log
        }
    }
}


def get_enabled_sensor():
    for sensor in config.sensors:
        if config.sensors[sensor].enabled:
            config.sensors[sensor]["sensorType"] = sensor
            return config.sensors[sensor]

    logger.error("No sensors is enabled.. Plz enable ONE!")
    exit(1)


# Get the enabled sensor
enabled_sensor_cfg = get_enabled_sensor()


def get_logfile_state(filepath) -> dict:
    # Get all file states..
    with open(filepath) as file:
        state = json.load(file)

    return state


def save_logfile_state(new_state: int, sensor: str, interface: str):
    # save current tracking of logfile
    new_filestate = get_logfile_state(state_file)
    # update file state
    new_filestate[sensor][interface] = new_state
    with open(state_file, "w") as file:
        json.dump(new_filestate, file)


def tail(logfile, parser, sensor: str, interface: str, run: bool):
    # Lets figure out were we left off
    saved_filestate = get_logfile_state(state_file)[sensor][interface]
    current_state = 0
    if saved_filestate > current_state:
        current_state = saved_filestate
    logger.info(f"Sensor {sensor} - Interface {interface} - Alert fileState at start up: {current_state} (file position)")

    while run:
        logfile.seek(0, 2)
        if logfile.tell() < current_state:
            logfile.seek(0, 0)
        else:
            logfile.seek(current_state, 0)
        line = logfile.readline()
        if not line:
            time.sleep(1)
            continue
        # print line
        if current_state < logfile.tell():
            # print logfile.tell()
            logger.debug(f"This is where we are at {logfile.tell()}, in file {interface}")

        # Lets run the new line through the parser and see whats happening before we say we have read it..
        logger.debug(line)

        parsed_line = parser(line)
        # alert = parsed_line
        if not parsed_line:
            # bc eve.json lines may contain other event types than alert.
            # Update current file state
            current_state = logfile.tell()
            # save current file state to file
            save_logfile_state(new_state=current_state, sensor=sensor, interface=interface)

            continue

        # Add interface to alert
        parsed_line["interface"] = interface

        if not isFilter_enabled and isNotify_enabled:
            logger.debug("sending notification..")
            # The hole notification thing should be cleaned up..
            notify.send_notification(
                message="\n".join(f"{k}: {v}" for k, v in parsed_line.items()),
                title=f"{sensor} Event\n".title()
            )

        if isFilter_enabled and not alert_filter.run_filter(alert=munch.munchify(parsed_line)):
            # Filter is enabled and this alert did not match any filters so we can send notification

            # Get pcap if enabled
            if config.misc.pcap:
                # returns url to view pcap -> str
                pcap_url = get_alert_pcap(parsed_line)
                parsed_line["pcap"] = pcap_url

            # Add reverse DNS to src/dest
            src_dns = get_hostname(parsed_line["src"])
            formatted_src = parsed_line["src"] + " - " + str(src_dns)
            dst_dns = get_hostname(parsed_line["dst"])
            formatted_dst = parsed_line["dst"] + " - " + str(dst_dns)

            parsed_line["src"] = formatted_src
            parsed_line["dst"] = formatted_dst

            # format time
            formatted_time = datetime.datetime.strptime(parsed_line["time"], '%m/%d/%y-%H:%M:%S.%f')
            parsed_line["time"] = str(formatted_time)

            if isNotify_enabled:
                # this "if" line is not necessary but prolly gonna add DB or something later..

                logger.info("sending notification..")
                # The hole notification thing should be cleaned up..
                # str(datetime.datetime.strptime("01/11/19-17:54:45.917318", '%m/%d/%y-%H:%M:%S.%f'))
                # notify.send_notification(
                #     message="\n".join(f"{k}: {v}" for k, v in parsed_line.items() if k not in config.misc.blacklistedFields),
                #     title=f"{sensor} Event\n".title()
                # )

                notify.send_notification(
                    message=parsed_line,
                    title=f"{sensor} Event\n".title()
                )


        # Update current file state
        current_state = logfile.tell()
        # save current file state to file
        # save_currentstate(interface, file_state)
        save_logfile_state(new_state=current_state, sensor=sensor, interface=interface)

    # logger.info("Tailer stopped")
    # logger.info(f"Saved current state: {current_state}")


if __name__ == "__main__":
    logger.info("Starting up...")

    # global tail_run
    tail_run = True
    alert_file = open(enabled_sensor_cfg.filePath, "r")
    current_parser = parsers[enabled_sensor_cfg.sensorType]["logType"][enabled_sensor_cfg.logType]
    sensor_interface = enabled_sensor_cfg.interface
    active_sensor = enabled_sensor_cfg.sensorType
    # catch keyboard interrupt so we can stop gracefully i think..
    try:
        # This is nasty as fuck! and cant do gracefull stop with out threads inside tail()..
        tail(logfile=alert_file, parser=current_parser, sensor=active_sensor,
             interface=sensor_interface, run=tail_run)
    except KeyboardInterrupt:
        # this is not working at all.. but not important..
        logger.info("Brutally Killed tail()..")
        tail_run = False

        save_logfile_state(new_state=alert_file.tell(), sensor=active_sensor, interface=sensor_interface)
        logger.info(f"Saved current state: {alert_file.tell()} (file position)")
        alert_file.close()
        logger.info(f"Closed logfile '{enabled_sensor_cfg.filePath}'")
        logger.info("Filter stats:")
        logger.info("Filter function stats: %s", alert_filter.filter_func_stats)
        logger.info("Filter name stats: %s", alert_filter.filter_name_stats)

        logger.info("Exiting..")
        exit(0)
