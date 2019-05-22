import logging
import logging.config
import json
import os
import sys
import traceback
import time
import threading

from typing import List

from src import config
from src.parsers import Suricata, Snort, PaloAltoParser
from src.notify import Notification
from src.filtering import AlertFilter
from src.misc.utils import get_hostname
from src.misc.restart import detect_change
from src.abstraction.models import Alert

from src.abstraction.interface import IFaceHTTPSource
from src.abstraction.models import SensorConfig

# Vars needed when 'restart' is enabled
sys_args = sys.argv
sys_exe = sys.executable

# Locks
get_state_lock = threading.RLock()
save_state_lock = threading.RLock()
notify_lock = threading.RLock()
dns_lock = threading.RLock()

# Create logger
logging.config.dictConfig(config.logging)
logger = logging.getLogger("alertBot")

log_levels = {
    "info": logging.INFO,
    "warn": logging.WARNING,
    "critical": logging.CRITICAL,
    "error": logging.ERROR,
    "debug": logging.DEBUG
}

if len(sys_args) > 1 and sys_args[1] != "restarted":
    try:
        # Use log level from command line argument
        logger.setLevel(log_levels[sys_args[1]])
    except KeyError as e:
        print(e)
        logger.error(e)
        logger.warning("Not a valid log level!")
        logger.warning(f"Valid log levels are: {log_levels.keys()}")
        exit(1)
    except IndexError as IE:
        pass

# File state for alerts (global)
state_file = "fileState.json"
if not os.path.isfile(state_file) or os.path.getsize(state_file) == 0:
    # Create the file_state file with default values
    logger.info("fileState.json do not exist or is empty. Creating default..")

    default_state = {}
    for _sensor in config["sensors"].keys():
        default_state[_sensor] = {}
        default_state[_sensor][config.sensors[_sensor].interface] = 0

    with open(state_file, "w") as file:
        json.dump(default_state, file)

alert_filter = None  # AlertFilter cls
filter_list = None  # JSON loaded filter list
isFilter_enabled = config.filter.enabled
isNotify_enabled = config.notify.enabled
isNotifyOnStartUp_enabled = config.notify.notifyOnStartUp
# isPcapParser_enabled = config.pcapParser.enabled
isReverseDNS_enabled = config.general.reverseDns
isRestartOnChange_enabled = config.general.restartOnChange

logger.info(f"Reverse DNS is {isReverseDNS_enabled}")
# logger.info(f"Pcap Parser is {isPcapParser_enabled}")
logger.info(f"Notification is {isNotify_enabled}")
logger.info(f"Startup alert is {isNotifyOnStartUp_enabled}")
logger.info(f"Filter is {isFilter_enabled}")
logger.info(f"Restart on change is {isRestartOnChange_enabled}")

if isFilter_enabled:
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

restart_success = False
if sys_args[len(sys_args) - 1] == "restarted":
    logger.info("AlertBot Restarted Successfully")
    restart_success = True
    sys_args.pop()

notify = None
if isNotify_enabled:
    notify = Notification(config.notify)
    if isNotifyOnStartUp_enabled and restart_success:
        notify.send_notification(message="Started after successful restart", title="Restart event")
        # Not really necessary I think..
        restart_success = False

    elif isNotifyOnStartUp_enabled:
        notify.send_notification(message="AlertBot powered up..", title="Upstart event")


# parsers Dictionary holds all available parser classes and parser functions. Could be auto generated but meh.
parsers = {
    "snort": {
        "parser_cls": Snort,
        "logType": {
            "full": "full_log",  # The value is the name of the parser function in the parser class
            "fast": "fast_log"
        }
    },
    "suricata": {
        "parser_cls": Suricata,
        "logType": {
            "eve": "eve_json",  # The value is the name of the parser function in the parser class
            "fast": "fast_log",
            "full": "full_log"
        }
    },
    "paloalto": {
        "parser_cls": PaloAltoParser,
        "logType": {
            "threat": "threat_log"
        }
    }
}


# def get_enabled_sensor():
#     """ Get the enabled sensor config """
#     enabled_count = 0
#     selected_sensor = None
#     for sensor in config.sensors:
#         if config.sensors[sensor].enabled:
#             enabled_count += 1
#             # Creates a new key "sensorType" = sensor ex snort
#             config.sensors[sensor]["sensorType"] = sensor
#             selected_sensor = config.sensors[sensor]
#
#     if not selected_sensor:
#         logger.error("No sensors is enabled.. Plz enable ONE!")
#         exit(1)
#
#     if enabled_count > 1:
#         logger.error(f"{enabled_count} sensor enabled! Only one can be enabled!")
#         exit(1)
#
#     return selected_sensor


def get_enabled_sensors() -> List[SensorConfig]:
    """ Get enabled sensors config """
    enabled = []
    # enabled = list(filter(lambda s: lambda sen: config.sensors[sen] if config.sensors[sen]["enabled"] else False,
    #                       config.sensors))

    for sensor in config.sensors:
        if sensor.enabled:
            enabled.append(SensorConfig(**sensor))

    if not enabled:
        logger.error("No sensors is enabled.. Plz enable ONE!")
        exit(1)

    return enabled


def get_logfile_state() -> dict:
    """ Get log state """
    # Get last file position for log files.. 'state_file' is global
    with get_state_lock:
        with open(state_file, "r") as s_file:
            state = json.load(s_file)

    return state


def save_logfile_state(new_state: int, sensor: str, interface: str):
    """ Save log state """
    # Save current file position of logfile. 'state_file' is global
    new_file_state = get_logfile_state()
    # Update file state
    new_file_state[sensor][interface] = new_state
    with save_state_lock:
        with open(state_file, "w") as s_file:
            json.dump(new_file_state, s_file)


def tail_file(logfile, parser, sensor_config: SensorConfig, run_event):
    """ Tail file log source """
    # Let's figure out where we left off
    saved_file_poss = get_logfile_state()[sensor_config.name][sensor_config.interface]
    current_file_poss = 0
    if saved_file_poss > current_file_poss:
        current_file_poss = saved_file_poss
    logger.info(f"Sensor: {sensor_config.name.title()} Interface: {sensor_config.interface}, Alert file position start up:"
                f" {current_file_poss} (file position)")

    while run_event.is_set():
        # While loop runs as long as threding.Event() is set
        logfile.seek(0, 2)
        if logfile.tell() < current_file_poss:
            logfile.seek(0, 0)
        else:
            logfile.seek(current_file_poss, 0)
        line = logfile.readline()
        if not line:
            time.sleep(1)
            # Sleep 1 sec and jumps to 'next' while loop iterations
            continue

        if current_file_poss < logfile.tell():
            logger.debug(f"This is where we are at {logfile.tell()}, in file {sensor_config.interface}")

        # Lets run the new line through the parser and see whats happening before we say we have read it..
        logger.debug(line)

        parsed_line = parser(line)
        # alert = parsed_line
        if not parsed_line:
            # BC eve.json lines may contain other event types than alert. Parser(s) handles this..
            # Update current file state
            current_file_poss = logfile.tell()
            # Save current read position state to file
            save_logfile_state(new_state=current_file_poss, sensor=sensor_config.name, interface=sensor_config.interface)
            # Jumps to 'next' while loop iterations
            continue

        alert = Alert(**parsed_line)
        # Add interface to alert
        alert.interface = sensor_config.interface

        if not isFilter_enabled and isNotify_enabled:
            # Notifications is enabled but we are not filtering any alert..
            logger.debug("Sending notification..")

            notify.send_notification(
                message=alert.__dict__, title=f"{sensor_config.name} Event".title()
            )

        if isFilter_enabled and not alert_filter.run_filter(alert=alert):
            # Filter is enabled and this alert did not match any filters so we can send notification

            # Get pcap if enabled. Only applicable for PFsnort alerts
            # if isPcapParser_enabled:
            #     # Returns url to view pcap -> str
            #     pcap_url = get_alert_pcap(alert.__dict__)
            #     alert.pcap = pcap_url

            # Add reverse DNS to src/dest. Reverse DNS is slow
            if isReverseDNS_enabled:
                # Needs lock
                with dns_lock:
                    src_dns = get_hostname(alert.src)
                    dest_dns = get_hostname(alert.dest)
                formatted_src = alert.src + " - " + str(src_dns)

                formatted_dest = alert.dest + " - " + str(dest_dns)

                alert.src = formatted_src
                alert.dest = formatted_dest

            if isNotify_enabled:
                logger.debug("Sending notification..")

                notify.send_notification(
                    message=alert.__dict__, title=f"{sensor_config.name} Event".title()
                )

        logger.debug(alert)

        # Update current file state
        current_file_poss = logfile.tell()
        # save current file state to file
        save_logfile_state(new_state=current_file_poss, sensor=sensor_config.name, interface=sensor_config.interface)


def tail_http(sensor_cls, sensor_config: SensorConfig, run_event):
    """ Tail http 'log source' """
    # Must be fixed when a new http log source is created..
    pull_interval = sensor_config.pullInterval * 60  # 2*60

    sensor_cls(sensor_config)
    # Init sensor
    sensor: IFaceHTTPSource = sensor_cls(sensor_config)
    # sensor: IFaceHTTPSource = sensor_cls  # already instantiated

    saved_state = get_logfile_state()[sensor_config.name][sensor_config.interface]

    current_state = 0
    if saved_state > current_state:
        current_state = saved_state

    logger.info(f"Sensor: {sensor_config.name.title()} Interface: {sensor_config.interface},  Alert seqNo start up:"
                f" {current_state}")

    while run_event.is_set():
        # Query PA for logs
        parsed_alerts = sensor.search(current_state)

        logger.debug(f"Total result from query: {len(parsed_alerts)}")

        # Alerts left after filtering and other conditions.. Mostly so we can send all alerts at once
        alertable_alerts = []

        for a in parsed_alerts:
            alert = Alert(**a)

            alert.interface = sensor_config.interface

            if not isFilter_enabled and isNotify_enabled:
                # Notifications is enabled but we are not filtering any alert..
                logger.debug("Sending notification..")

                notify.send_notification(
                    message=alert.__dict__, title=f"{sensor_config.name} Event".title()
                )

            if isFilter_enabled and not alert_filter.run_filter(alert=alert):
                # Filter is enabled and this alert did not match any filters so we can send notification

                # Add reverse DNS to src/dest
                if isReverseDNS_enabled:
                    # Reverse DNS is slow
                    src_dns = get_hostname(alert.src)  # NEEDS LOCK
                    formatted_src = alert.src + " - " + str(src_dns)
                    dest_dns = get_hostname(alert.dest)
                    formatted_dest = alert.dest + " - " + str(dest_dns)

                    alert.src = formatted_src
                    alert.dest = formatted_dest

                if isNotify_enabled:
                    logger.debug("Sending notification..")

                    # NEEDS LOCK
                    with notify_lock:
                        notify.send_notification(
                            message=alert.__dict__, title=f"{sensor_config.name} Event".title()
                        )

            logger.debug(alert)

            # Update current seqno
            # Must be fixed when a new http log source is created..
            current_state = alert.seqno  # int(a["seqno"])

        # save current file state to file
        save_logfile_state(new_state=current_state, sensor=sensor_config.name, interface=sensor_config.interface)

        # Sleep
        time.sleep(pull_interval)


running_threads = []
run_events = []
open_files = []

http_run_event = None
file_run_event = None
watch_run_event = None


def shutdown_gracefully():
    """ Attempt a graceful shutdown """

    # Kill threads if any (ex file watcher).
    if running_threads:
        logger.info("Killing thread(s).. You must wait their sleep time..")

        for rv in run_events:
            # Clear all run events
            rv.clear()

        for th in running_threads:
            # Kill(join) all running threads
            th.join()
        logger.debug("All threads are dead")

    if open_files:
        # Close all open log files and save current position
        for of in open_files:
            # Get One sensor config = of["sensor"] -> Munch object
            curr_sensor = list(filter(lambda x: x.name == of["sensor"], config.sensors))[0]
            file_position = of["alert_file"].tell()
            of["alert_file"].close()
            logger.info(f"Closed logfile '{of['filePath']}'")

            save_logfile_state(new_state=file_position, sensor=curr_sensor.sensorType, interface=curr_sensor.interface)
            logger.info(f"Saved current state: {file_position} (file position)")

    # Currently no reason to 'gracefully' stop tail_http threads..

    if isFilter_enabled:
        logger.info("Check alert filter stats in 'filter_stats.json'")
        alert_filter.save_filter_stats()

    logger.info("Done shutting down")


if __name__ == "__main__":
    logger.info("Powering up...")

    # running_threads = []
    # run_events = []
    # open_files = []
    #
    # http_run_event = None
    # file_run_event = None
    # watch_run_event = None

    if isRestartOnChange_enabled:
        watch_interval = config.general.watchInterval  # Minutes
        watched_files = config.general.watchedFiles
        watch_run_event = threading.Event()
        watch_run_event.set()

        run_events.append(watch_run_event)

        w_th = threading.Thread(target=detect_change, args=(sys_exe, sys_args, watch_run_event, watch_interval,
                                                            watched_files, alert_filter))
        running_threads.append(w_th)
        # w_th.start()

    # Get config for all enabled sensors
    enabled_sensors = get_enabled_sensors()

    # Get save log state
    current_logfile_state = get_logfile_state()

    for s in enabled_sensors:
        # If for some reason the sensor interface change after first run, we need to update..
        try:
            current_logfile_state[s.name][s.interface]
        except KeyError:
            # Add the new interface to state_file
            save_logfile_state(new_state=0, sensor=s.sensorType, interface=s.interface)

        # Init selected parser class and parser function
        #parser_cls = parsers[s.sensorType]["parser_cls"](s)  # s = sensor_config
        parser_cls = parsers[s.sensorType]["parser_cls"]  # s = sensor_config

        if s.logSourceType == "file":
            # Open log file. This file object will stay open until KeyboardInterrupt is caught (or killed).
            parser_func = parsers[s.sensorType]["logType"][s.logType]
            # parser ->This is the same as doing Snort().full_log,
            # if snort is the enabled sensor and full_log is the function.
            init_parser_cls = parser_cls(s)  # Init parser_cls
            _parser = getattr(init_parser_cls, parser_func)  # Only used for logSourceType == "file"
            alert_file = open(s.filePath, "r")

            open_files.append({"alert_file": alert_file, "filePath": s.filePath, "sensor": s.name})

            # Runs forever
            file_run_event = threading.Event()
            file_run_event.set()

            run_events.append(file_run_event)

            f_th = threading.Thread(target=tail_file, args=(alert_file, _parser, s, file_run_event))
            # tail_file(logfile=alert_file, parser=parser, sensor_name=active_sensor)
            running_threads.append(f_th)
            # f_th.start()

        elif s.logSourceType == "http":
            # Runs forever
            logger.debug(s)
            http_run_event = threading.Event()
            http_run_event.set()

            run_events.append(http_run_event)

            h_th = threading.Thread(target=tail_http, args=(parser_cls, s, http_run_event))
            running_threads.append(h_th)
            # h_th.start()
            # tail_http(sensor_cls=parser_cls, sensor_config=s)
    try:
        # Start all threads
        for t in running_threads:
            t.start()
    except KeyboardInterrupt:
        # Kill tail() while loop. KeyboardInterrupt is the real killer of tail()
        # tail_run.clear()
        shutdown_gracefully()

        logger.info("Exiting..")
        logging.shutdown()
        exit(0)

    except Exception as e:
        # Catch and Log all unexpected exceptions..
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logger.exception("An unexpected error has occurred!", exc_info=True)

        tb = traceback.format_exception(exc_type, exc_value, exc_traceback)
        msg = "An unexpected error has occurred! Check logs! Shutting down..\n" + "".join(tb_line for tb_line in tb)

        if isNotify_enabled:
            notify.send_notification(message=msg, title="Unexpected error Event")

        # Try to shutdown stuff
        shutdown_gracefully()

        logger.info("Exiting..")
        logging.shutdown()
        exit(1)


