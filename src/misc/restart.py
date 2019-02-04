import time
import os
import logging

logger = logging.getLogger("alertBot.fileWatcher")


def restart_app(sys_exe, sys_args, run_event, alert_filter):
    """ Restart the entire program """
    arguments = sys_args[:]
    arguments.append("restarted")

    run_event.clear()

    # Save alert_filter stats if filter is enabled...
    if alert_filter:
        alert_filter.save_filter_stats()

    logger.warning("Restarting app")
    logging.shutdown()
    os.execl(sys_exe, sys_exe, * arguments)


def detect_change(sys_exe, sys_args: list, run_event, interval: int, files_to_watch: list, alert_filter):
    """ Detects changes in watched files """

    # This function should be executed in a thread
    logger.info("Started file watcher (detect_change)")

    watched_files = files_to_watch
    watched_files_MTIMES = [(f, os.path.getmtime(f)) for f in watched_files]

    while run_event.is_set():
        time.sleep(interval * 60)  # minutes

        for f, mtime in watched_files_MTIMES:
            logger.debug(f"current: {os.path.getmtime(f)}, old: {mtime}")
            if os.path.getmtime(f) != mtime:
                logger.info(f"Detected change in file: {str(f)}")
                logger.warning("Attempting to restart")

                restart_app(sys_exe, sys_args, run_event, alert_filter)

        logger.debug("No change detected")


