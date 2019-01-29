import time
import os
import sys
import logging
import threading
# import psutil

# from src import config
logger = logging.getLogger("alertBot.fileWatcher")


def restart_app(sys_exe, sys_args, run_event):
    """ Restart entire  program """
    # py_version = "python3.7"
    arguments = sys_args[:]
    arguments.append("restarted")

    # try:
    #     p = psutil.Process(os.getpid())
    #
    #     for handler in p.open_files() + p.connections():
    #         os.close(handler.fd)
    # except Exception as e:
    #     print("Error:", e)
    #     os._exit(0)

    run_event.clear()
    logger.warning("Restarting app")
    logging.shutdown()
    os.execl(sys_exe, sys_exe, * arguments)
    #os.execv(sys.executable, [py_version] + sys_args)


def detect_change(sys_exe, sys_args: list, run_event, interval: int, files_to_watch: list):
    """ Detects changes in watched files """

    # This function should be executed in a thread
    logger.info("started detect change")

    watched_files = files_to_watch
    watched_files_MTIMES = [(f, os.path.getmtime(f)) for f in watched_files]

    while run_event.is_set():
        time.sleep(interval * 60)  # minutes

        for f, mtime in watched_files_MTIMES:
            logger.debug(f"current: {os.path.getmtime(f)}, old: {mtime}")
            if os.path.getmtime(f) != mtime:
                logger.info(f"Detected change in file: {str(f)}")
                logger.warning("Attempting to restart")

                restart_app(sys_exe, sys_args, run_event)

        logger.debug("No change detected")


if __name__ == "__main__":
    print("Starting up")
    sys_args = sys.argv
    print("Upstart sys_args: ", sys_args)
    sys_exe = sys.executable
    print("Upstart sys_exe: ", sys_exe)
    print("sys_args[len(sys_args) - 1]: ", sys_args[len(sys_args) - 1])
    if sys_args[len(sys_args) - 1] == "restarted":
        print("Restarted successfully")
        logger.info("Restarted successfully")
        sys_args.pop()

    run_event = threading.Event()
    run_event.set()

    #th = threading.Thread(target=detect_change, args=(sys_exe, sys_args, config.general.watchInterval, config.general.watchedFiles))
    #th = threading.Thread(target=detect_change,
    #                      args=(sys_exe, sys_args, run_event, config.general.watchInterval, config.general.watchedFiles))
    th = threading.Thread(target=detect_change,
                          args=(
                          sys_exe, sys_args, run_event, 2, "testMe.txt"))
    print("Starting detect_change thread")
    th.start()

    try:
        while True:
            print("Main thread sleep")
            time.sleep(15)
    except KeyboardInterrupt:
        print("run_event.clear()")
        run_event.clear()
        print("th.join(1)")
        th.join(2)
        print("exiting")
        exit(0)
