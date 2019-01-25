import json
import munch
import os

config_file = "config.json"

if not os.path.isfile(config_file):
    config_file = "../config.json"

with open(config_file, "r") as cfg:
    config = json.load(cfg)

# TODO: Validate config...
config = munch.munchify(config)


from .filtering.filter_alerts import AlertFilter
from .notify.notify import SendNotification
from .parsers.suricata import Suricata
from .parsers.snort import Snort