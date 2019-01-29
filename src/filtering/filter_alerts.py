import logging
import re
import json
import os
from netaddr import IPNetwork, IPAddress, AddrFormatError
import munch

from src.abstraction.exceptions import FilterValidationError
from src.abstraction.models import Alert

logger = logging.getLogger("alertBot.filter")


class AlertFilter:
    """ 200 iq class """

    filter_funcs = {}
    required_filter_fields = ["filterName", "rules"]
    required_rules_fields = ["func", "value", "field"]
    stats_file = "filter_stats.json"

    # TODO: Save and load filter stats to/from file

    @staticmethod
    def validate_regex(pattern: str, filter_name: str):
        """ Validate regex """
        try:
            validated = re.compile(pattern)
        except re.error as regexerror:
            logger.debug(regexerror)
            logger.error(f"<Invalid regular expression '{pattern}' in filter '{filter_name}'>")
            exit(1)
        else:
            return validated

    def __init__(self, filter_list: list):
        # Validate all filters before we do anything..
        self._validate_filter(filter_list)

        # munchify filter_list so we can use dot notations when referencing dict keys, even nested keys.
        # Also compile any regex patterns in filter_list
        self.filterList = munch.munchify(self._compile_regex(filter_list))

        # Sort filter_list so that we start with the most specific filter e.g the filter with most rules comes first
        self.filter_list = sorted(self.filterList, key=lambda f: len(f["rules"]), reverse=True)

        # Generate truth_index so that we can use implicit OR when
        # a filter have multiple rules with a multiple of the same filed
        self.truth = self._truth_index()

        # Declare Filter stats vars
        self.filter_func_true_stats = {}     # How many times a single filter rule function has returned true
        self.filter_func_stats = {}          # How many times a filter func(rule) was true when the filter returned true
        self.filter_name_stats = {}          # How many times filter(filterName) has returned true
        self.filtered_alert_name_stats = {}  # How many times 'alert.name' has been filtered
        self.not_filtered_alerts_stats = {}  # How many times 'alert.name' was _NOT_ filtered

        # Load existing filter stats into Filter stats vars (only if existing stats exists)
        self._load_filter_stats()

    def _truth_index(self) -> dict:
        index = {}
        for f in self.filter_list:
            field_val = dict()
            for r in f["rules"]:
                field_val[r["field"]] = field_val.get(r["field"], 0) + 1

            index[f["filterName"]] = field_val

        return index

    def _compile_regex(self, filter_list: list):
        """ Validates and compiles regex if any """
        for _filter in filter_list:
            for rule in _filter["rules"]:
                if rule["func"] == "regex":
                    rule["value"] = self.validate_regex(pattern=rule["value"], filter_name=_filter["filterName"])

        return filter_list

    def _validate_filter(self, filter_list: list):
        """ Validate all filters """

        # filter_list is NOT type Munch at this point.
        # This is the received arg(filter_list) from __init__ and is !NOT! 'self.filter_list'!
        used_filter_names = []

        for _filter in filter_list:
            filter_keys = _filter.keys()
            for required_field in self.required_filter_fields:
                # Validate that required_filter_fields exist
                if required_field not in filter_keys:
                    logger.debug(_filter)
                    raise FilterValidationError(f"Required filter field '{required_field}' missing from filter")

                # Validate that required_filter_fields have a value.
                if not _filter[required_field]:
                    logger.debug(_filter)
                    raise FilterValidationError(f"Required filter field '{required_field}' is missing a value in "
                                                f"filter '{_filter['filterName']}'")

            # Safely add filterName(value) to used_filter_names. Checked later..
            used_filter_names.append(_filter["filterName"])

            # Validate rules 'section' in filter
            for rule in _filter["rules"]:
                rules_keys = rule.keys()
                for required_rule_f in self.required_rules_fields:
                    # Validate that required_rules_fields exists
                    if required_rule_f not in rules_keys:
                        logger.debug(rule)
                        raise FilterValidationError(f"Required rule field '{required_rule_f}' missing from rules in "
                                                    f"filter '{_filter['filterName']}'")

                    # Validate that required_rules_fields have a value
                    if not rule[required_rule_f]:
                        logger.debug(rule)
                        raise FilterValidationError(f"Required rule field '{required_rule_f}' is missing a value in "
                                                    f"filter '{_filter['filterName']}'")

                    # Validate that rule.func value is supported..
                    if rule["func"] not in self.filter_funcs.keys():
                        raise FilterValidationError(f"Unknown rule function '{rule['func']}' detected in "
                                                    f"filter '{_filter['filterName']}'")

        # Validate that a filterName(value) is only used once.
        uniq_filter_names = set(used_filter_names)
        if len(used_filter_names) > len(uniq_filter_names):
            raise FilterValidationError("A filterName(value) is used more than once. filterName should be uniq")

        logger.info("All filters validated successfully")

    def filter_stats(self) -> dict:
        """ Get all filter stats

            Maybe just return a 'nice' formatted string?
        """

        return {
            "filter_func_true_stats": self.filter_func_true_stats,
            "filter_func_stats": self.filter_func_stats,
            "filter_name_stats": self.filter_name_stats,
            "filtered_alert_name_stats": self.filtered_alert_name_stats,
            "not_filtered_alerts_stats": self.not_filtered_alerts_stats
        }

    def save_filter_stats(self) -> None:
        """ Save filter stats to file """
        with open(self.stats_file, "w") as f:
            json.dump(self.filter_stats(), f)

        logger.info(f"Saved filter stats to {self.stats_file}")

        return None

    def _load_filter_stats(self) -> None:
        """ Load saved filter stats from file to filter stats vars(if stats file exist """
        if not os.path.isfile(self.stats_file) or os.path.getsize(self.stats_file) == 0:
            # stats_file don't exists or is not empty. No stats to load..
            logger.info(f"No filter stats to load. {self.stats_file} don't exist or is empty.")
            return None

        with open(self.stats_file, "r") as f:
            stats = json.load(f)
            self.filter_func_true_stats = stats["filter_func_true_stats"]
            self.filter_func_stats = stats["filter_func_stats"]
            self.filter_name_stats = stats["filter_name_stats"]
            self.filtered_alert_name_stats = stats["filtered_alert_name_stats"]
            self.not_filtered_alerts_stats = stats["not_filtered_alerts_stats"]

        logger.info("Loaded filter stats")

        return None

    def run_filter(self, alert: Alert) -> bool:
        """ The function that implements the filtering logic """
        if not isinstance(alert, Alert):
            raise TypeError("Argument 'alert' is not type Alert")

        for _filter in self.filter_list:
            true_counter = 0
            len_filter = len(_filter.rules)  # THIS filter
            len_truth = len(self.truth[_filter.filterName])  # THIS filter
            logger.debug(f"filterName: {_filter.filterName}, len: {len_filter}, len_truth: {len_truth}")
            logger.debug(f"truth - {self.truth[_filter.filterName]}")

            # iterate and run each specific filter for this filter
            tmp_stats = dict()
            for rule in _filter.rules:
                try:
                    # Mapping filter rules to actual functions and exec (value, field)
                    if self.filter_funcs[rule.func](rule.value, alert.__dict__[rule.field]):
                        # This specific filter rule returned true.
                        # All filters in rule->[] must be True to actually filter the alert,
                        # except if a field is used multiple times

                        # This stats counter only count when each filter function returns True
                        # and do not have relation to "filter = true"
                        tmp_stats[rule.func] = tmp_stats.get(rule.func, 0) + 1
                        self.filter_func_true_stats[rule.func] = self.filter_func_true_stats.get(rule.func, 0) + 1
                        true_counter += 1
                except IndexError:
                    logger.critical(
                        "IndexError in 'filter_funcs[rule.func]' or 'alert[rule.field]'")
                    logger.exception(msg="IndexError in 'filter_funcs[rule.func]' or 'alert[rule.field]'",
                                     exc_info=True)
                    exit(1)

            if len_truth <= true_counter <= len_filter:
                # This check allows 'implicit OR' when a multiple of the same field is used in the same filter.
                # Ex field 'name' is used multiple times in rules->[].
                # Prolly better to use something like "if true_counter in range(len_truth, len_filter)"

                # Enough filter criteria's in rules->[] returned True aka filtering this alert.
                logger.info(f"Filtering alert '{alert.name}' with filter '{_filter.filterName}'")

                # Log stats for filter name
                self.filter_name_stats[_filter.filterName] = self.filter_name_stats.get(_filter.filterName, 0) + 1

                # Log stats for filter functions when this filter (not just 1 rule) returned true..
                for func_name, func_val in tmp_stats.items():
                    self.filter_func_stats[func_name] = self.filter_func_stats.get(func_name, 0) + func_val

                # Log stats for how many times 'alert.name' was filtered
                self.filtered_alert_name_stats[alert.name] = self.filtered_alert_name_stats.get(alert.name, 0) + 1
                return True

        # Not enough filter criteria's matched.. aka this alert should not be filtered..
        logger.debug(f"No filter matched for alert: '{alert.name}'")
        # Log stats for how many times 'alert.name' was _NOT_ filtered
        self.not_filtered_alerts_stats[alert.name] = self.not_filtered_alerts_stats.get(alert.name, 0) + 1

        return False


#### filter functions ####


def contains(value: str, field: str) -> bool:
    if value in field:
        logger.debug("filter match func 'contains()'")
        return True

    logger.debug(f"no 'contains()' match for value {value} on field {field}")
    return False
AlertFilter.filter_funcs["contains"] = contains


def not_contains(value: str, field: str) -> bool:
    if not (value in field):
        logger.debug("filter match func 'not_contains()'")
        return True
    logger.debug(f"no 'not_contains()' match for value {value} on field {field}")
    return False
AlertFilter.filter_funcs["not contains"] = not_contains


def regex_filter(compiled_pattern, field: str) -> bool:
    if compiled_pattern.search(field):
        logger.debug("filter match func 'regex_filter()'")
        return True

    logger.debug(f"no 'regex_filter()' match for value {compiled_pattern} on field {field}")
    return False
AlertFilter.filter_funcs["regex"] = regex_filter


def exactly(value: str, field: str) -> bool:
    if value == field:
        logger.debug("filter match func 'exactly()'")
        return True

    logger.debug(f"no 'exactly()' match for value {value} on field {field}")
    return False
AlertFilter.filter_funcs["exactly"] = exactly


def not_exactly(value: str, field: str) -> bool:
    if value != field:
        logger.debug("filter match func 'not_equal()'")
        return True

    logger.debug(f"no 'not_equal' match for value {value} on field {field}")
    return False
AlertFilter.filter_funcs["not exactly"] = exactly


def ip_in_cidr_range(value: str, field: str) -> bool:

    # ip_in_cidr_range_filter(CIDR ex 192.168.1.0/24, ip.addr)
    try:
        if IPAddress(field) in IPNetwork(value):
            logger.debug("filter match func 'ip_in_cidr_range()'")
            return True
    except AddrFormatError as e:
        logger.exception(msg=f"Is filter value '{value}' or field '{field}' a valid IP address?", exc_info=True)
        return False

    logger.debug(f"no 'ip_in_cidr_range()' match for value {value} on field {field}")
    return False
AlertFilter.filter_funcs["ip in cidr"] = ip_in_cidr_range


def ip_not_in_cidr_range(value: str, field: str) -> bool:
    if ip_in_cidr_range(value, field):
        # ip is in CIDR aka return False
        return False
    # IP is not in CIDR aka return True
    logger.debug("filter match func 'ip_not_in_cidr_range()'")
    return True
AlertFilter.filter_funcs["ip not in cidr"] = ip_not_in_cidr_range


def starts_with(value: str, field: str) -> bool:
    if field.startswith(value):
        return True
    return False
AlertFilter.filter_funcs["startswith"] = starts_with


def ends_with(value: str, field: str) -> bool:
    if field.endswith(value):
        return True
    return False
AlertFilter.filter_funcs["endswith"] = ends_with

