import re
import logging
from netaddr import IPNetwork, IPAddress, AddrFormatError
import munch

logger = logging.getLogger("alertBot.filter")


class AlertFilter:

    filter_funcs = {}

    def __init__(self, filter_list: list):
        # munchify filter_list so we can use dot notations when referencing dict keys
        # Also compile any regex patterns in filter_list
        self.filterList = munch.munchify(self.compile_regex(filter_list))
        # Sort filter_list so that we start with the most specific filter e.g the filter with most rules comes first
        self.filter_list = sorted(self.filterList, key=lambda f: len(f["rules"]), reverse=True)
        # Generate truth_index so that we can use implicit OR
        # when a filter have multiple rules with a multiple of the same filed
        self.truth = self.truth_index()
        # Filtering stats
        self.filter_func_true_stats = {}
        self.filter_func_stats = {}
        self.filter_name_stats = {}

    def truth_index(self) -> dict:
        index = {}
        for f in self.filter_list:
            field_val = {}
            for r in f["rules"]:
                field_val[r["field"]] = field_val.get(r["field"], 0) + 1

            index[f["filterName"]] = field_val

        return index

    def compile_regex(self, filter_list: list):
        # Validate and compile regex
        for _filter in filter_list:
            for rule in _filter["rules"]:
                if rule["func"] == "regex":
                    rule["value"] = self.validate_regex(rule["value"], _filter["filterName"])

        return filter_list

    def validate_regex(self, pattern: str, filter_name: str):
        try:
            validated = re.compile(pattern)
        except re.error as regexerror:
            print(regexerror)
            print(f"<Invalid regular expression '{pattern}' in filter '{filter_name}'>")
            exit(1)
        else:
            return validated

    def validate_filter_list(self):
        # Validate that filter_list have all fields..
        try:
            for _filter in self.filter_list:
                if not _filter["filterName"]:
                    raise Exception(f"Filter missing 'filterName' field\n {_filter}")

                if not _filter["rules"]:
                    raise Exception(f"Filter missing 'rules' field\n {_filter}")

                for rule in _filter["rules"]:

                    if not rule["func"]:
                        raise Exception(f"Filter missing 'func' field\n {_filter}")

                    if not rule["func"] in self.filter_funcs.keys():
                        raise Exception(f"Filter func '%s' not valid\n {_filter}" % rule["func"])

                    if not rule["value"]:
                        raise Exception(f"Filter missing 'value' field\n {_filter}")

                    if not rule["field"]:
                        raise Exception(f"Filter missing 'field' field\n {_filter}")
        except KeyError:
            logger.critical("Missing fields in filter list")
            raise

    def run_filter(self, alert: munch.Munch) -> bool:
        """ 200 iq function """
        if not isinstance(alert, munch.Munch):
            alert = munch.munchify(alert)

        for _filter in self.filter_list:
            true_counter = 0
            len_filter = len(_filter.rules)  # THIS filter
            len_truth = len(self.truth[_filter.filterName])  # THIS filter
            logger.debug(f"filterName: {_filter.filterName}, len: {len_filter}, len_truth: {len_truth}")
            logger.debug(f"truth - {self.truth[_filter.filterName]}")

            # iterate and run each specific filter for this filter
            tmp_stats = {}
            for rule in _filter.rules:
                try:
                    # Mapping filter rules to actual functions and exec (value, field)
                    if self.filter_funcs[rule.func](rule.value, alert[rule.field]):
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

                # Log stats for filter functions when this filter returned true..
                for func_name, func_val in tmp_stats.items():
                    self.filter_func_stats[func_name] = self.filter_func_stats.get(func_name, 0) + func_val
                return True

        # Not enough filter criteria's matched.. aka this alert should not be filtered..
        logger.debug(f"No filter matched for alert '{alert.name}'. NOT filtering")
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

