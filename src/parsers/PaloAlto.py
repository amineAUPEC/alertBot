import logging
import datetime
from pan import xapi
import xml.etree.ElementTree as etree
from typing import List

from src.misc.utils import url_sanitizer
from src.abstraction.interface import IFaceHTTPSource

logger = logging.getLogger("alertBot.PaloAlto")


class PA(xapi.PanXapi):
    """ PA class to wrap PanXapi results to dict/JSON
    All functions below is mostly stolen from pan.config.PanConfig so don't blame me for trashy code

    I guess this is cleaner than;
        try:
            palo = xapi.PanXapi(tag="pa-100", api_key=apikey, hostname="<ip>", port=443)
        except xapi.PanXapiError as msg:
            print('pan.xapi.PanXapi:', msg, file=sys.stderr)
            sys.exit(1)

        # Get logs "cmd"
        palo.log(log_type="threat", nlogs=2)
        pprint(palo.xml_python())

        def result_to_json(elem):
            "" XMl response to JSON.. ""
            # https://github.com/kevinsteves/pan-python/blob/200342c37d98bd3c8cf59e13f410711ac1034f88/bin/panxapi.py#L699
            # https://github.com/kevinsteves/pan-python/blob/master/lib/pan/config.py#L135
            xpath = '*'
            conf = PanConfig(config=elem)
            j = conf.python(xpath)
            return j
            # print(json.dumps(j, sort_keys=True, separators=(',', ': '), indent=2))
            #return json.dumps(j, sort_keys=True, separators=(',', ': '), indent=2)


        # json_result = result_to_json(palo.element_result)
        # pprint(json_result)
    """

    def __init__(self, ip: str, port: int, apikey: str, tag="pan-100"):
        super().__init__(tag=tag, api_key=apikey, hostname=ip, port=port)

    def __find_xpath(self, root_elem, xpath=None):
        # Not a true Xpath
        # http://docs.python.org/dev/library/xml.etree.elementtree.html#xpath-support
        if xpath:
            try:
                # nodes = self.config_root.findall(xpath)
                # nodes = root_elem(xpath)
                nodes = etree.fromstring(root_elem).findall(xpath)
            except SyntaxError as msg:
                raise Exception('ElementTree.find SyntaxError: %s' % msg)
        else:
            nodes = [root_elem]

        return nodes

    def __serialize_py(self, elem, obj, forcelist=False):
        _tags_forcelist = set(['entry', 'member'])

        tag = elem.tag
        text = elem.text
        tail = elem.tail  # unused
        text_strip = None
        if text:
            text_strip = text.strip()
        attrs = elem.items()

        if forcelist:
            if tag not in obj:
                obj[tag] = []
            if not len(elem) and not text_strip and not attrs:
                obj[tag].append(None)
                return
            if not len(elem) and text_strip and not attrs:
                obj[tag].append(text)
                return

            obj[tag].append({})
            o = obj[tag][-1]

        else:
            if not len(elem) and not text_strip and not attrs:
                obj[tag] = None
                return
            if not len(elem) and text_strip and not attrs:
                if text_strip == 'yes':
                    obj[tag] = True
                elif text_strip == 'no':
                    obj[tag] = False
                else:
                    obj[tag] = text
                return

            obj[tag] = {}
            o = obj[tag]

        for k, v in attrs:
            #            o['@' + k] = v
            o[k] = v

        if text_strip:
            o[tag] = text

        if len(elem):
            tags = {}
            for e in elem:
                if e.tag in tags:
                    tags[e.tag] += 1
                else:
                    tags[e.tag] = 1
            for e in elem:
                forcelist = False
                if e.tag in _tags_forcelist or tags[e.tag] > 1:
                    forcelist = True
                self.__serialize_py(e, o, forcelist)

    def python_dict(self, elem, xpath=None):
        """ Original name python(..)"""
        nodes = self.__find_xpath(elem, xpath)
        if not nodes:
            return None

        d = {}
        if len(nodes) > 1:
            for _elem in nodes:
                self.__serialize_py(_elem, d)
        else:
            self.__serialize_py(nodes[0], d)

        return d

    def query_result(self, xapi=None, result=False):
        """ Returns dict
            Original name xml_python(..)
        """
        xpath = None
        if result:
            if self.element_result is None or not len(self.element_result):
                return None
            elem = self.element_result
            # select all child elements
            xpath = '*'
        else:
            if self.element_root is None:
                return None
            elem = self.element_root

        # try:
        #     conf = pan.config.PanConfig(config=elem)
        # except pan.config.PanConfigError as msg:
        #     print('pan.config.PanConfigError:', msg, file=sys.stderr)
        #     sys.exit(1)

        d = self.python_dict(elem, xpath)
        # d = conf.python(xpath)

        return d


class PaloAltoParser(IFaceHTTPSource):
    """ Idiot class to follow the 'parser class paradigm' in the project """

    def __init__(self, sensor_config: dict, dateformat: str = ""):

        self.sensor_config = sensor_config

        # Output date format - see datetime for formatting options. For future work..
        self._dateformat = "%Y-%m-%d %H:%M:%S.%f"
        if dateformat:
            self._dateformat = dateformat

        # Init PA API class
        try:
            self.palo = PA(ip=self.sensor_config["ip"], port=self.sensor_config["port"], apikey=self.sensor_config["apikey"])
        except xapi.PanXapiError as msg:
            logger.error('pan.xapi.PanXapi: %s', msg)
            exit(1)

    def threat_log(self, threat_logs: List[dict]) -> List[dict]:
        """ 'parse' Palo Alto threat logs """

        alerts = []

        for alert in threat_logs:
            logger.debug(alert)
            # print(alert)
            new_alert = {
                "time": datetime.datetime.strptime(alert['time_generated'],
                                                   "%Y/%m/%d %H:%M:%S").strftime(self._dateformat),
                "name": alert['threatid'],
                "src": alert['src'],
                "dest": alert['dst'],
                "proto": alert['proto'],
                "action": alert["action"],
                "direction": alert["direction"],
                "app": alert['app'],
                "rule": alert['rule'],
                "subtype": alert['subtype'],
                "category": alert['thr_category'],
                "severity": alert['severity'],
                "seqno": int(alert['seqno']),
                # Below is temp work around. Dont work if src/dst dont have 'code'
                "dstloc": alert['dstloc']['code'] if alert['dstloc']['code'].isalpha() else "rfc1918",
                "srcloc": alert['srcloc']['code'] if alert['srcloc']['code'].isalpha() else "rfc1918"
            }

            try:
                new_alert["misc"] = url_sanitizer(alert["misc"])
            except KeyError:
                # All alerts dont contain misc field..
                logger.debug("Alert dont contain misc field..")

            alerts.append(new_alert)

        return alerts

    def search(self, seqno: int) -> list:
        """ Execute search """
        # ( seqno geq 30334 ) and !( seqno eq 30334 )
        search_filter = f"( seqno geq {seqno} ) and !( seqno eq {seqno} )"
        logger.debug(f"PA query filter '{search_filter}'")

        self.palo.log(log_type=self.sensor_config["logType"],
                      nlogs=self.sensor_config["nlogs"], filter=search_filter)

        json_res = self.palo.query_result()

        try:
            logs = json_res["response"]["result"]["log"]["logs"]["entry"]
        except KeyError:
            # No new alerts..
            logger.debug("No new logs from PA..")
            logs = []

        # must sort received logs in order to 'increment' var current_seqno
        # else we're gonna get the same alerts multiple times..
        return sorted(self.threat_log(logs), key=lambda s: s["seqno"], reverse=False)

