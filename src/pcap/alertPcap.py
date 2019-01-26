import datetime
import os
import requests
import logging
from src import config

logger = logging.getLogger("alertBot.pcap")

try:
    import pyshark
except ImportError as ie:
    logger.error("Package pyshark is not installed", ie)
    raise



# WINDOWS edit config.ini to change thark.exe path
# located in ..site-packages\pyshark
protocols = {
    6: "tcp",
    17: "udp"

}


def newest_pcapfile(pcap_dir):
    files = os.listdir(pcap_dir)
    #paths = [os.path.join(path, if basename.startswith("snort.log.") for basename in files)]

    paths = [os.path.join(pcap_dir, basename) for basename in files if basename.startswith("snort.log.")]

    newest_file = max(paths, key=os.path.getctime)
    paths.remove(newest_file)
    secound_newest_file = max(paths, key=os.path.getctime)

    #return newest_file, secound_newest_file

    return [newest_file, secound_newest_file]


def gen_alert_dict(pcap):
    alert_dict = {
        "tcp": {},
        "udp": {},
        "icmp": {}
    }

    for pkt in pcap:
        try:
            # alert_dict[int(pkt.tcp.stream)].append(pkt)
            # Generate dict by streams and corresponding packets
            proto = protocols[int(pkt.ip.proto)]
            try:
                alert_dict[proto][int(pkt[proto].stream)]
            except KeyError:
                alert_dict[proto][int(pkt[proto].stream)] = [pkt]
            else:
                alert_dict[proto][int(pkt[proto].stream)].append(pkt)

        except AttributeError:
            continue

    return alert_dict


def find_alert_stream(alert_time: datetime, pcap):
    """ Returns stream nr if found or None"""
    for pkt in pcap:
        #print(pkt)
        try:
            #print("pkt time: ", pkt.sniff_time, " alert time: ", alert_time)
            if pkt.sniff_time == alert_time:
                #print("found time match")
                logger.debug("found time match")

                proto = protocols[int(pkt.ip.proto)]
                #print(pkt[proto])
                logger.debug("protocol: %s", proto)
                #print(dir(pkt[proto]))
                #print(pkt[proto].dstport)
                #print(pkt["dns"])
                #print("proto: ", proto)
                #print(proto)
                #print(pkt.ip)
                #print("find_alert_stream Return: ", int(pkt[proto].stream), proto)
                return int(pkt[proto].stream), proto
        except AttributeError:
            continue

    # No stream found..
    #print("No stream found..")
    logger.info("No stream found in pcap..")
    return None


def parse(packets, proto="tcp"):
    pkt_proto = {
        53: "dns",
        80: "http",
        8080: "http",
        443: "ssl"
    }

    #print(packets)
    for pkt in packets:
        app_proto = pkt.highest_layer
        try:
            #print("highest_layer: ", app_proto)
            #print("pcap: ", str(pkt[str(app_proto).lower()]))
            #print(dir(pkt[str(app_proto).lower()]))
            pkt_protocol = protocols[int(pkt.ip.proto)]  # ex udp/tcp ..
            packet_data = {
                "src": pkt.ip.src,
                "src_port": pkt[pkt_protocol].srcport,
                "dest": pkt.ip.dst,
                "dest_port": pkt[pkt_protocol].dstport,
                "proto": pkt_protocol,
                "pcap": str(pkt[str(app_proto).lower()])
            }
            #print("Returning packet_data: ", packet_data)
            return packet_data
        except KeyError as ke:
            logger.debug(ke)
            #print(ke)
            continue

    logger.warning("No packets parsed..")
    #print("No packets parsed..")
    return None


def execute_search(pcap_file, alert_time):
    #print("Executing pcap search")
    alert_found = find_alert_stream(alert_time, pcap_file)
    #print("alert_found: ", alert_found)

    if not alert_found:
        logger.info("No PCAP/stream found for this alert..")
        return None

    stream, proto = alert_found

    alert_dict = gen_alert_dict(pcap_file)
    #print("alert_dict: ", alert_dict)

    packet_stream = alert_dict[proto][stream]

    parsed = parse(packets=packet_stream, proto=proto)
    #print(parsed)

    if not parsed:
        return None

    return parsed


def create_pcap_url(pcap_data: dict, alert: dict) -> str:
    logger.debug(pcap_data)
    #print("create_pcap_url: ", pcap_data)
    gen_url = config.misc.pcapGenUrl
    ignore_keys = ["pcap"]
    alert_details = "\n".join(f"{k}: {v}" for k, v in alert.items())
    message = alert_details + "\n#### Pcap Details ####\n" + "\n".join(f"{k}: {v}" for k, v in pcap_data.items() if k not in ignore_keys)

    r = requests.post(gen_url, json={"msg": message, "pcap": pcap_data["pcap"]})

    if r.status_code != 200:
        logger.warning(f"Response code not 200! Code: {r.status_code}")
        return "URL creation Error.."

    return r.json()["url"]


def get_alert_pcap(alert) -> str:
    pcap_dir = config.misc.pcapDir
    alert_time = datetime.datetime.strptime(alert["time"], '%m/%d/%y-%H:%M:%S.%f')
    for p_file in newest_pcapfile(pcap_dir):
        exe_search = execute_search(pyshark.FileCapture(p_file), alert_time)

        if exe_search:
            #pprint(exe_search)
            return create_pcap_url(exe_search, alert)

    logger.info("No PCAP data available ")
    return "No PCAP data available "

####
## use dir(pkt) to check atributes
# a = {
#     "time": "01/13/19-15:50:25.079495",
#     "name": "INDICATOR-COMPROMISE Suspicious .pw dns query",
#     "proto": "UDP",
#     "src": "192.168.1.50",
#     "src_port": 50258,
#     "dst": "192.168.1.1",
#     "dst_port": 53,
#
# }
