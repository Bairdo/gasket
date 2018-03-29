import os

import dpkt


EAP_LOGOFF_DATA = '\x02\x02\x00\x00'
EAP_START_DATA = '\x02\x01\x00\x00'
EAP_SUCCESS_LEN = 4

ETHER_EAP = 0x888e
ETHER_IPV4 = 0x800


def auth_time(filename):
    """Time from eap-start to success.
    """
    start = end = None
    try:
        for ts, pkt in dpkt.pcap.Reader(open(filename, 'r')):
            eth = dpkt.ethernet.Ethernet(pkt)
            if eth.type == ETHER_EAP:
                if start is None and eth.data == EAP_START_DATA:
                    start = ts
                elif len(eth.data) > EAP_SUCCESS_LEN and ord(eth.data[4]) == 3:
                    end = ts
                    break

        if start is not None and end is not None:
            return (end - start)
    except dpkt.NeedData:
        pass
    return 'N/A'


def ping_reply_time(filename, client_ip, internet_ip):
    """Time from eap-start to first ping reply.
    """
    start = end = None

    for ts, pkt in dpkt.pcap.Reader(open(filename, 'r')):
        eth = dpkt.ethernet.Ethernet(pkt)
        if start is None:
            if eth.type == ETHER_EAP and len(eth.data) > EAP_SUCCESS_LEN and ord(eth.data[4]) == 3:
                start = ts
        else:
            if eth.type == ETHER_IPV4:
                src = get_eth_address(eth.data.src)
                dst = get_eth_address(eth.data.dst)
                if src == internet_ip and dst == client_ip:
                    end = ts
                    break

    if start is not None and end is not None:
        return (end - start)
    return 'N/A'


def logoff_time(filename, client_ip, internet_ip):
    """Time from eap-logoff to first ping that does not get a reply.
    """
    start = end = None

    packets = list(dpkt.pcap.Reader(open(filename, 'r')))

    for ts, pkt in packets:
        eth = dpkt.ethernet.Ethernet(pkt)
        if start is None:
            if eth.type == ETHER_EAP and eth.data == EAP_LOGOFF_DATA:
                start = ts
        else:
            if eth.type == ETHER_IPV4:
                src, dst, seq = get_ICMP_info(eth)
                if src == client_ip and dst == internet_ip:
                    for _, pkt2 in packets:
                        eth2 = dpkt.ethernet.Ethernet(pkt2)
                        if eth2.type == ETHER_IPV4:
                            src2, dst2, seq2 = get_ICMP_info(eth2)

                            if src2 == dst and dst2 == src and seq2 == seq:
                                break
                    else:
                        end = ts
                        break

    if start is not None and end is not None:
        return (end - start)
    return 'N/A'


def reauth_time(filename):
    """Time from the (after logoff) eap-start to eap-success.
    """
    logoff = False
    start = end = None

    for ts, pkt in dpkt.pcap.Reader(open(filename, 'r')):
        eth = dpkt.ethernet.Ethernet(pkt)
        if not logoff:
            if eth.type == ETHER_EAP and eth.data == EAP_LOGOFF_DATA:
                logoff = True
            else:
                continue

        elif eth.type == ETHER_EAP:
            if start is None and eth.data == EAP_START_DATA:
                start = ts
            elif len(eth.data) > EAP_SUCCESS_LEN and ord(eth.data[4]) == 3:
                end = ts
                break

    if start is not None and end is not None:
        return (end - start)
    return 'N/A'


def reauth_ping_reply_time(filename, client_ip, internet_ip):
    """Time from the eap-start (after eap-logoff) to first successful ping reply.
    """
    logoff = False
    start = end = None

    for ts, pkt in dpkt.pcap.Reader(open(filename, 'r')):
        eth = dpkt.ethernet.Ethernet(pkt)
        if not logoff:
            if eth.type == ETHER_EAP and eth.data == EAP_LOGOFF_DATA:
                logoff = True
            else:
                continue

        if start is None:
            if eth.type == ETHER_EAP and len(eth.data) > EAP_SUCCESS_LEN and ord(eth.data[4]) == 3:
                start = ts
        else:
            if eth.type == ETHER_IPV4:
                src = get_eth_address(eth.data.src)
                dst = get_eth_address(eth.data.dst)
                if src == internet_ip and dst == client_ip:
                    end = ts
                    break

    if start is not None and end is not None:
        return (end - start)
    return 'N/A'


def get_ICMP_info(eth):
    src = get_eth_address(eth.data.src)
    dst = get_eth_address(eth.data.dst)
    seq = eth.data.data.data.seq
    return src, dst, seq


def get_eth_address(address):
    """
    Args:
        address (eth.data.src/dst):
    """
    return '.'.join(str(ord(x)) for x in address)


def save_CSV(test_name, data):
    filename = 'results/%s.csv' % test_name

    with open(filename, 'a') as file:
        file.write('\n' + ', '.join([str(i) for times in data for i in times]))


def check_valid_results(results):
    print('cvr', results)

    old_length = len(results)
    filter(lambda a: a != 'N/A', results)
    new_length = len(results)
    if old_length != new_length:
        print('errors: %d with results' % (old_length - new_length))
