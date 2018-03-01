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

    for ts, pkt in dpkt.pcap.Reader(open(filename, 'r')):
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type == 0x888e:
            if start is None and eth.data == EAP_START_DATA:
                start = ts
            elif len(eth.data) > EAP_SUCCESS_LEN and ord(eth.data[4]) == 3:
                end = ts
                break

    if start is not None and end is not None:
        return (end - start)
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
                src = '.'.join(str(ord(x)) for x in eth.data.src)
                dst = '.'.join(str(ord(x)) for x in eth.data.dst)
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
                src = '.'.join(str(ord(x)) for x in eth.data.src)
                dst = '.'.join(str(ord(x)) for x in eth.data.dst)
                if src == internet_ip and dst == client_ip:
                    end = ts
                    break

    if start is not None and end is not None:
        return (end - start)
    return 'N/A'


def get_ICMP_info(eth):
    src = '.'.join(str(ord(x)) for x in eth.data.src)
    dst = '.'.join(str(ord(x)) for x in eth.data.dst)
    seq = eth.data.data.data.seq
    return src, dst, seq


def save_CSV(test_name, data):
    filename = 'results/%s.csv' % test_name

    with open(filename, 'a') as file:
        file.write('\n' + ', '.join([str(i) for i in data]))


def check_valid_results(results):
    print('cvr', results)

    old_length = len(results)
    filter(lambda a: a != 'N/A', results)
    new_length = len(results)
    if old_length != new_length:
        print('errors: %d with results' % (old_length - new_length))


def read_folder(dir_name):
    auth_times = []
    ping_reply_times = []
    logoff_times = []
    reauth_times = []
    reauth_ping_reply_times = []

    for filename in sorted(os.listdir(dir_name), key=lambda x: int(x.split('_')[1][:-5])):
        print(filename)
        pcap_file = dir_name + '/' + filename
        auth_times.append(auth_time(pcap_file))
        ping_reply_times.append(ping_reply_time(pcap_file))
        logoff_times.append(logoff_time(pcap_file))
        reauth_times.append(reauth_time(pcap_file))
        reauth_ping_reply_times.append(reauth_ping_reply_time(pcap_file))
        save_CSV(3, auth_times, ping_reply_times,
                 logoff_times, reauth_times, reauth_ping_reply_times)

if __name__ == '__main__':
        # print 'Auth Time: %ss' % auth_time('pcaps/test3_1.pcap')
        # print 'Ping Reply Time: %ss' % ping_reply_time('tcpdump')
        # print 'Logoff Time: %ss' % logoff_time('tcpdump3')
        # print 'Reauth Time: %ss' % reauth_time('pcaps/test3_1.pcap')
        # print 'Reauth Ping Reply Time: %ss' %
        # reauth_ping_reply_time('pcaps/test3_1.pcap')

    read_folder('test_results_1/pcaps')
