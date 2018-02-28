
import argparse
import time
import shutil

import mn
from readpcap import *

def avg(L):
    print(L)
    return sum(L) / float(len(L))


def test1(n):
    print('Test 1')
    times = []
    for i in range(1, n + 1):
        print('trial', i)

        pcap_file = 'pcaps/test1_%s.pcap' % i

        hosts = mn.start()
        h0 = hosts[0]
        mn.start_tcpdump(h0, pcap_file)
        mn.set_up()
        mn.authenticate(h0)
        print(h0.cmd('ping 10.0.0.40 -c1'))
        mn.shut_down(hosts)

        times.append(auth_time(pcap_file))
        save_CSV(1, times)

        time.sleep(10)

    print('Avg auth time: %ss' % avg(times))


def test2(n):
    print('Test 2')

    auth_times = []
    ping_reply_times = []

    for i in range(1, n + 1):
        print('trial', i)

        pcap_file = 'pcaps/test2_%s.pcap' % i

        hosts = mn.start()
        h0 = hosts[0]
        mn.start_tcpdump(h0, pcap_file)
        mn.set_up()
        pid = h0.cmd('ping 10.0.0.40 -i0.1 &')
        mn.authenticate(h0)
        time.sleep(1)
        mn.shut_down(hosts)

        auth_times.append(auth_time(pcap_file))
        ping_reply_times.append(ping_reply_time(pcap_file))
        save_CSV(2, auth_times, ping_reply_times)

        time.sleep(10)

    print('Avg auth time: %ss' % avg(auth_times))
    print('Avg ping reply time: %ss' % avg(ping_reply_times))


def test3(n):
    print('Test 3')

    auth_times = []
    ping_reply_times = []
    logoff_times = []
    reauth_times = []
    reauth_ping_reply_times = []

    shutil.rmtree('etc_backups/3', ignore_errors=True)

    for i in range(n):
        if os.path.isdir('etc'):
            shutil.rmtree('etc')
        shutil.copytree('etc-read-only', 'etc')
        print('trial', i)

        pcap_file = 'pcaps/test3_%s.pcap' % i

        hosts = mn.start()
        h0 = hosts[0]
        print('mn started')
        mn.start_tcpdump(h0, pcap_file)
        mn.start_tcpdump(mn.NET.get('i0'), 'pcaps/test3_i0_%d.pcap' % i)
        print('tcpdump started')
        mn.set_up()
        print('setup completed')
        pid = h0.cmd('ping 10.0.0.40 -i0.1 &')
        mn.authenticate(h0)
        time.sleep(1)
        h0.cmd('wpa_cli -i %s logoff' % 'h0-eth0')

        mn.wait_until_logoff(h0)

        time.sleep(5)

        h0.cmd('kill %s' % pid)

        time.sleep(5.1)

        h0.cmd('wpa_cli -i %s logon' % 'h0-eth0')

        mn.wait_until_authenticate(h0)

        time.sleep(1)

        mn.shut_down(hosts)
        at = auth_time(pcap_file)
        auth_times.append(at)

        ping_reply_times.append(ping_reply_time(pcap_file))
        logoff_times.append(logoff_time(pcap_file))

        reauth_times.append(reauth_time(pcap_file))
        reauth_ping_reply_times.append(reauth_ping_reply_time(pcap_file))
        save_CSV(3, auth_times, ping_reply_times,
                 logoff_times, reauth_times, reauth_ping_reply_times)

        # uncomment to create backups of etc file
        shutil.move('../etc', 'etc_backups/3/etc_%s' % i)
        shutil.copytree('etc', '../etc')
        print('trial completed')
        time.sleep(10)

    print(n, 'trials')
    print('ats', auth_times)
    print('Avg auth time: %ss' % avg(auth_times))
    print('prt', ping_reply_times)
    print('Avg ping reply time: %ss' % avg(ping_reply_times))
    print('lt', logoff_times)
    print('Avg logoff time: %ss' % avg(logoff_times))
    print('rt', reauth_times)
    print('Avg reauth time: %ss' % avg(reauth_times))
    print('rprt', reauth_ping_reply_times)
    print('Avg reauth ping reply time: %ss' % avg(reauth_ping_reply_times))

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('num_runs', help='Number of runs of each test', type=int)
    args = parser.parse_args()

    test3(args.num_runs)
