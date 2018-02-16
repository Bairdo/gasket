import mn
from readpcap import *
import time
import shutil


def avg(L):
    return sum(L) / float(len(L))


def test1(n):
    print('Test 1')
    times = []
    for i in range(1, n + 1):
        print('trial', i)

        pcap_file = 'pcaps/test1_%s.pcap' % i

        mn.start()
        mn.start_tcpdump(pcap_file)
        mn.set_up()
        mn.authenticate()
        print(mn.h0.cmd('ping 10.0.0.40 -c1'))
        mn.shut_down()

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

        mn.start()
        mn.start_tcpdump(pcap_file)
        mn.set_up()
        pid = mn.h0.cmd('ping 10.0.0.40 -i0.1 &')
        mn.authenticate()
        time.sleep(1)
        mn.h0.cmd('kill %s' % pid)
        mn.shut_down()

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

    for i in range(1, n + 1):
        print('trial', i)

        pcap_file = 'pcaps/test3_%s.pcap' % i

        mn.start()
        mn.start_tcpdump(pcap_file)
        mn.set_up()

        pid = mn.h0.cmd('ping 10.0.0.40 -i0.1 &')
        mn.authenticate()
        time.sleep(1)
        mn.h0.cmd('wpa_cli -i %s logoff' % 'h0-eth0')

        mn.wait_until_logoff()

        time.sleep(1)

        mn.h0.cmd('kill %s' % pid)

        time.sleep(5.1)

        mn.h0.cmd('wpa_cli -i %s logon' % 'h0-eth0')

        mn.wait_until_authenticate()

        time.sleep(1)

        mn.shut_down()

        auth_times.append(auth_time(pcap_file))
        ping_reply_times.append(ping_reply_time(pcap_file))
        logoff_times.append(logoff_time(pcap_file))
        reauth_times.append(reauth_time(pcap_file))
        reauth_ping_reply_times.append(reauth_ping_reply_time(pcap_file))
        save_CSV(3, auth_times, ping_reply_times,
                 logoff_times, reauth_times, reauth_ping_reply_times)

        # uncomment to create backups of etc file
        # shutil.move('../etc', 'etc_backups/3/etc_%s'%i)
        # shutil.copytree('etc', '../etc')

        time.sleep(10)

    print(n, 'trials')
    print('Avg auth time: %ss' % avg(auth_times))
    print('Avg ping reply time: %ss' % avg(ping_reply_times))
    print('Avg logoff time: %ss' % avg(logoff_times))
    print('Avg reauth time: %ss' % avg(reauth_times))
    print('Avg reauth ping reply time: %ss' % avg(reauth_ping_reply_times))

if __name__ == '__main__':
    test3(1)
