
import argparse
from datetime import datetime
import time
import shutil

import mn
from readpcap import *


PCAP_FORMAT_STRING = '%s/%s_%d_%s.pcap'


def avg(list_):
    """Mean average
    Args:
        list_   (list<floats>): numbers to take mean of.
    """
    print(list_)
    return sum(list_) / float(len(list_))


def dir_setup():
    """Creates needed directories if dont exist.
    """
    if not os.path.isdir('results'):
        os.mkdir('results')
    if not os.path.isdir('pcaps'):
        os.mkdir('pcaps')


def setup():
    """cleans the environment.
    """
    if os.path.isdir('etc-test'):
        shutil.rmtree('etc-test')
    shutil.copytree('etc', 'etc-test')

    if os.path.isdir('docker-compose-test'):
        shutil.rmtree('docker-compose-test')
    shutil.copytree('docker-compose', 'docker-compose-test')


    os.system('ovs-vsctl del-br s1')
    os.system(('docker stop {0}_gasket_1 {0}_hostapd_1 ' +
               '{0}_freeradius_1 {0}_rabbitmq_server_1 ' +
               '{0}_rabbitmq_adapter_1 {0}_faucet_1').format('performancetests'))


def start(pcap_dir, test_name, run_no, no_hosts):
    """starts mininet and tcpdumps, and docker containers.
    Args:
        pcap_dir    (str): directory to save pcap files in.
        test_name   (str):
        test_no     (int): run number.
    """
    hosts = mn.start(no_hosts)
    h0 = hosts[0]
    print('mn started')
    mn.start_tcpdump(h0, PCAP_FORMAT_STRING % (pcap_dir, test_name, run_no, h0.name))
    i0 = mn.NET.get('i0')
    mn.start_tcpdump(i0, PCAP_FORMAT_STRING % (pcap_dir, test_name, run_no, i0.name))
    print('tcpdump started')
    mn.set_up()
    print('setup completed')
    return hosts


def clean_up(test_name, test_no):
    """backsup the files used for the test.
    Args:
        test_name   (str):
        test_no     (int): run number.
    """
    shutil.move('etc-test', 'test-backups/%s/%d/etc' % (test_name, test_no))
    shutil.move('docker-compose-test', 'test-backups/%s/%d/docker-compose' % (test_name, test_no))
    shutil.move('hostapd.log', 'test-backups/%s/%d/hostapd.log' % (test_name, test_no))
    shutil.move('faucet-perftests.log', 'test-backups/%s/%d/faucet.log' % (test_name, test_no))
    shutil.move('faucet-adapter-perftests.log',
                'test-backups/%s/%d/faucet-adapter.log' % (test_name, test_no))


def createCSV(filename, headers):
    """Create the CSV header.
    Args:
        filename    (str):
        headers     (list): header names.
    """
    with open(filename, 'w+') as file:
        file.write(', '.join([str(h) for h in headers]))


def test3(n, pcap_dir):
    """Test that logs on, off and then back on.
    """
    print('Test 3')

    auth_times = []
    ping_reply_times = []
    logoff_times = []
    reauth_times = []
    reauth_ping_reply_times = []

    dir_setup()
    createCSV('results/%s.csv' % test3.__name__,
              ['test_duration', 'auth_time', 'ping_reply_time',
               'logoff_time', 'reauth_time', 'reauth_ping_reply_time'])
    for i in range(n):

        print('trial', i)
        start_time = datetime.now()
        setup()
        hosts = start(pcap_dir, test3.__name__, i, 2) # TODO not sure why this needs to be 2.
        h0 = hosts[0]
        i0 = mn.NET.get('i0')
        pid = h0.cmd('ping 10.0.0.40 -i0.1 &')
        mn.authenticate(h0)
        time.sleep(1)
        h0.cmd('wpa_cli -i %s-eth0 logoff' % h0.name)

        mn.wait_until_logoff(h0)

        time.sleep(5)

        h0.cmd('kill %s' % pid)

        time.sleep(5.1)

        h0.cmd('wpa_cli -i %s-eth0 logon' % h0.name)

        mn.wait_until_authenticate(h0)

        time.sleep(1)

        # shutdown
        log_location = './'
        mn.shut_down(hosts, log_location)
        # record
        pcap_file = PCAP_FORMAT_STRING % (pcap_dir, test3.__name__, i, h0.name)
        at = auth_time(pcap_file)
        auth_times.append(at)
        prt = ping_reply_time(pcap_file, h0.IP(), i0.IP())
        ping_reply_times.append(prt)
        lt = logoff_time(pcap_file, h0.IP(), i0.IP())
        logoff_times.append(lt)
        rat = reauth_time(pcap_file)
        reauth_times.append(rat)
        rprt = reauth_ping_reply_time(pcap_file, h0.IP(), i0.IP())
        reauth_ping_reply_times.append(rprt)

        time_taken = datetime.now() - start_time
        save_CSV(test3.__name__, [time_taken, at, prt, lt, rat, rprt])

        # cleanup
        clean_up(test3.__name__, i)
        print('trial completed')
        time.sleep(10)

    print(n, 'trials')
    print('ats', auth_times)
    check_valid_results(auth_times)
    print('Avg auth time: %ss' % avg(auth_times))
    print('prt', ping_reply_times)
    check_valid_results(ping_reply_times)
    print('Avg ping reply time: %ss' % avg(ping_reply_times))
    print('lt', logoff_times)
    check_valid_results(logoff_times)
    print('Avg logoff time: %ss' % avg(logoff_times))
    print('rt', reauth_times)
    check_valid_results(reauth_times)
    print('Avg reauth time: %ss' % avg(reauth_times))
    print('rprt', reauth_ping_reply_times)
    check_valid_results(reauth_ping_reply_times)
    print('Avg reauth ping reply time: %ss' % avg(reauth_ping_reply_times))


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('num_runs', help='Number of runs of each test', type=int)
    parser.add_argument('-p', '--pcap_dir', help='path to directory for pcaps', type=str)
    args = parser.parse_args()

    test3(args.num_runs, args.pcap_dir)
