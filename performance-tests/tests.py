
import argparse
from datetime import datetime
import errno
import os
import time
import shutil

import mn

import readpcap


PCAP_FORMAT_STRING = '%s/%s_%d_%s.pcap'


def avg(list_):
    """Mean average
    Args:
        list_   (list<floats>): numbers to take mean of.
    """
    print(list_)
    return sum(list_) / float(len(list_))


def dir_setup(pcap_dir_base, test_name, no_runs):
    """Creates needed directories if dont exist.
    """

    def delete_and_make_dir(path):
        try:
            os.makedirs(path)
        except OSError as ex:
            if ex.errno == errno.EEXIST and os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
                os.makedirs(path)
            else:
                raise

    if not os.path.isdir('results'):
        os.mkdir('results')
    if not os.path.isdir('test-backups'):
        os.mkdir('test-backups')


    for i in range(no_runs):
        path = '%s/%s/%d' % (pcap_dir_base, test_name, i)
        delete_and_make_dir(path)


def setup(hostapd_port_no):
    """cleans the environment.
    """
    if os.path.isdir('etc-test'):
        shutil.rmtree('etc-test')
    shutil.copytree('etc', 'etc-test')


    with open('etc-test/ryu/faucet/faucet.yaml', 'r') as faucet:
        txt = faucet.read()

    host_ports_conf = ''
    for i in range(2, hostapd_port_no):
        host_ports_conf = r'''%s
            %d:
                native_vlan: 100
                acl_in: port_faucet-1_%d
''' % (host_ports_conf, i, i)

    with open('etc-test/ryu/faucet/faucet.yaml', 'w') as faucet:
        faucet.write(txt % {'host_ports' : host_ports_conf, 'hostapd_port': hostapd_port_no})


    with open('etc-test/ryu/faucet/faucet-acls.yaml', 'a') as faucet_acls:
        for i in range(2, hostapd_port_no):
            acl = '''  port_faucet-1_%d:
  - rule:
      actions:
        allow: 1
        output:
          dl_dst: '44:44:44:44:44:44'
      dl_type: 34958
  - rule:
      actions:
        allow: 1
        output:
          dl_dst: '44:44:44:44:44:44'
''' % i
            faucet_acls.write(acl)


    with open('etc-test/ryu/faucet/gasket/base-no-authed-acls.yaml', 'a') as gasket_acls:
        for i in range(2, hostapd_port_no):
            acl = '''    port_faucet-1_%d:
    - rule:
        actions:
            allow: 1
            output:
                dl_dst: '44:44:44:44:44:44'
        dl_type: 34958
    - authed-rules
    - rule:
        actions:
            allow: 1
            output:
                dl_dst: '44:44:44:44:44:44'
''' % i
            gasket_acls.write(acl)


    with open('etc-test/ryu/faucet/gasket/auth.yaml', 'r') as gasket_auth:
        txt = gasket_auth.read()

    host_ports_conf = ''
    for i in range(2, hostapd_port_no):
        host_ports_conf = '''%s
            %d:
                auth_mode: access
''' % (host_ports_conf, i)

    with open('etc-test/ryu/faucet/gasket/auth.yaml', 'w') as gasket_auth:
        gasket_auth.write(txt % {'host_ports' : host_ports_conf, 'hostapd_port' : hostapd_port_no})


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
    print('mn started')
    for host in hosts:
        mn.start_tcpdump(host, PCAP_FORMAT_STRING % (pcap_dir, test_name, run_no, host.name))

    i0 = mn.NET.get('i0')
    mn.start_tcpdump(i0, PCAP_FORMAT_STRING % (pcap_dir, test_name, run_no, i0.name))
    print('tcpdumps started')
    mn.set_up(pcap_dir)
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


def authenticate(host):
    print(host.cmdPrint('wpa_supplicant -f etc-test/{0}/wpa.log -Dwired -i{0}-eth0 -cetc-test/{0}/host-wpa.conf -B -W'.format(host.name)))

    print(host.cmdPrint('wpa_cli -a etc-test/{0}/host-action.sh > /tmp/qwerty.uio 2>&1 &'.format(host.name)))



def test_many_hosts(no_runs, pcap_dir_base, no_hosts):
    """n hosts all logon, logoff, logon again.
    """
    test_name = '%s_%d' % (test_many_hosts.__name__, no_hosts)
    auth_matrix = [[0 for x in range(no_hosts)] for y in range(no_runs)]
    prt_matrix = [[0 for x in range(no_hosts)] for y in range(no_runs)]
    logoff_times_matrix = [[0 for x in range(no_hosts)] for y in range(no_runs)]
    reauth_times_matrix = [[0 for x in range(no_hosts)] for y in range(no_runs)]
    reauth_ping_matrix = [[0 for x in range(no_hosts)] for y in range(no_runs)]

    dir_setup(pcap_dir_base, test_name, no_runs)

    headers = ['test_duration']
    for header in ['auth', 'ping_reply', 'logoff', 'reauth_time', 'reauth_ping_reply']:
        for i in range(no_hosts):
            headers.append('h%d-%s' % (i, header))
    createCSV('results/%s.csv' % test_name, headers)

    for run_no in range(no_runs):

        start_time = datetime.now()
        pcap_dir = '%s/%s/%d'  % (pcap_dir_base, test_name, run_no)
        setup(no_hosts + 2)
        hosts = start(pcap_dir, test_name, run_no, no_hosts)
        i0 = mn.NET.get('i0')
        # do the stuff here.
        # ...
        i = -1
        for host in hosts:
            i += 1
            os.mkdir('etc-test/%s' % host.name)
            shutil.copy('host-action.sh', 'etc-test/%s/host-action.sh' % host.name)
            shutil.copy('host-wpa.conf', 'etc-test/%s/host-wpa.conf' % host.name)
            with open('etc-test/%s/host-wpa.conf' % host.name, 'r') as wpa_file:
                wpa_conf = wpa_file.read()

            with open('etc-test/%s/host-wpa.conf' % host.name, 'w') as wpa_file:
                wpa_file.write(wpa_conf % {'IDENTITY' : 'host%duser' % i,
                                           'PASSWORD' : 'host%dpass' % i})
            host.cmd('ping %s -i0.1 &' % i0.IP())

        for host in hosts:
            authenticate(host)

        time.sleep(60)

        log_location = './'
        mn.shut_down(hosts, log_location)

        host_no = -1
        for host in hosts:
            host_no += 1
            pcap_file = PCAP_FORMAT_STRING % (pcap_dir, test_name, run_no, host.name)

            auth_matrix[run_no][host_no] = readpcap.auth_time(pcap_file)

            prt_matrix[run_no][host_no] = readpcap.ping_reply_time(pcap_file, host.IP(), i0.IP())

            logoff_times_matrix[run_no][host_no] = readpcap.logoff_time(pcap_file,
                                                                        host.IP(),
                                                                        i0.IP())

            reauth_times_matrix[run_no][host_no] = readpcap.reauth_time(pcap_file)

            reauth_ping_matrix[run_no][host_no] = readpcap.reauth_ping_reply_time(pcap_file,
                                                                                  host.IP(),
                                                                                  i0.IP())


        time_taken = datetime.now() - start_time
        readpcap.save_CSV(test_name, [[time_taken], auth_matrix[run_no], prt_matrix[run_no],
                                      logoff_times_matrix[run_no], reauth_times_matrix[run_no],
                                      reauth_ping_matrix[run_no]])

        # cleanup
        clean_up(test_name, run_no)
        print('trial completed')
        time.sleep(10)


if __name__ == '__main__':

    PARSER = argparse.ArgumentParser()
    PARSER.add_argument('num_runs', help='Number of runs of each test', type=int)
    PARSER.add_argument('-p', '--pcap_dir', help='path to directory for pcaps', type=str)
    PARSER.add_argument('--num-hosts', nargs='+', type=int)
    ARGS = PARSER.parse_args()

    print(ARGS)

    for HOST_NO in ARGS.num_hosts:
        test_many_hosts(ARGS.num_runs, ARGS.pcap_dir, HOST_NO)
