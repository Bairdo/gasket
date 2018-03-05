
import os
import re
from subprocess import Popen, PIPE
import time

from mininet.net import Mininet
from mininet.node import RemoteController

import netifaces

from topo import Single


def wait_until_line(output, target, out=False):
    for _ in range(1000):
        line = output.readline()
        if out and line:
            print(line)
        if line:
            if re.search(target, line) is not None:
                break


def wpa_cli_status(host, intf):
    status = host.cmd('wpa_cli -i %s status' % intf)

    pattern = 'Supplicant PAE state=\S*'
    for line in status.split('\n'):
        match = re.search(pattern, line)
        if match:
            return match.group(0).split('=')[1]


def start(no_hosts):
    global NET
    NET = Mininet(topo=Single(no_hosts),
                  controller=RemoteController('c1', '127.0.0.1', 6699))
    NET.start()

    return [NET.get(h) for h in NET.topo.hosts() if h.startswith('h')]


def set_up(pcap_dir):
    global FAUCET, FREERADIUS, HOSTAPD, GASKET, RABBIT_SERVER, RABBIT_ADAPTER
    print('starting containers')
    FAUCET = Popen(
        ['docker-compose', 'up', 'faucet'], stdout=PIPE, stderr=PIPE)
    RABBIT_SERVER = Popen(
        ['docker-compose', 'up', 'rabbitmq_server'], stdout=PIPE, stderr=PIPE)
    RABBIT_ADAPTER = Popen(
        ['docker-compose', 'up', 'rabbitmq_adapter'], stdout=PIPE, stderr=PIPE)
    FREERADIUS = Popen(
        ['docker-compose', 'up', 'freeradius'], stdout=PIPE, stderr=PIPE)
    HOSTAPD = Popen(
        ['docker-compose', 'up', 'hostapd'], stdout=PIPE, stderr=PIPE)

    print('hostapd started')
    wait_until_line(HOSTAPD.stdout, 'Device "eth3" does not exist.')

    Popen(['ovs-docker',
           'add-port',
           's1', 'eth3',
           'performancetests_hostapd_1',
           '--ipaddress=10.0.0.22/8'])
    print('docker link added')
    wait_until_line(HOSTAPD.stdout, 'eth3: AP-ENABLED')
    print('hostapd all good')
    time.sleep(15)
    GASKET = Popen(
        ['docker-compose', 'up', 'gasket'], stdout=PIPE, stderr=PIPE)

    print('gasket started')
    wait_until_line(FAUCET.stdout, 'instantiating app faucet.faucet of Faucet')

    for switch in NET.switches:
        print(type(switch))
        print(pcap_dir)
        for intf in switch.intfNames():
            os.system('tcpdump -i {0} -w {1}/{0}.pcap &'.format(intf, pcap_dir))


    interfaces = netifaces.interfaces()
    print(interfaces)
    for intf in interfaces:
        if intf.endswith('_l'):
            os.system('tcpdump -i {0} -w {1}/{0}.pcap &'.format(intf, pcap_dir))

    print('started mininet')

    time.sleep(15)

    print('Faucet good')


def start_tcpdump(host, filename):

    return host.cmd('tcpdump -i %s-eth0 -w %s &' % (host.name, filename))


def authenticate(host):
    host.cmd('wpa_supplicant -Dwired -i{0}-eth0 -c{0}.conf &'.format(host.name))

    wait_until_authenticate(host)


def wait_until_authenticate(host):
    status = None

    for _ in range(100):
        new_status = wpa_cli_status(host, '%s-eth0' % host.name)
        if status != new_status:
            print('wait_until_authenticate', new_status)
        status = new_status
        if status == 'AUTHENTICATED':
            break
        time.sleep(1)
        if status == 'HELD':
            break


def wait_until_logoff(host):
    status = None

    for _ in range(100):
        new_status = wpa_cli_status(host, '%s-eth0' % host.name)
        if status != new_status:
            print('wait_until_logoff', new_status)
        status = new_status
        if status == 'LOGOFF':
            break
        if status == 'HELD':
            break
        time.sleep(1)


def shut_down(hosts, log_location):
    for host in hosts:
        host.cmd('wpa_cli -i%s-eth0 terminate' % host.name)

    NET.stop()
    # must use this otherwise adapter will restart.
    os.system('docker stop performancetests_rabbitmq_adapter_1')
    os.system('killall tcpdump')
    RABBIT_SERVER.terminate()
    FAUCET.terminate()
    GASKET.terminate()
    FREERADIUS.terminate()
    HOSTAPD.terminate()
    with open('%s/faucet-adapter-perftests.log' % log_location, 'a+') as log:
        log.write(RABBIT_ADAPTER.stdout.read())
    with open('%s/hostapd.log' % log_location, 'w+') as log:
        log.write(HOSTAPD.stdout.read())

    with open('%s/faucet-perftests.log' % log_location, 'w+') as log:
        log.write(FAUCET.stdout.read())
