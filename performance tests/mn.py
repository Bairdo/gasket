from subprocess import Popen, PIPE
import signal
import re
import time

from mininet.net import Mininet
from mininet.node import RemoteController

from topo import Single

import os
from signal import SIGHUP

def wait_until_line(output, target):
    for i in range(1000):
        line = output.readline()
        if line:
            if re.search(target, line) is not None:
                break

def wpa_cli_status(host, intf):
    status = host.cmd('wpa_cli -i %s status' % intf)
        
    pattern = 'Supplicant PAE state=\S*'
    for l in status.split('\n'):
        match = re.search(pattern, l)
        if match:
            return match.group(0).split('=')[1]

def start():
  global net, h0
  net = Mininet(topo=Single(),
                controller=RemoteController('c1', '172.222.0.100', 6653))
  net.start()
  h0 = net.get('h0')

def set_up():
  global freeradius, hostapd, gasket
  freeradius = Popen(['docker-compose', 'up', 'freeradius'], stdout=PIPE, stderr=PIPE)
  hostapd = Popen(['docker-compose', 'up', 'hostapd'], stdout=PIPE, stderr=PIPE)
  
  wait_until_line(hostapd.stdout, 'Device "eth3" does not exist.')

  Popen(['ovs-docker',
         'add-port',
         's1', 'eth3',
         'gasket_hostapd_1',
         '--ipaddress=10.0.0.22/8'])
  wait_until_line(hostapd.stdout, 'eth3: AP-ENABLED')
  
  time.sleep(1)
  
  gasket = Popen(['docker-compose', 'up', 'gasket'], stdout=PIPE, stderr=PIPE)
  
  wait_until_line(gasket.stdout, 'instantiating app faucet.faucet of Faucet')

def start_tcpdump(filename):
  global pid
  
  pid = h0.cmd('tcpdump -v -i h0-eth0 -w %s &' % filename)
  time.sleep(1)

def authenticate():
  h0.cmd('wpa_supplicant -Dwired -ih0-eth0 -ch0.conf &')
  
  wait_until_authenticate()
  
def wait_until_authenticate():
  status = None

  for i in range(100):
      new_status = wpa_cli_status(h0, 'h0-eth0')
      if status != new_status:
          print new_status
      status = new_status
      if status == 'AUTHENTICATED':
          break
      time.sleep(1)
      if status == 'HELD':
          break

def wait_until_logoff():
  status = None
  
  for i in range(100):
      new_status = wpa_cli_status(h0, 'h0-eth0')
      if status != new_status:
          print new_status
      status = new_status
      if status == 'LOGOFF':
          break
      if status == 'HELD':
          break
      time.sleep(1)

def shut_down():
  h0.cmd('wpa_cli -ih0-eth0 terminate')

  time.sleep(1)
  
  h0.cmd('kill -SIGHUP %s' % pid)
  
  net.stop()

  freeradius.terminate()
  hostapd.terminate()
  with open('hostapd.log', 'w') as log:
    log.write(hostapd.stdout.read())
  gasket.terminate()