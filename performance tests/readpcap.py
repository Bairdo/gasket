import dpkt
import os

def auth_time(filename):
    start = end = None
    
    for ts, pkt in dpkt.pcap.Reader(open(filename,'r')):
       eth = dpkt.ethernet.Ethernet(pkt)
       if eth.type == 0x888e:
           if start is None and eth.data == '\x02\x01\x00\x00':
               start = ts
           elif len(eth.data) > 4 and ord(eth.data[4]) == 3:
              end = ts
              break
   
    if start is not None and end is not None:
        return (end - start)
    return 'N/A'
        
def ping_reply_time(filename):
    start = end = None
    
    for ts, pkt in dpkt.pcap.Reader(open(filename,'r')):
       eth = dpkt.ethernet.Ethernet(pkt)
       if start is None:
           if eth.type == 0x888e and len(eth.data) > 4 and ord(eth.data[4]) == 3:
               start = ts
       else:
           if eth.type == 0x800:
               src = '.'.join(str(ord(x)) for x in eth.data.src)
               dst = '.'.join(str(ord(x)) for x in eth.data.dst)
               if src == '10.0.0.40' and dst == '10.0.0.10':
                  end = ts
                  break
   
    if start is not None and end is not None:
        return (end - start)
    return 'N/A'
        
def logoff_time(filename):
    start = end = None
    
    packets = list(dpkt.pcap.Reader(open(filename,'r')))
    
    for ts, pkt in packets:
       eth = dpkt.ethernet.Ethernet(pkt)
       if start is None:
           if eth.type == 0x888e and eth.data == '\x02\x02\x00\x00':
               start = ts
       else:
           if eth.type == 0x800:
               src, dst, seq = get_ICMP_info(eth)
               if src == '10.0.0.10' and dst == '10.0.0.40':
                   for _, pkt2 in packets:
                       eth2 = dpkt.ethernet.Ethernet(pkt2)
                       if eth2.type == 0x800:
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
    logoff = False
    start = end = None
    
    for ts, pkt in dpkt.pcap.Reader(open(filename,'r')):
       eth = dpkt.ethernet.Ethernet(pkt)
       if not logoff:
           if eth.type == 0x888e and eth.data == '\x02\x02\x00\x00':
               logoff = True
           else:
               continue
       
       elif eth.type == 0x888e:
           if start is None and eth.data == '\x02\x01\x00\x00':
               start = ts
           elif len(eth.data) > 4 and ord(eth.data[4]) == 3:
              end = ts
              break
   
    if start is not None and end is not None:
        return (end - start)
    return 'N/A'

def reauth_ping_reply_time(filename):
    logoff = False
    start = end = None
    
    for ts, pkt in dpkt.pcap.Reader(open(filename,'r')):
       eth = dpkt.ethernet.Ethernet(pkt)
       if not logoff:
           if eth.type == 0x888e and eth.data == '\x02\x02\x00\x00':
               logoff = True
           else:
               continue
       
       if start is None:
           if eth.type == 0x888e and len(eth.data) > 4 and ord(eth.data[4]) == 3:
               start = ts
       else:
           if eth.type == 0x800:
               src = '.'.join(str(ord(x)) for x in eth.data.src)
               dst = '.'.join(str(ord(x)) for x in eth.data.dst)
               if src == '10.0.0.40' and dst == '10.0.0.10':
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

def save_CSV(test_no, *data):
  check_valid_results(*data)
  filename = 'results/test_%s.csv' % test_no
  
  data = zip(*data)
  
  with open(filename, 'w') as file:
    file.write('\n'.join([', '.join([str(x) for x in line]) for line in data]))

def check_valid_results(*results):
  for list in results:
    if list[-1] == 'N/A':
      print 'error with results'
      for list in results:
        list.pop()
      return
      
def read_folder(dir_name):
  auth_times = []
  ping_reply_times = []
  logoff_times = []
  reauth_times = []
  reauth_ping_reply_times = []
  
  for filename in sorted(os.listdir(dir_name), key=lambda x:int(x.split('_')[1][:-5])):
    print filename
    pcap_file = dir_name+'/'+filename
    auth_times.append(auth_time(pcap_file))
    ping_reply_times.append(ping_reply_time(pcap_file))
    logoff_times.append(logoff_time(pcap_file))
    reauth_times.append(reauth_time(pcap_file))
    reauth_ping_reply_times.append(reauth_ping_reply_time(pcap_file))
    save_CSV(3, auth_times, ping_reply_times, logoff_times, reauth_times, reauth_ping_reply_times)

if __name__ == '__main__':
    #print 'Auth Time: %ss' % auth_time('pcaps/test3_1.pcap')
    #print 'Ping Reply Time: %ss' % ping_reply_time('tcpdump')
    #print 'Logoff Time: %ss' % logoff_time('tcpdump3')
    #print 'Reauth Time: %ss' % reauth_time('pcaps/test3_1.pcap')
    #print 'Reauth Ping Reply Time: %ss' % reauth_ping_reply_time('pcaps/test3_1.pcap')
    
    read_folder('test_results_1/pcaps')