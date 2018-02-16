import socket
import time
import select

UDP_IP = "127.0.0.1"
UDP_PORT = 5005

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # 

sock.setblocking(0)
                 
while 1:
    sock.sendto("PING", (UDP_IP, UDP_PORT))
    
    if select.select([sock], [], [], 1)[0]:
        print 'recieved message:', sock.recv(1024)
    
    time.sleep(1)