import socket, sys
from struct import *
from models import Packet,Socket,Scan

def scan(source, destination, port):
####################initialize the socket#########################
    sock = Socket()
    s = sock.create_raw_socket()
##################################################################
################ constructing the packet##########################
    p = Packet()
    packet = ''

    ip_header = p.create_IP_header(source, destination)

    tcp_header = p.create_TCP_header(1234, port)


    packet = ip_header + tcp_header
###################################################################
#################Sending the packet################################
    s.sendto(packet, (destination , 0 ))
###################################################################
######################listen to incoming packets for SYN-ACK#######
    listen = s
    raw_packet = listen.recvfrom(4096)

    job = Scan
    flag = job.response_flag(raw_packet)
    if flag == 18:  #syn-ack is 18
        return True
    else:
        return False
#######################################################################
source = '192.168.100.1'#input('Enter The source ip address: ')
destination = '192.168.100.50'#input('Enter the address to scan: ')
port_from = 2#int(input('from Port: '))
port_to = 5#int(input('To Port: '))
for i in range (port_from,port_to+1):
    result = scan(source,destination, i)
    if result:
        print ('Port '+ str(i) + ' is open')

    else:
        print ('Port '+ str(i) + ' is closed')
