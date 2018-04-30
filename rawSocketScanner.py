import socket, sys
from struct import *

# checksum functions needed for calculating checksum
def checksum(msg):
    s = 0
    # loop taking 2 characters at a time
    #print (msg[7])
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + (msg[i+1])
        s = s + w

    s = (s>>16) + (s & 0xffff);
    #s = s + (s >> 16);
    #complement and mask to 4 byte short
    s = ~s & 0xffff
    #print (s)
    return s

def scan(address, port):
    #create a raw socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error as msg:
        print ('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()

    # tell kernel not to put in headers, since we are providing it
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # now start constructing the packet
    packet = ''

    source_ip = '192.168.100.1'
    dest_ip = address # or socket.gethostbyname('www.google.com')
    # ip header fields
    ihl = 5
    version = 4
    tos = 0
    tot_len = 20 + 20   # python seems to correctly fill the total length, dont know how ??
    id = 54321  #Id of this packet
    frag_off = 0
    ttl = 255
    protocol = socket.IPPROTO_TCP
    check = 10  # python seems to correctly fill the checksum
    saddr = socket.inet_aton ( source_ip )  #Spoof the source ip address if you want to
    daddr = socket.inet_aton ( dest_ip )

    ihl_version = (version << 4) + ihl

    # the ! in the pack format string means network order
    ip_header = pack('!BBHHHBBH4s4s' , ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)

    # tcp header fields
    source = 1234   # source port
    dest = port # destination port
    seq = 0
    ack_seq = 0
    doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
    #tcp flags
    fin = 0
    syn = 1
    rst = 0
    psh = 0
    ack = 0
    urg = 0
    window = socket.htons (5840)    #   maximum allowed window size
    check = 0
    urg_ptr = 0

    offset_res = (doff << 4) + 0
    tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5)
    # the ! in the pack format string means network order
    tcp_header = pack('!HHLLBBHHH' , source, dest, seq, ack_seq, offset_res, tcp_flags,  window, check, urg_ptr)
    # pseudo header fields
    source_address = socket.inet_aton( source_ip )
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)

    psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
    psh = psh + tcp_header
    tcp_checksum = checksum(psh)

    # make the tcp header again and fill the correct checksum
    tcp_header = pack('!HHLLBBHHH' , source, dest, seq, ack_seq, offset_res, tcp_flags,  window, tcp_checksum , urg_ptr)

    # final full packet - syn packets dont have any data
    packet = ip_header + tcp_header

    #Send the packet finally - the port specified has no effect
    s.sendto(packet, (dest_ip , 0 ))

    #listen to incoming packets for SYN-ACK
    listen = s

    raw_packet = listen.recvfrom(4096)
    #we need to unpack the packets since they are bytes
    #we're looking for SYN-ACK s
    #fields to check: IP - src addr;TCP - src port, flags
    #print (raw_packet)
    if raw_packet:
        packet = raw_packet[0]
        ip_header = unpack('!BBHHHBBH4s', packet[0:16])
        ip_header_length = (ip_header[0] & 0xf) * 4   #been fucked until this trick
        src_addr = socket.inet_ntoa(ip_header[8])     #unpacks ip to string
        #print (src_addr)
        tcp_header_raw = packet[ip_header_length:ip_header_length+14] #ip_header_length was needed to find proper tcp_header offset
        tcp_header = unpack('!HHLLBB' , tcp_header_raw) #partialy unpacked coz we neeed just ports and flags

        src_port = tcp_header[0]
        dst_port = tcp_header[1]
        flag = tcp_header[5]  #SYN-ACK will be 18
        print (tcp_header)
        if flag == 18:
            return True
        else:
            return False
address = input('Enter the address to scan: ')
port_from = int(input('from Port: '))
port_to = int(input('To Port: '))
for i in range (port_from,port_to):
    result = scan(address, i)
    if result:
        print ('Port '+ str(i) + ' is open')
    else:
        print ('Port '+ str(i) + ' is closed')
