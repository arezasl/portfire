#what classes might this need:
 #first we need to have a class to perform packet generation upom a call
import socket
from struct import *
class Packet():

    def create_IP_header(self, source, destination):
        self.source_ip = source
        self.dest_ip = destination
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
        saddr = socket.inet_aton ( self.source_ip )  #Spoof the source ip address if you want to
        daddr = socket.inet_aton ( self.dest_ip )

        ihl_version = (version << 4) + ihl

        # the ! in the pack format string means network order
        ip_header = pack('!BBHHHBBH4s4s' , ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)
        return ip_header
    def create_TCP_header(self, sport, dport):
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
        source = sport   #source port
        dest = dport     #destination port
        seq = 0
        ack_seq = 0
        doff = 5        #4 bit field, size of tcp header, 5 * 4 = 20 bytes
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
        self.tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5)
        # the ! in the pack format string means network order
        tcp_header = pack('!HHLLBBHHH' , sport, dport, seq, ack_seq, offset_res, self.tcp_flags,  window, check, urg_ptr)
        # pseudo header fields
        source_address = socket.inet_aton( str(self.source_ip) )
        dest_address = socket.inet_aton(str(self.dest_ip))
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)

        psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
        psh = psh + tcp_header
        tcp_checksum = checksum(psh)
        # make the tcp header again and fill the correct checksum
        tcp_header = pack('!HHLLBBHHH' , source, dest, seq, ack_seq, offset_res, self.tcp_flags,  window, tcp_checksum , urg_ptr)

        return tcp_header
class Socket:           #socket check and opening, proxy related stuff
    def create_raw_socket(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error as msg:
            print ('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
            sys.exit()
        # tell kernel not to put in headers, since we are providing it
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        return s






class Scan:

    def response_flag(raw_packet):
            #we need to unpack the packets since they are bytes
            #we're looking for SYN-ACK s
            #fields to check: IP - src addr;TCP - src port, flags
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
        return flag
