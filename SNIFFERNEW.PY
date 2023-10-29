import socket
import struct
from sniffer import parce_udp_header

sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
sniffer.bind(('eth0', 0))

def parse_eth_header(data):
    eth_header = struct.unpack("!6s6sH", data[:14])
    src_mac = eth_header[0]
    dest_mac = eth_header[1]
    eth_protocol = socket.ntohs(eth_header[2])
    return src_mac, dest_mac, eth_protocol

def parse_ip_header(data):
    ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
    ttl = ip_header[5]
    protocol = ip_header[6]
    src_ip = socket.inet_ntoa(ip_header[8])
    dest_ip = socket.inet_ntoa(ip_header[9])
    return ttl, protocol, src_ip, dest_ip

def parse_tcp_header(data):
    tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
    src_port = tcp_header[0]
    dest_port = tcp_header[1]
    sequence = tcp_header[2]
    ack = tcp_header[3]
    offset_reserved = tcp_header[4]
    tcp_flags = tcp_header[5]
    window = tcp_header[6]
    checksum = tcp_header[7]
    urgent_pointer = tcp_header[8]
    return src_port, dest_port, sequence, ack, offset_reserved, tcp_flags, window, checksum, urgent_pointer

def parse_udp_header(data):
    udp_header = struct.unpack('!HHHH', data[:8])
    src_port = udp_header[0]
    dest_port = udp_header[1]
    length = udp_header[2]
    checksum = udp_header[3]
    return src_port, dest_port, length, checksum

def parse_icmp_header(data):
    icmp_header = struct.unpack('!BBH', data[:4])
    icmp_type = icmp_header[0]
    code = icmp_header[1]
    checksum = icmp_header[2]
    return icmp_type, code, checksum

while True:
    raw_data, addr = sniffer.recvfrom(65535)
    src_mac, dest_mac, eth_protocol = parse_eth_header(raw_data)

    if eth_protocol == 8:
        ttl, protocol, src_ip, dest_ip = parse_ip_header(raw_data)

        if protocol == 6:
            src_port, dest_port, sequence, ack, offset_reserved, tcp_flags, window, checksum, urgent_pointer = parse_tcp_header(raw_data)
            # IDS Rules for TCP
            # ...

        elif protocol == 17:
            src_port, dest_port, length, checksum = parce_udp_header
