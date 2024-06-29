#!/usr/bin/env python3
# packet_sniffer.py

"""
Author: Drew Mayberry
Date: June 28, 2024
Description: This program is a Python packet sniffer that captures and displays Ethernet, IP, TCP, UDP, and ICMP packet headers and data. It logs each captured packet to a timestamped file in the 'logs' directory.
Version: 1.0
"""

import socket
import struct
import textwrap
import datetime
import os

class PacketSniffer:
    def __init__(self, interface):
        self.interface = interface

    def sniff_packets(self):
        try:
            # Create a raw socket to receive packets
            sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            sniffer.bind((self.interface, 0))
            print(f"Sniffing packets on {self.interface}...")

            while True:
                # Read a single packet
                raw_packet, _ = sniffer.recvfrom(65536)

                # Log raw packet data to a file
                self.log_packet(raw_packet)

                # Unpack Ethernet header (first 14 bytes)
                eth_header = raw_packet[:14]
                eth = struct.unpack("!6s6sH", eth_header)
                dest_mac = self.get_mac_address(eth_header[0:6])
                src_mac = self.get_mac_address(eth_header[6:12])
                eth_proto = socket.ntohs(eth[2])

                # Display Ethernet header information
                print("\nEthernet Frame:")
                print(f"Destination MAC: {dest_mac} | Source MAC: {src_mac} | Protocol: {eth_proto}")

                # Parse IP packets, if it's an IP packet (ethertype 0x0800)
                if eth_proto == 8:
                    # Parse IP header (20 bytes for IPv4)
                    ip_header = raw_packet[14:34]
                    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                    version_ihl = iph[0]
                    version = version_ihl >> 4
                    ihl = version_ihl & 0xF
                    iph_length = ihl * 4
                    ttl = iph[5]
                    protocol = iph[6]
                    s_addr = socket.inet_ntoa(iph[8])
                    d_addr = socket.inet_ntoa(iph[9])

                    # Display IP header information
                    print("IP Header:")
                    print(f"Version: {version} | IP Header Length: {iph_length} | TTL: {ttl}")
                    print(f"Protocol: {protocol} | Source Address: {s_addr} | Destination Address: {d_addr}")

                    # TCP packets (protocol 6)
                    if protocol == 6:
                        tcp_header = raw_packet[34:54]
                        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                        source_port = tcph[0]
                        dest_port = tcph[1]
                        sequence = tcph[2]
                        acknowledgement = tcph[3]
                        doff_reserved = tcph[4]
                        tcph_length = doff_reserved >> 4
                        print("TCP Header:")
                        print(f"Source Port: {source_port} | Destination Port: {dest_port}")
                        print(f"Sequence Number: {sequence} | Acknowledgement: {acknowledgement}")
                        print(f"TCP Header Length: {tcph_length}")
                        h_size = iph_length + tcph_length * 4
                        data_size = len(raw_packet) - h_size

                        # Data contained in the packet
                        data = raw_packet[h_size:]
                        print("Data:")
                        print(self.format_multi_line('\t\t', data))

                    # UDP packets (protocol 17)
                    elif protocol == 17:
                        udp_header = raw_packet[34:42]
                        udph = struct.unpack('!HHHH', udp_header)
                        source_port = udph[0]
                        dest_port = udph[1]
                        length = udph[2]
                        checksum = udph[3]
                        print("UDP Header:")
                        print(f"Source Port: {source_port} | Destination Port: {dest_port}")
                        print(f"Length: {length} | Checksum: {checksum}")
                        h_size = iph_length + 8
                        data_size = len(raw_packet) - h_size

                        # Data contained in the packet
                        data = raw_packet[h_size:]
                        print("Data:")
                        print(self.format_multi_line('\t\t', data))

                    # ICMP packets (protocol 1)
                    elif protocol == 1:
                        icmp_header = raw_packet[34:38]
                        icmph = struct.unpack('!BBH', icmp_header)
                        icmp_type = icmph[0]
                        code = icmph[1]
                        checksum = icmph[2]
                        print("ICMP Header:")
                        print(f"Type: {icmp_type} | Code: {code} | Checksum: {checksum}")
                        h_size = iph_length + 4
                        data_size = len(raw_packet) - h_size

                        # Data contained in the packet
                        data = raw_packet[h_size:]
                        print("Data:")
                        print(self.format_multi_line('\t\t', data))

                # Other protocols (ARP, etc.)
                else:
                    print("Non-IP Packet captured.")

        except KeyboardInterrupt:
            print("\n\nUser interrupted.")
            exit(0)

        except socket.error as e:
            print(f"Socket error occurred: {e}")
            exit(1)

    @staticmethod
    def get_mac_address(bytes_address):
        # Convert bytes to MAC address format
        bytes_str = map('{:02x}'.format, bytes_address)
        return ':'.join(bytes_str).upper()

    @staticmethod
    def format_multi_line(prefix, string, size=80):
        # Format the given string with a prefix for readability
        size -= len(prefix)
        if isinstance(string, bytes):
            string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
            if size % 2:
                size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

    def log_packet(self, packet):
        # Create logs directory if it doesn't exist
        if not os.path.exists("logs"):
            os.makedirs("logs")
        # Log packet to a file with timestamp
        with open(f"logs/{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log", 'wb') as f:
            f.write(packet)

# Example usage:
if __name__ == "__main__":
    interface = input("Enter interface")  # Replace with your network interface
    sniffer = PacketSniffer(interface)
    sniffer.sniff_packets()

