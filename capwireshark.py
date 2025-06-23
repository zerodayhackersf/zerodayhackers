#!/usr/bin/env python3

import argparse
from scapy.all import *
from scapy.layers import http
import pandas as pd
import pyfiglet
import sys
import time
from datetime import datetime
import subprocess
import os

# Banner
def show_banner():
    banner = pyfiglet.figlet_format("CapWireShark", font="slant")
    print(banner)
    print("Wireshark-like packet analyzer - Command Line Version")
    print("="*60 + "\n")

# Packet capture function
def packet_capture(interface, count, filter_exp, output_file, timeout, verbose):
    print(f"[*] Starting packet capture on interface {interface}...")
    print(f"[*] Filter: {filter_exp if filter_exp else '<none>'}")
    print(f"[*] Count: {count if count else 'unlimited'}")
    print(f"[*] Timeout: {timeout if timeout else 'none'} seconds")
    print("[*] Press Ctrl+C to stop capture\n")
    
    packets = []
    start_time = time.time()
    
    def packet_handler(pkt):
        packets.append(pkt)
        if verbose:
            print_packet(pkt)
        if count and len(packets) >= count:
            raise KeyboardInterrupt
    
    try:
        if timeout:
            sniff(iface=interface, filter=filter_exp, prn=packet_handler, timeout=timeout)
        else:
            sniff(iface=interface, filter=filter_exp, prn=packet_handler)
    except KeyboardInterrupt:
        pass
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"\n[*] Capture completed. Duration: {duration:.2f} seconds")
    print(f"[*] Captured {len(packets)} packets")
    
    if output_file:
        wrpcap(output_file, packets)
        print(f"[*] Packets saved to {output_file}")

# Packet analysis functions
def print_packet(pkt):
    timestamp = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S.%f')
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        length = len(pkt)
        
        protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            2: "IGMP",
            89: "OSPF"
        }
        
        proto_name = protocol_map.get(proto, str(proto))
        
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            print(f"{timestamp} {src}:{sport} -> {dst}:{dport} {proto_name} Len={length}")
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            print(f"{timestamp} {src}:{sport} -> {dst}:{dport} {proto_name} Len={length}")
        else:
            print(f"{timestamp} {src} -> {dst} {proto_name} Len={length}")
    elif pkt.haslayer(ARP):
        print(f"{timestamp} ARP {pkt[ARP].psrc} -> {pkt[ARP].pdst}")
    else:
        print(f"{timestamp} Unknown packet type")

def analyze_pcap(pcap_file):
    print(f"[*] Analyzing PCAP file: {pcap_file}")
    packets = rdpcap(pcap_file)
    
    # Basic statistics
    print(f"\n[*] Basic Statistics:")
    print(f"Total packets: {len(packets)}")
    
    # Protocol distribution
    protocol_dist = {}
    for pkt in packets:
        if pkt.haslayer(IP):
            proto = pkt[IP].proto
            protocol_map = {
                1: "ICMP",
                6: "TCP",
                17: "UDP",
                2: "IGMP",
                89: "OSPF"
            }
            proto_name = protocol_map.get(proto, str(proto))
            protocol_dist[proto_name] = protocol_dist.get(proto_name, 0) + 1
        elif pkt.haslayer(ARP):
            protocol_dist["ARP"] = protocol_dist.get("ARP", 0) + 1
    
    print("\n[*] Protocol Distribution:")
    for proto, count in protocol_dist.items():
        print(f"{proto}: {count} packets")
    
    # Top talkers
    ip_packets = [pkt for pkt in packets if pkt.haslayer(IP)]
    if ip_packets:
        src_ips = [pkt[IP].src for pkt in ip_packets]
        dst_ips = [pkt[IP].dst for pkt in ip_packets]
        
        src_counts = pd.Series(src_ips).value_counts()
        dst_counts = pd.Series(dst_ips).value_counts()
        
        print("\n[*] Top Source IPs:")
        print(src_counts.head(10).to_string())
        
        print("\n[*] Top Destination IPs:")
        print(dst_counts.head(10).to_string())

def http_sniffer(interface, output_file):
    print(f"[*] Starting HTTP sniffer on interface {interface}...")
    print("[*] Press Ctrl+C to stop capture\n")
    
    http_packets = []
    
    def process_http(pkt):
        if pkt.haslayer(http.HTTPRequest):
            host = pkt[http.HTTPRequest].Host.decode()
            path = pkt[http.HTTPRequest].Path.decode()
            method = pkt[http.HTTPRequest].Method.decode()
            
            print(f"[HTTP Request] {method} http://{host}{path}")
            
            if pkt.haslayer(Raw):
                load = pkt[Raw].load.decode(errors='ignore')
                print(f"[Payload]\n{load}\n")
            
            http_packets.append(pkt)
        elif pkt.haslayer(http.HTTPResponse):
            status = pkt[http.HTTPResponse].Status_Code.decode()
            reason = pkt[http.HTTPResponse].Reason_Phrase.decode()
            
            print(f"[HTTP Response] {status} {reason}")
            
            if pkt.haslayer(Raw):
                load = pkt[Raw].load.decode(errors='ignore')
                print(f"[Payload]\n{load}\n")
            
            http_packets.append(pkt)
    
    try:
        sniff(iface=interface, prn=process_http, filter="tcp port 80 or tcp port 8080 or tcp port 8000")
    except KeyboardInterrupt:
        pass
    
    if output_file and http_packets:
        wrpcap(output_file, http_packets)
        print(f"\n[*] HTTP packets saved to {output_file}")

def list_interfaces():
    print("[*] Available network interfaces:")
    interfaces = os.listdir('/sys/class/net/') if os.path.exists('/sys/class/net/') else []
    if not interfaces:
        print("Could not list interfaces automatically. Try using 'ifconfig' or 'ip link'")
    else:
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface}")

def main():
    show_banner()
    
    parser = argparse.ArgumentParser(description="PyShark - Wireshark-like packet analyzer")
    subparsers = parser.add_subparsers(dest='command', help='sub-command help')
    
    # Capture command
    capture_parser = subparsers.add_parser('capture', help='capture packets')
    capture_parser.add_argument('-i', '--interface', required=True, help='network interface')
    capture_parser.add_argument('-c', '--count', type=int, help='number of packets to capture')
    capture_parser.add_argument('-f', '--filter', default='', help='BPF filter expression')
    capture_parser.add_argument('-o', '--output', help='output pcap file')
    capture_parser.add_argument('-t', '--timeout', type=int, help='capture duration in seconds')
    capture_parser.add_argument('-v', '--verbose', action='store_true', help='verbose output')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='analyze pcap file')
    analyze_parser.add_argument('-f', '--file', required=True, help='pcap file to analyze')
    
    # HTTP sniffer command
    http_parser = subparsers.add_parser('http', help='capture HTTP traffic')
    http_parser.add_argument('-i', '--interface', required=True, help='network interface')
    http_parser.add_argument('-o', '--output', help='output pcap file')
    
    # List interfaces command
    subparsers.add_parser('interfaces', help='list available network interfaces')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'capture':
        packet_capture(args.interface, args.count, args.filter, args.output, args.timeout, args.verbose)
    elif args.command == 'analyze':
        analyze_pcap(args.file)
    elif args.command == 'http':
        http_sniffer(args.interface, args.output)
    elif args.command == 'interfaces':
        list_interfaces()

if __name__ == "__main__":
    main()