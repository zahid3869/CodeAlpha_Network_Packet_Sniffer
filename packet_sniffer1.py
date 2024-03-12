#!/usr/bin/env python
import argparse
from scapy.all import sniff, Ether

def packet_handler(pkt):
    if pkt.haslayer(Ether):
        print(pkt.summary())

def main():
    parser = argparse.ArgumentParser(description="Simple Packet Sniffer")
    parser.add_argument("-i", "--interface", help="Interface to sniff on")
    args = parser.parse_args()

    if args.interface:
        print(f"Sniffing on interface {args.interface}...")
        sniff(iface=args.interface, prn=packet_handler, store=0)
    else:
        print("Please provide an interface to sniff on using the -i or --interface option.")

if __name__ == "__main__":
    main()

