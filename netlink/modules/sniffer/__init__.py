"""
Author: Chris Martinez
Date: 20 April 2026
Version: 1.0.0
Name: __init__.py (sniffer)
Description: This module is responsible for sniffing network traffic and 
capturing packets for analysis. It uses Scapy to capture packets on the network
and can filter traffic based on 
"""
import argparse

from functools import partial
from scapy.all import sniff, wrpcap
from scapy.layers.dns import DNS
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Dot1Q, Ether,STP
from scapy.layers.tls.all import TLS
from scapy.packet import Packet

from netlink.core.base_module import BaseModule
from netlink.core.output import OutputManager

class Sniffer(BaseModule):
    """
    This sniffer is responsible for sniffing network traffic and capturing
    packets for analysis
    """
    ############################################################################
    # Class Level Attributes
    ############################################################################
    NAME = "sniffer"
    DESCRIPTION = "Capture and decode live network traffic"
    REQUIRES_ROOT = True

    ############################################################################
    # Constructor
    ############################################################################
    def __init__(self, iface: str, output: OutputManager):
        super().__init__(iface, output)
        self._protocol_count: dict[str, int] = dict()

    ############################################################################
    # Methods
    ############################################################################
    def add_args(self, parser: argparse.ArgumentParser) -> None:
        """
        Adds module-specific arguments to the argument parser. This method is
        called by the Engine when setting up the CLI for this module.
        Args:
            parser (argparse.ArgumentParser): The argument parser to which
                                              module-specific args are added.
        """
        parser.description = """Capture and decode live network traffic on the 
        specified interface. Supports BPF filters to narrow capture to specific 
        protocols or hosts. Output has three levels of detail: default shows a 
        one-line summary per packet, --verbose adds key protocol fields, and
        --deep-inspect shows a full indented layer breakdown in the terminal. 
        Use --pcap to save all captured packets for analysis in Wireshark."""
          
        parser.add_argument(
            '-c',
            '--count',
            type=int,
            action='store',
            dest='count',
            default=100,
            help="Number of packets to capture (Default=100)"
        )

        parser.add_argument(
            '-f',
            '--filter',
            type=str,
            action='store',
            dest='filter',
            default='',
            help="Specific BPF you wish to implement (Default=Capture All)"
        )

        parser.add_argument(
            '--pcap',
            type=str,
            action='store',
            dest='pcap',
            default=None,
            help="File location for pcap (Default=None)"
        )

        parser.add_argument(
            '--timeout',
            type=int,
            action='store',
            dest='timeout',
            default=None,
            help="Stop sniffing after N seconds (Dafault=None)"
        )

        parser.add_argument(
            '--verbose',
            action='store_true',
            dest='verbose',
            default=False,
            help="""Show additional protocol fields per packet such as TCP 
            flags, TTL, DNS query names, and TLS version alongside the standard 
            one-line summary. Best used with a specific BPF filter to reduce 
            noise."""
        )

        parser.add_argument(
            '--deep-inspect',
            action='store_true',
            dest='deep_inspect',
            default=False,
            help="""Show a full indented layer-by-layer breakdown for each 
            captured packet. Displays all available fields per protocol layer. 
            Very verbose — best used with --count set to a low value 
            (e.g. 5 or 10) or a tight BPF filter. For full packet inspection 
            across a session use --pcap and open the file in Wireshark 
            instead."""
        )


    def run(self, args: argparse.Namespace) -> None:
        """
        Executes the main functionality of the sniffer module. This method is
        called by the Engine when the user runs this module from the CLI.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                       specific to the sniffer module.
        Returns:
            None: True if the module executed successfully, False otherwise.
        """
        prn = partial(self._process_packet, args=args)

        sniff_kwargs = {
            'iface': self.iface,
            'count': args.count,
            'timeout': args.timeout,
            'prn': prn,
        }

        if args.filter:
            sniff_kwargs['filter'] = args.filter

        pkts = sniff(**sniff_kwargs)

        if args.pcap:
            wrpcap(args.pcap, pkts)
        
        msg = (
            f"Total amount of packets captured -> {len(pkts)} "
            f"{'Packet' if len(pkts) == 1 else 'Packets'}"
        )
        self.output.info(msg)
        self.output.info("Protocol Summary:")
        for proto, count in sorted(self._protocol_count.items()):
            packet_or_packets = 'packet' if count == 1 else 'packets'
            self.output.info(f"  {proto:<12} {count} {packet_or_packets}")

    def validate_args(self, args: argparse.Namespace) -> bool:
        """
        Validates the provided arguments for the sniffer module. This method is
        called by the Engine after parsing the command-line arguments to ensure
        that they are valid before executing the module.
        Args:
            args (argparse.Namespace): The parsed command-line arguments 
                                       specific to the sniffer module.
        Returns:
            bool: True if the arguments are valid, False otherwise.
        """
        if args.count < 0:
            self.output.warn("Count must be greater than 0 packets")
            return False
        return True

    def _process_packet(self, pkt: Packet, args: argparse.Namespace) -> None:
        """
        Handles incoming network packets by extracting key metadata and logging
        the results. It identifies IP-based traffic (TCP, UDP, ICMP) and ARP 
        requests, formatting the connection details for both console output and
        structured data recording.
        Args:
            pkt (Packet): The captured packet object provided by Scapy.
        """
        ICMP_PROTO = 1
        TCP_PROTO = 6
        UDP_PROTO = 17
        PKT_SIZE = len(pkt)

        src_ip = None
        src_port = None
        src_mac = None

        dst_ip = None
        dst_port = None
        dst_mac = None
        
        protocol = 'Other'
        pkt_size_print =f"({PKT_SIZE} {'byte' if PKT_SIZE == 1 else 'bytes'})"
        terminal_printout = f"[Other] {pkt_size_print}"

        if pkt.haslayer(IP):
            terminal_printout = self._inspect_ip(pkt, IP) #type: ignore
        elif pkt.haslayer(IPv6):
            terminal_printout = self._inspect_ip(pkt, IPv6) #type: ignore
        elif pkt.haslayer(ARP):
            protocol = 'ARP'
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc
            dst_ip = pkt[ARP].pdst
            dst_mac = pkt[ARP].hwdst
            terminal_printout = (
                f"[{protocol}] {src_ip} ({src_mac}) --> {dst_ip} ({dst_mac}) "
                f"{pkt_size_print}"
            )
        elif pkt.haslayer(Dot1Q):
            protocol = 'VLAN'
            src_mac = pkt[Ether].src if pkt.haslayer(Ether) else 'None'
            dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else 'None'
            vlan_id = pkt[Dot1Q].vlan
            terminal_printout = (
                f"[{protocol}] id={vlan_id} src={src_mac} --> dst={dst_mac} "
                f"{pkt_size_print}"
            )
        elif pkt.haslayer(STP):
            protocol = 'STP'
            proto = pkt[STP].proto
            version = pkt[STP].version
            terminal_printout = (
                f"[{protocol}] proto={proto} version={version} {pkt_size_print}"
            )

        data = {
            'protocol': protocol,
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'pkt_size': PKT_SIZE
        }
        
        self.output.info(terminal_printout)
        self.output.record(data)
    
    def _inspect_ip(self, pkt: Packet, ip_version: IP|IPv6) -> str:
        """
        
        """
        PKT_SIZE = len(pkt)

        src_ip = None
        src_port = None
        src_mac = None

        dst_ip = None
        dst_port = None
        dst_mac = None
        
        protocol = 'Other'
        pkt_size_print =f"({PKT_SIZE} {'byte' if PKT_SIZE == 1 else 'bytes'})"
        terminal_printout = f"[Other] {pkt_size_print}"

        if pkt.haslayer(ip_version): #type: ignore
            protocol = 'IPv4' if ip_version == IP else 'IPv6'
            src_ip = pkt[ip_version].src #type: ignore
            dst_ip = pkt[ip_version].dst #type: ignore
            if pkt.haslayer(TLS):
                protocol = 'TLS'
                src_port = pkt[TCP].sport if pkt.haslayer(TCP) else 'None'
                dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else 'None'
            elif pkt.haslayer(HTTP):
                if pkt.haslayer(HTTPRequest):
                    protocol = 'HTTP Request'
                elif pkt.haslayer(HTTPResponse):
                    protocol = 'HTTP Response'
                else:
                    protocol = 'HTTP'
                src_port = pkt[TCP].sport if pkt.haslayer(TCP) else 'None'
                dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else 'None'
            elif pkt.haslayer(DNS):
                protocol = 'DNS'
                src_port = pkt[UDP].sport if pkt.haslayer(UDP) else 'None'
                dst_port = pkt[UDP].dport if pkt.haslayer(UDP) else 'None'
            elif pkt.haslayer(DHCP):
                protocol = 'DHCP'
                src_port = pkt[UDP].sport if pkt.haslayer(UDP) else 'None'
                dst_port = pkt[UDP].dport if pkt.haslayer(UDP) else 'None'
            elif pkt.haslayer(TCP):
                protocol = 'TCP'
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                protocol = 'UDP'
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
            elif pkt.haslayer(ICMP):
                protocol = 'ICMP'

            terminal_printout = (
                f"[{protocol}] {src_ip}:{src_port} --> {dst_ip}:{dst_port} "
                f"{pkt_size_print}"
            )
        
        return terminal_printout