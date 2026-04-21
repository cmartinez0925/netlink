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

from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.packet import Packet
from netlink.core.base_module import BaseModule

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
    # No need, already inherited by BaseModule

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

    def run(self, args: argparse.Namespace) -> bool:
        """
        Executes the main functionality of the sniffer module. This method is
        called by the Engine when the user runs this module from the CLI.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                       specific to the sniffer module.
        Returns:
            bool: True if the module executed successfully, False otherwise.
        """
        pass

    def validate_args(self, args) -> bool:
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
        pass

    def _process_packet(self,pkt: Packet) -> None:
        """
        Internal method to process each captured packet. This method is called
        by Scapy for each packet that matches the specified filter during 
        sniffing.
        Args:
            pkt (Packet): The captured packet object provided by Scapy.
        """
        ICMP_PROTO = 1
        TCP_PROTO = 6
        UDP_PROTO = 17

        data = dict()

        src_ip = None
        src_port = None
        dst_ip = None
        dst_port = None
        protocol = 'Other'
        pkt_size = len(pkt)
        msg = f"[{protocol}] {pkt_size} bytes"

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto = pkt[IP].proto
        
            if proto == ICMP_PROTO:
                protocol = 'ICMP'
            elif proto == TCP_PROTO:
                protocol = 'TCP'
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif proto == UDP_PROTO:
                protocol = 'UDP'
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
            
            msg = (
            f"[{protocol}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
            f"({pkt_size} bytes)"
        )

        if ARP in pkt:
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
            protocol = 'ARP'
            msg = f"[ARP] {src_ip} -> {dst_ip} ({pkt_size} bytes)"
        
        data['src_ip'] = src_ip
        data['src_port'] = src_port
        data['dst_ip'] = dst_ip
        data['dst_port'] = dst_port
        data['protocol'] = protocol
        data['pkt_size'] = pkt_size

        self.output.info(msg)
        self.output.record(data)
        