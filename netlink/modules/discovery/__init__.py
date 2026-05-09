"""
Author: Chris Martinez
Date: 13 April 2026
Version: 1.0.0
Name: __init__.py (discovery)
Description: This module discovers if any hosts on the network are
alive. It sends ARP requests to the specified IP range and listens for
responses. The module can be used to quickly identify active hosts on 
the local network.
"""

import argparse
import ipaddress
import random
import logging

from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, ICMP
from scapy.all import sr, srp
from netlink.core.base_module import BaseModule
from netlink.core.output import OutputManager

class Discovery(BaseModule):
    """The Discovery class is responsible for discovering active hosts
    on the local network using ARP requests.
    """

    ############################################################################
    # Class Level Attributes
    ############################################################################
    NAME: str = "discovery"
    DESCRIPTION: str = "Discover live hosts on the network via ARP Sweep"
    REQUIRES_ROOT: bool = True
    LOWER_PORT = 1024
    UPPER_PORT = 65535
    BROADCAST = 'ff:ff:ff:ff:ff:ff'

    ############################################################################
    # Constructor
    ############################################################################
    def __init__(self, iface: str, output: OutputManager):
        super().__init__(iface, output)

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
        parser.description = (
            "Perform an ARP sweep on the specified network to discover live "
            "hosts. Sends ARP requests to every IP in the target range and "
            "collects replies. Only works on local subnets since ARP does not "
            "cross routers."
        )
        
        parser.add_argument(
            '-t',
            '--target',
            type=str,
            action='store',
            dest='target',
            required=True,
            help=(
                "Target IP range to scan (e.g., 192.168.1.1 or 192.168.1.0/24)"
            )
        )

        parser.add_argument(
            '--timeout',
            type=float,
            action='store',
            dest='timeout',
            default=2,
            help="Timeout in seconds to wait for responses (default: 2)"
        )

        parser.add_argument(
            '--method',
            type=str,
            choices=['arp', 'icmp', 'syn'],
            dest='method',
            default='arp',
            help="Discover method: arp, imcp, syn (default=arp)"
        )

        parser.add_argument(
            '--record-all',
            action='store_true',
            dest='record_all',
            default=False,
            help="Record all host including non-responding (default: False)"
        )

    def run(self, args: argparse.Namespace) -> None:
        """
        Executes the main logic of the Discovery module. Dispatches to the
        appropriate discovery method based on the --method argument. Supports
        three discovery modes: ARP sweep for local subnet discovery, ICMP ping
        for remote subnet discovery, and TCP SYN ping as a reliable fallback
        when ICMP is blocked by firewalls.
        Args:
            args (argparse.Namespace): Parsed command-line arguments specific
                                    to the Discovery module.
        """
        method_selected = args.method

        if method_selected == 'arp':
            self._arp_sweep(args)
        elif method_selected == 'icmp':
            self._icmp_ping(args)
        elif method_selected == 'syn':
            self._syn_ping(args)


    def validate_args(self, args: argparse.Namespace) -> bool:
        """
        Validates the module-specific arguments provided by the user. This 
        method is called by the Engine before running the module. It checks if
        the target argument is a valid IP address or CIDR range and if the
        timeout is a non-negative number.
        Args:
            args (argparse.Namespace): The parsed command-line arguments 
                                        specific to the module.
        Returns:
            bool: True if the arguments are valid, False otherwise.
        """
        try:
            ipaddress.ip_network(args.target, strict=False)
        except Exception:
            msg = "Please provide a valid IPv4 or IPv6 Address"
            self.output.error(msg)
            return False
        
        return True
    
    def _arp_sweep(self, args: argparse.Namespace) -> None:
        """
        Performs an ARP sweep on the specified target network to discover live
        hosts. Sends ARP requests to every IP in the target range and collects
        replies. Only works on local subnets since ARP does not cross routers.
        Displays the IP and MAC address of each responding host.
        Args:
            args (argparse.Namespace): Parsed command-line arguments containing
                                    target and timeout.
        """
        hosts_alive = 0
        target_ip = None
        target_mac = None

        pkt = Ether(dst=self.BROADCAST)/ARP(pdst=args.target)
        answered, unanswered = srp(
            pkt, iface=self.iface, timeout=args.timeout, verbose=0)
        
        for _, pkt_received in answered:
            if pkt_received.haslayer(ARP):
                target_ip = pkt_received[ARP].psrc
            else:
                target_ip = 'unknown'

            if pkt_received.haslayer(Ether):
                target_mac = pkt_received[Ether].src
            else:
                target_mac = 'unknown'

            data = {
                'target_ip': target_ip,
                'method': 'arp',
                'host_status': 'alive',
            }

            msg = f"{target_ip} at {target_mac} is alive"

            self.output.success(msg)
            self.output.record(data)

            hosts_alive += 1
        
        if args.record_all:
            for pkt_sent, in unanswered:
                data = {
                    'target_ip': pkt_sent[ARP].pdst,
                    'method': 'arp',
                    'host_status': 'no_response',
                }

                self.output.record(data)
        
        self.output.info(f"There are {hosts_alive} hosts alive")

    def _icmp_ping(self, args: argparse.Namespace) -> None:
        """
        Performs ICMP echo request discovery on the specified target network.
        Expands the CIDR range using the ipaddress module and sends an ICMP
        echo request to each host. A response indicates the host is alive.
        Works across routers but may be blocked by firewalls. Displays the IP
        address of each responding host.
        Args:
            args (argparse.Namespace): Parsed command-line arguments containing
                                    target and timeout.
        """
        # So MAC Broadcast warning don't appear, excessive on linux
        # Will need to readdress this later
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

        ECHO_REQUEST = 8
        hosts_alive = 0
        target_ip = None
        network = ipaddress.ip_network(args.target, strict=False).hosts()
        pkts = [IP(dst=str(host))/ICMP(type=ECHO_REQUEST) for host in network]

        answered, unanswered = sr(pkts, timeout=args.timeout, verbose=0)

        for _, pkt_received in answered:
            if pkt_received.haslayer(IP):
                target_ip = pkt_received[IP].src
            else:
                target_ip = "N/A"

            data = {
                'target_ip': target_ip,
                'method': 'icmp',
                'host_status': 'alive',
            }

            msg = f"{target_ip} is alive"
            self.output.info(msg)
            self.output.record(data)
            hosts_alive += 1

        if args.record_all:
            for pkt_sent in unanswered:
                data = {
                    'target_ip': pkt_sent[IP].dst,
                    'method': 'icmp',
                    'host_status': 'no_response',
                }
            
                self.output.record(data)
        
        self.output.info(f"There are {hosts_alive} hosts alive")


    def _syn_ping(self, args: argparse.Namespace) -> None:
        """
        Performs TCP SYN ping discovery on the specified target network.
        Expands the CIDR range using the ipaddress module and sends a TCP SYN
        packet to port 80 of each host. A SYN-ACK or RST response indicates
        the host is alive regardless of whether the port is open or closed.
        More reliable than ICMP when firewalls block echo requests.
        Args:
            args (argparse.Namespace): Parsed command-line arguments containing
                                    target and timeout.
        """
        # So MAC Broadcast warning don't appear, excessive on linux
        # Will need to readdress this later
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

        TARGET_PORT = 80 #HTTP
        hosts_alive = 0
        source_port = random.randint(self.LOWER_PORT, self.UPPER_PORT)
        target_ip = None
        network = ipaddress.ip_network(args.target, strict=False).hosts()
        pkts = [
            IP(dst=str(host))/TCP(sport=source_port, dport=TARGET_PORT) 
            for host in network
        ]

        answered, unanswered = sr(pkts, timeout=args.timeout, verbose=0)

        for _, pkt_received in answered:
            if pkt_received.haslayer(IP):
                target_ip = pkt_received[IP].src
            else:
                target_ip = "N/A"
                        
            data = {
                'target_ip': target_ip,
                'method': 'syn',
                'host_status': 'alive',
            }

            msg = f"{target_ip} is alive"
            self.output.info(msg)
            self.output.record(data)
            hosts_alive += 1
        
        if args.record_all:
            for pkt_sent in unanswered:
                data = {
                    'target_ip': pkt_sent[IP].dst,
                    'method': 'syn',
                    'host_status': 'no_response',
                }

                self.output.record(data)
        
        self.output.info(f"There are {hosts_alive} hosts alive")
