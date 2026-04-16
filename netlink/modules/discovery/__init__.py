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

from scapy.layers.l2 import Ether, ARP
from scapy.all import srp
from netlink.core.base_module import BaseModule

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

    def run(self, args: argparse.Namespace) -> None:
        """
        Executes the main logic of the Discovery module. It sends ARP requests
        to the specified target IP range and listens for responses to identify
        active hosts on the network.
        Args:
            args (argparse.Namespace):  Parsed command-line arguments specific
                                        to the Discovery module.
        """
        hosts_alive = 0
        pkt = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=args.target)
        answered, _ = srp(
            pkt, iface=self.iface, timeout=args.timeout, verbose=0)
        
        for _, pkt_received in answered:
            ip_addr = pkt_received[ARP].psrc
            mac_addr = pkt_received[Ether].src
            msg = f"{ip_addr}:{mac_addr} is alive"
            self.output.success(msg)
            self.output.record({'ip': ip_addr, 'mac': mac_addr})
            hosts_alive += 1
        
        self.output.info(f"There are {hosts_alive} hosts alive")

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
        if args.target:
            return True
        self.output.warn("Please provide a target")
        return False
        