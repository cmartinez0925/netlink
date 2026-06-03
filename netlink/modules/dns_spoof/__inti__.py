# ARGS
    # --target the victim's IP address
    #--domain the domain to spoof (e.g. google.com)
    #--spoof-ip the fake IP address to redirect the victim to
    #--ttl optional, how long the victim caches the fake record

#Data for the response pkt (DNSRR)
    #rrname = pkt[DNS].qd.qname
    #type = 1 (A Record aka IPv4)
    #ttl = This is either similar to the dns server you are pretending to be or as long as we need it to be to accomplish our goal
    #rdata = This is the actual IP Address

#sniff
    # BPF Filter = 'udp and port 53'


"""
Author: Chris Martinez
Date: 2 June 2026
Version: 1.0.0
Name: __init__.py (dns_spoof)
Description: 
"""

import argparse
import ipaddress
import itertools
import signal

from functools import partial
from scapy.all import sniff, send
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from typing import Any
from types import FrameType

from netlink.core.base_module import BaseModule
from netlink.core.output import OutputManager

class DNSSpoof(BaseModule):
    """

    """

    ############################################################################
    # Class Level Attributes
    ############################################################################
    NAME: str = "dns_spoof"
    DESCRIPTION: str = "Performs DNS spoofing on a designated victim"
    REQUIRES_ROOT: bool = True

    DNS_FILTER = "udp and port 53"

    ############################################################################
    # Constructor
    ############################################################################
    def __init__(self, iface: str, output: OutputManager):
        """

        """
        super().__init__(iface, output)
        self._keyboard_interrupted = False

    ############################################################################
    # Abstract Required Methods
    ############################################################################
    def add_args(self, parser: argparse.ArgumentParser) -> None:
        """

        """
        parser.add_argument(
            '-t',
            '--target',
            type=str,
            action='store',
            dest='target',
            required=True,
            help="The target's IP address where the DNS Response will be sent"
        )

        parser.add_argument(
            '-s',
            '--spoof-ip',
            type=str,
            action='store',
            dest='spoof_ip',
            required=True,
            help="The f"
        )

        parser.add_argument(
            '-d',
            '--domain',
            type=str,
            action='store',
            dest='domain',
            required=True,
            help="The domain address"
        )

        parser.add_argument(
            '--ttl',
            type=int,
            action='store',
            dest='ttl',
            default=300,
            help=""
        )

    def run(self, args: argparse.Namespace) -> None:
        """

        """
        pass

    ############################################################################
    # Methods
    ############################################################################
    def validate_args(self, args: argparse.Namespace) -> bool:
        """

        """
        return True

    def _process_packet(self, pkt: Packet, args: argparse.Namespace) -> None:
        """
        
        """
        pass

    def _signint_handler(self, sig: int, frame: FrameType|None) -> None:
        """
        
        """
        self._keyboard_interrupted = True