"""
Author: Chris Martinez
Date: 29 April 2026
Version: 1.0.0
Name: __init__.py (crafter)
Description: This module will allow us to send customizable packets out onto the
wire via the use of the command line. Currently the type of packets you will be
able to send are: syn, icmp, udp, arp, and dns
"""

import argparse

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from netlink.core.base_module import BaseModule
from netlink.core.output import OutputManager

class Crafter(BaseModule):
    """
    """
    ############################################################################
    # Class Level Attributes
    ############################################################################
    NAME = "crafter"
    DESCRIPTION = "Send packets over the wire via the command line"
    REQUIRES_ROOT = True


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
        
        """

        # Crafter's global args since they are common to all subparsers
        parser.add_argument(
            '-c',
            '--count',
            type=int,
            action='store',
            dest='count',
            default=0,
            help="Number of packets to send (Default=infinite)"
        )

        parser.add_argument(
            '--interval',
            type=float,
            action='store',
            dest='interval',
            default=0.0,
            help="The interval of N seconds between packets sent (Dafault=0)"
        )

        parser.add_argument(
            't',
            '--target',
            type=str,
            action='store',
            dest='target',
            required=True,
            help="The target's IP address where the packet is sent"
        )


        # Specific args for each packet_type
        subparsers = parser.add_subparsers(
            dest='packet_type',
            metavar='PACKET TYPE',
            help='Packet type to send'
        )
        
        ######TCP SYN #######
        syn_parser = subparsers.add_parser(
            name='syn',
            help=(
                "Sends a TCP SYN packet which can be used for port probing and "
                "firewall testing"
            )
        )

        syn_parser.add_argument(
            '-p',
            '--port',
            type=int,
            action='store',
            dest='port',
            required=True,
            help="Port to send the TCP SYN packet to"
        )

        ######ICMP ECHO REQUEST #######
        icmp_parser = subparsers.add_parser(
            name='icmp',
            help="ICMP echo request, raw ping at the packet level"
        )

        ######UDP #######
        udp_parser = subparsers.add_parser(
            name='udp',
            help="UDP packet with custom payload, used for testing UDP services"
        )

        udp_parser.add_argument(
            '-p',
            '--port',
            type=int,
            action='store',
            dest='port',
            required=True,
            help="Port to send the UDP packet to"
        )

        udp_parser.add_argument(
            '--payload',
            type=str,
            action='store',
            dest='payload',
            default='',
            help="Payload to be sent (Default='')"
        )

        ######ARP REQUEST/REPLY #######
        arp_parser = subparsers.add_parser(
            name='arp',
            help=(
                'ARP request or reply, which is used for network testing and '
                'host resolution'
            )
        )

        arp_parser.add_argument(
            '--op',
            type=str,
            action='store',
            dest='op',
            default='request',
            help='The type of ARP packet you wish to send (Default="request")'
        )

        ######DBS QUERY #######
        dns_parser = subparsers.add_parser(
            name='dns',
            help=(
                'DNS query that is sent directly to a specified resolver, '
                'for testing DNS behavior'
            )
        )

        dns_parser.add_argument(
            '--query',
            type=str,
            action='store',
            dest='query',
            required=True,
            help='The domain to query'
        )

        dns_parser.add_argument(
            '--server',
            type=str,
            action='store',
            dest='server',
            required=True,
            help='The IP of the DNS server'
        )
 

    def run(self, args: argparse.Namespace) -> None:
        """
        
        """
        pass

    def validate_args(self, args: argparse.Namespace) -> bool:
        """
        
        """
        if args.packet_type is None:
            msg = "Must specify the packet type for crafter to send"
            self.output.warn(msg)
            return False
        
        if args.port < 1 and args.port > 65535:
            msg = "Port must be between 1 and 65,535"
            self.output.warn(msg)
            return False
        
        op = args.op.lower()
        if args.op is not 'request' or args.op is not 'reply':
            msg = "Must specified 'request' or 'reply' for an ARP packet"
            self.output.warn(msg)
            return False
        
        #####
        # STILL NEED TO CHECK FOR PROPER SERVER IP
        # NEED TO REVIEW PYTHON'S IPADDRESS MODULE POSSIBLY
        ######


        return True