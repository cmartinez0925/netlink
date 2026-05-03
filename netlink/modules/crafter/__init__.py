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
import ipaddress
import itertools
import random
import time

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.all import send
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
        Adds module-specific arguments to the argument parser. Creates a nested
        subparser for each supported packet type (syn, icmp, udp, arp, dns).
        Each packet type has its own set of arguments while sharing common
        arguments for target, count, and interval.
        Args:
            parser (argparse.ArgumentParser): The argument parser to which
                                            module-specific args are added.
        """
        # Crafter's global args since they are common to all subparsers
        parser.add_argument(
            '-c',
            '--count',
            type=int,
            action='store',
            dest='count',
            default=1,
            help="Number of packets to send (Default=1, 0=infinite)"
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
            '-t',
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

        ######DNS QUERY #######
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
        Executes the main functionality of the Crafter module. Dispatches to
        the appropriate packet send method based on the chosen packet type.
        Prints a summary after the dispatch method returns.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                    specific to the Crafter module.
        """
        dispatch = {
            'syn': self._send_syn,
            'icmp': self._send_icmp,
            'udp': self._send_udp,
            'arp': self._send_arp,
            'dns': self._send_dns,
        }

        if args.packet_type is None:
            self.output.error("Please provide a packet type")
            return
        
        handler = dispatch[args.packet_type]
        handler(args)

    def validate_args(self, args: argparse.Namespace) -> bool:
        """
        Validates the provided arguments for the Crafter module. Checks that
        a packet type was specified, that port numbers are within valid range
        for syn and udp packets, and that the arp operation is either request
        or reply.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                    specific to the Crafter module.
        Returns:
            bool: True if the arguments are valid, False otherwise.
        """
        if args.packet_type is None:
            msg = "Must specify the packet type for crafter to send"
            self.output.warn(msg)
            return False
        elif args.packet_type in ('syn', 'udp'):
            if args.port < 1 or args.port > 65535:
                msg = "Port must be between 1 and 65,535"
                self.output.warn(msg)
                return False
        elif args.packet_type == 'arp':
            # Make sure op is either 'request' or 'reply
            op = args.op.lower().strip()
            if args.op not in ('request', 'reply'):
                msg = "Must specified 'request' or 'reply' for an ARP packet"
                self.output.warn(msg)
                return False
        
        # Make sure target ip is proper format
        try:
            ipaddress.ip_address(args.target)
        except Exception as e:
            msg = "Please provide a valid IPv4 or IPv6 address"
            self.output.error(msg)
            return False

        return True
    
    ############################################################################
    # Packet Send Methods
    ############################################################################
    def _send_syn(self, args: argparse.Namespace) -> None:
        """
        Builds and sends a TCP SYN packet to the specified target and port.
        Uses a random source port for each packet. Useful for port probing
        and firewall testing.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                    containing target, port, count, and
                                    interval.
        """
        source_port = random.randint(1024, 65535)
        target_port = args.port
        target_ip = args.target
        pkt = IP(dst=target_ip)/TCP(sport=source_port, dport=target_port)
        counter = range(args.count) if args.count > 0 else itertools.count()
        
        for _ in counter:
            send(pkt, verbose=0)
            self.output.success(f"SYN sent to {target_ip}:{target_port}")
            data = {
                'packet_type': args.packet_type,
                'source_port': source_port,
                'target_ip': target_ip,
                'target_port': target_port,
            }
            self.output.record(data)
            time.sleep(args.interval)

    def _send_icmp(self, args: argparse.Namespace) -> None:
        """
        Builds and sends an ICMP echo request packet to the specified target.
        Useful for raw ping testing at the packet level when system ping is
        unavailable or blocked.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                    containing target, count, and interval.
        """
        pass

    def _send_udp(self, args: argparse.Namespace) -> None:
        """
        Builds and sends a UDP packet with a custom payload to the specified
        target and port. Useful for testing UDP services and custom protocol
        interaction.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                    containing target, port, payload,
                                    count, and interval.
        """
        pass

    def _send_arp(self, args: argparse.Namespace) -> None:
        """
        Builds and sends an ARP request or reply packet to the specified
        target. Op code 1 sends a request (who-has) and op code 2 sends a
        reply (is-at). Useful for network testing and groundwork for ARP
        spoofing.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                    containing target, op, count, and
                                    interval.
        """
        pass

    def _send_dns(self, args: argparse.Namespace) -> None:
        """
        Builds and sends a DNS query packet to the specified DNS server for
        the given domain. Sends directly over UDP to port 53. Useful for
        testing DNS resolver behavior and custom DNS interactions.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                    containing target, server, query,
                                    count, and interval.
        """
        pass
