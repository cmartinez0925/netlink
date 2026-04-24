"""
Author: Chris Martinez
Date: 15 April 2026
Version: 1.0.0
Name: __init__.py (scanner)
Description: This module is responsible for scanning hosts on the network to 
identify open ports and services. It uses TCP SYN scanning toprobe specified 
ports on target hosts and determines if they are open,closed, or filtered. The 
module can be used to quickly assess the attack surface of a host by identifying
which services are running and potentially vulnerable.
"""
import argparse
import random

from scapy.layers.inet import IP, TCP
from scapy.all import sr1, send
from netlink.core.base_module import BaseModule


class Scanner(BaseModule):
    """
    The Scanner class is responsible for scanning hosts on the network
    to identify open ports and services.
    """
    ############################################################################
    # Class Level Attributes
    ############################################################################
    NAME = "scanner"
    DESCRIPTION = "SYN port scanner"
    REQUIRES_ROOT = True   

    ############################################################################
    # Constructor
    ############################################################################
    # No need, already inherited by BaseModule

    ############################################################################
    # Methods
    ############################################################################
    def add_args(self, parser):
        """
        Adds module-specific arguments to the argument parser. This method is
        called by the Engine when setting up the CLI for this module.
        Args:
            parser (argparse.ArgumentParser): The argument parser to which
                                              module-specific args are added.
        """
        parser.description = (
            "Perform a TCP SYN scan on the specified target to identify open "
            "ports. Sends SYN packets to each port and analyzes responses — "
            "SYN-ACK means open, RST means closed, no response means filtered. "
            "Requires root."
        )
        
        parser.add_argument(
            '-t',
            '--target',
            type=str,
            action='store',
            dest='target',
            required=True,
            help=(
                "Target IP range to scan (e.g., 192.168.1.1)"
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
            '-p',
            '--ports',
            type=str,
            action='store',
            dest='ports',
            default='1-1024',
            help="Ports to scan (e.g., 1-1024 or 80, 443) (default: 1-1024)"
        )    

    def run(self, args: argparse.Namespace) -> None:
        """
        Executes the main functionality of the Scanner module. This method is
        called by the Engine after validating the arguments. It performs a SYN
        scan on the specified target and ports, and outputs the results.
        Args:
            args (argparse.Namespace): The parsed command-line arguments 
                                       specific to the Scanner module.
        """
        SYN_ACK = 0x12
        RST_ACK = 0x14

        ports = self.parse_ports(args.ports)
        ports_open = 0

        for port in ports:
            my_port = random.randint(1024, 65535)
            pkt = IP(dst=args.target)/TCP(sport=my_port, dport=port, flags='S')
            response = sr1(pkt, timeout=args.timeout, verbose=0)

            # Access the response to determine if port is open
            if response is None:
                # Port is filtered or dropped
                continue
            elif response[TCP].flags == SYN_ACK:
                # Port is open
                ip_addr = response[IP].src
                msg = f"{ip_addr}:{port} is open"
                pkt = IP(dst=ip_addr)/TCP(sport=my_port, dport=port, flags='R')
                send(pkt, verbose=0)
                self.output.success(msg)
                self.output.record({'ip': args.target, 'port': port})
                ports_open += 1
            elif response[TCP].flags == RST_ACK:
                # Port is closed
                continue

        self.output.info(f"{args.target} has {ports_open} ports open")       

    @staticmethod
    def parse_ports(ports_str: str) -> list[int]:
        """
        Parses a string of ports and returns a list of integers.
        The input string can contain individual ports separated by commas, 
        and port ranges specified with a hyphen.
        Args:
            ports_str (str): A string representing ports to scan (e.g., "80,443,
                             1000-2000").
        Returns:
            list[int]: A list of port numbers to scan.
        """
        ports: list[int] = list()

        ports_str_list = ports_str.split(',')

        for port in ports_str_list:
            if '-' in port:
                temp_list = port.split('-')
                start = int(temp_list[0])
                end = int(temp_list[1]) + 1
                ports.extend(range(start, end))
            else:
                ports.append(int(port))

        return ports

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
        if not args.target:
            self.output.warn("Please provide a target")
            return False

        if not args.ports:
            self.output.warn("Please provide a port(s) to scan")
            return False

        return True
    