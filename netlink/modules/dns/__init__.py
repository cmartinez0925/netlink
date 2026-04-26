"""
Author: Chris Martinez
Date: 26 April 2026
Version: 1.0.0
Name: __init__.py (dns)
Description: This module analyzes DNS traffic on the network by capturing and 
decoding DNS queries and responses. It tracks domain query frequency, logs 
source IPs, and displays resolved addresses to provide visibility into network 
DNS activity and detect anomalous behavior.
"""

import argparse

from scapy.all import sniff
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP, TCP
from scapy.packet import Packet
from netlink.core.base_module import BaseModule
from netlink.core.output import OutputManager

class DNSAnalyzer(BaseModule):
    """
    The DNSAnalyzer class passively monitors DNS traffic on the network by 
    capturing packets on port 53 and decoding both queries and responses. 
    It maintains a query log tracking how frequently each domain is queried 
    and supports filtering to show only queries or only responses. Results 
    are displayed in real time and a summary of the top queried domains is 
    provided at the end of each session.
    """
    ############################################################################
    # Class Level Attributes
    ############################################################################
    NAME = "dns"
    DESCRIPTION = "Capture and analyze DNS queries and responses on the network"
    REQUIRES_ROOT = True
    
    DNS_QUERY = 0
    DNS_RESPONSE = 1

    ############################################################################
    # Constructor
    ############################################################################
    def __init__(self, iface: str, output: OutputManager):
        super().__init__(iface, output)

        # Tracks how many times each domain has been queried.
        # Key is domain, Value is count
        self._query_log: dict[str, int] = dict() 

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
            "Monitors DNS traffic on the networks by capturing packets on port "
            "53 and decodes both queries and responses. Runs indefinitely by "
            "default (--count 0) until stopped with Crtl+C or --timeout is "
            "reached."
        )

        parser.add_argument(
            '-c',
            '--count',
            type=int,
            action='store',
            dest='count',
            default=0,
            help="Number of packets to caputre (Default=infinite)"
        )

        parser.add_argument(
            '--timeout',
            type=int,
            action='store',
            dest='timeout',
            default=None,
            help="Stop sniffing after N seconds (Default=None)"    
        )

        parser.add_argument(
            '--queries-only',
            action='store_true',
            dest='queries_only',
            default=False,
            help="Shows only queries, not responses (Default=False)"
        )

        parser.add_argument(
            '--responses-only',
            action='store_true',
            dest='responses_only',
            default=False,
            help="Shows only responses not queries (Default=False)"
        )

    def run(self, args: argparse.Namespace) -> None:
        """
        Executes the main functionality of the DNSAnalyzer module. This method 
        is called by the Engine when the user runs this module from the CLI.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                       specific to the sniffer module.
        Returns:
            bool: True if the module executed successfully, False otherwise.
        """
        pass

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
        if args.queries_only and args.responses_only:
            msg = (
                "You cannot set the '--queries-only' and '--responses-only' at "
                "the same time, please only choose one."
            )
            self.output.warn(msg)
            return False
        elif args.count < 0:
            self.output.warn("Count must be greater than 0 packets")
            return False
        return True
    
    def _process_packet(self, pkt: Packet, args: argparse.Namespace) -> None:
        """
        Processes each captured DNS packet and extracts relevant information.
        This method is called by Scapy for each packet captured on port 53.
        It inspects the DNS layer to determine if the packet is a query or a
        response using the qr flag (0=query, 1=response). For queries it 
        extracts the domain name and source IP, updates the internal query log,
        and logs the event. For responses it extracts the domain name, resolved
        address from the answer record, and source IP. Respects the 
        --queries-only and --responses-only flags to filter output accordingly.
        Args:
            pkt (Packet): The captured packet object provided by Scapy.
            args (argparse.Namespace): The parsed command-line arguments used
                                    to check query/response filter flags.
        """
        if DNS in pkt:
            query_msg = None
            response_msg = None

            if pkt[DNS].qr == self.DNS_QUERY:
                domain_name = pkt[DNS].qd.qname.decode()
                src_ip = pkt[IP].src
                self._query_log[domain_name] = self._query_log.get(domain_name, 0) + 1
                query_amt = self._query_log[domain_name]
                query_event = {
                    'event': 'query',
                    'src_ip': src_ip,
                    'domain': domain_name,
                    'count': query_amt,
                }
                query_msg = (
                    f"[QUERY] {src_ip} asked for {domain_name}. "
                    f"(Seen {query_amt} {'time' if query_amt == 1 else 'times'}.)"
                )
                self.output.record(query_event)
            elif pkt[DNS].qr == self.DNS_RESPONSE:
                domain_name = pkt[DNS].an.rrname.decode()
                domain_addr = pkt[DNS].an.rdata #Decode not needed for A records
                src_ip = pkt[IP].src
                response_event = {
                    'event': 'response',
                    'src_ip': src_ip,
                    'domain': domain_name,
                    'resolved_to': domain_addr,
                }
                response_msg = (
                    f"[RESPONSE] {domain_name} resolved to {domain_addr}"
                )
                self.output.record(response_event)
            if args.queries_only and not args.responses_only:
                # Display only queries
                if query_msg:
                    self.output.info(query_msg)
            elif args.responses_only and not args.queries_only:
                # Display only responses
                if response_msg:
                    self.output.info(response_msg)
            else:
                # Display both
                if query_msg:
                    self.output.info(query_msg)
                if response_msg:
                    self.output.info(response_msg)
