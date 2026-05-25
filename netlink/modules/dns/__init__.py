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

from functools import partial
from scapy.all import sniff
from scapy.layers.dns import DNS
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet
from typing import Any

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

    DNS_RECORD_TYPES = {
        1:   'A',
        2:   'NS',
        5:   'CNAME',
        6:   'SOA',
        12:  'PTR',
        15:  'MX',
        16:  'TXT',
        17:  'RP',
        18:  'AFSDB',
        24:  'SIG',
        25:  'KEY',
        28:  'AAAA',
        29:  'LOC',
        33:  'SRV',
        35:  'NAPTR',
        36:  'KX',
        37:  'CERT',
        39:  'DNAME',
        41:  'OPT',
        42:  'APL',
        43:  'DS',
        44:  'SSHFP',
        45:  'IPSECKEY',
        46:  'RRSIG',
        47:  'NSEC',
        48:  'DNSKEY',
        49:  'DHCID',
        50:  'NSEC3',
        51:  'NSEC3PARAM',
        52:  'TLSA',
        53:  'SMIMEA',
        55:  'HIP',
        59:  'CDS',
        60:  'CDNSKEY',
        61:  'OPENPGPKEY',
        62:  'CSYNC',
        63:  'ZONEMD',
        64:  'SVCB',
        65:  'HTTPS',
        99:  'SPF',
        108: 'EUI48',
        109: 'EUI64',
        249: 'TKEY',
        250: 'TSIG',
        251: 'IXFR',
        252: 'AXFR',
        255: 'ANY',
        256: 'URI',
        257: 'CAA',
        32768: 'TA',
        32769: 'DLV',
    }

    ############################################################################
    # Constructor
    ############################################################################
    def __init__(self, iface: str, output: OutputManager):
        super().__init__(iface, output)

        # Tracks how many times each domain has been queried.
        # Key is domain, Value is count
        self._query_log: dict[str, int] = dict()
        self._pkt_count: int = 0

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

        parser.add_argument(
            '--top',
            type=int,
            dest='top',
            default=5,
            help="Display the top queried domains (Default=5)"  
        )

    def run(self, args: argparse.Namespace) -> None:
        """
        Executes the main functionality of the DNSAnalyzer module. This method
        is called by the Engine when the user runs this module from the CLI.
        It sets up the packet capture using Scapy's sniff() function with a
        port 53 BPF filter to capture only DNS traffic. Uses functools.partial
        to bind the parsed arguments to _process_packet so the query/response
        filter flags are accessible during packet processing. After capturing
        is complete, prints a summary of the top 5 most queried domains from
        the internal query log.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                    specific to the DNSAnalyzer module.
        """
        prn = partial(self._process_packet, args=args)
        
        sniff_kwargs = {
            'iface': self.iface,
            'count': args.count,
            'filter': 'port 53',
            'prn': prn,
            'timeout': args.timeout,
        }

        sniff(**sniff_kwargs)
        label = f"{'Packet' if self._pkt_count == 1 else 'Packets'}"
        msg = f"Total amount of packets to display -> {self._pkt_count} {label}"
        self.output.info(msg)
        self._print_top(args)
     
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
            
            # To defensively guard with MacOS BPF Quirks
            if IP not in pkt and IPv6 not in pkt:
                return
            
            if pkt[DNS].qr == self.DNS_QUERY:
                query_event, query_msg = self._parse_query(pkt)
                self.output.record(query_event)
            elif pkt[DNS].qr == self.DNS_RESPONSE:
                # Guard in case there is no answer record 
                if pkt[DNS].an is None:  
                    return
                try:
                    response_event, response_msg = self._parse_response(pkt)
                    self.output.record(response_event)
                except Exception:
                    return
                
            self._pkt_count += 1
            self._print_messages(query_msg, response_msg, args)

    def _parse_query(self, pkt: Packet) -> tuple[dict, str]:
        """
        Parses a DNS query packet and extracts the queried domain name and
        source IP address. Updates the internal query log by incrementing
        the count for the domain and builds a structured event dictionary
        for JSON recording along with a formatted terminal message showing
        how many times the domain has been queried in the current session.
        Args:
            pkt (Packet): The captured packet object provided by Scapy.
        Returns:
            tuple[dict, str]: A tuple containing the structured query event
                            dictionary for recording and a formatted string
                            showing the source IP, domain name, and running
                            query count for terminal display.
        """
        domain_name = pkt[DNS].qd.qname.decode()
        src_ip = pkt[IP].src if IP in pkt else pkt[IPv6].src

        self._query_log[domain_name] = self._query_log.get(
            domain_name, 0) + 1
        count = self._query_log[domain_name]

        query_event = {
            'event': 'query',
            'src_ip': src_ip,
            'domain_name': domain_name,
            'count': count,
        }

        query_msg = (
            f"[QUERY] {src_ip} asked for {domain_name} "
            f"(Seen {count} "
            f"{'time' if count == 1 else 'times'}.)"
        )

        return query_event, query_msg
    
    def _parse_response(self, pkt: Packet) -> tuple[dict, str]:
        """
        Parses a DNS response packet and extracts the resolved domain name,
        answer address, DNS record type, and source IP address. Resolves the
        record type integer to a human readable string using the DNS_RECORD_TYPES
        class attribute. Delegates rdata decoding to _get_domain_addr to handle
        both bytes and non-bytes rdata types safely. Assumes the answer record
        is not None — callers must guard against this before invoking.
        Args:
            pkt (Packet): The captured packet object provided by Scapy.
        Returns:
            tuple[dict, str]: A tuple containing the structured response event
                            dictionary for recording and a formatted string
                            showing the domain name and resolved address for
                            terminal display.  
        """
        src_ip = pkt[IP].src if IP in pkt else pkt[IPv6].src
        domain_name = pkt[DNS].an.rrname.decode()
        rdata = pkt[DNS].an.rdata
        record_type_num = pkt[DNS].an.type
        record_type = self.DNS_RECORD_TYPES.get(
            record_type_num, f'Unknown {record_type_num}'
        )

        domain_addr = self._get_domain_addr(rdata)

        response_event = {
            'event': 'response',
            'src_ip': src_ip,
            'domain_name': domain_name,
            'resolved_to': domain_addr,
            'record_type': record_type,
        }

        response_msg = (
            f"[RESPONSE] {domain_name} resolved to {domain_addr}"
        )

        return response_event, response_msg
    
    def _get_domain_addr(self, rdata: Any) -> str:
        """
        Safely converts DNS answer rdata to a human readable string for display
        and JSON serialization. CNAME and PTR records return rdata as bytes
        containing an encoded domain name which must be decoded. A and AAAA
        records return rdata as a plain string IP address. Handles both cases
        by checking the type and decoding bytes using UTF-8 with replacement
        for any invalid characters.
        Args:
            rdata (Any): The rdata field from a Scapy DNS answer record.
        Returns:
            str: A human readable string representation of the resolved address
                or domain name safe for both terminal display and JSON output. 
        """
        if isinstance(rdata, bytes):
            return rdata.decode('utf-8', errors='replace')
        else:
            return str(rdata)

    def _print_messages(self, 
                        query_msg: str|None,
                        response_msg: str|None,
                        args: argparse.Namespace) -> None:
        """
        Prints query and response messages to the terminal based on the active
        filter flags. Respects --queries-only to suppress response messages and
        --responses-only to suppress query messages. When neither flag is set
        both query and response messages are displayed. Each message is only
        printed if it is not None since only one of query_msg or response_msg
        will be set for any given packet.
        Args:
            query_msg (str | None): The formatted query message to display or
                                    None if the current packet is not a query.
            response_msg (str | None): The formatted response message to display
                                    or None if the current packet is not a
                                    response.
            args (argparse.Namespace): The parsed command-line arguments used
                                    to check the queries_only and
                                    responses_only flags.
        """
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

    def _print_top(self, args: argparse.Namespace) -> None:
        """
        Prints a summary of the most frequently queried domains from the
        internal query log. Sorts the query log by count in descending order
        and displays the top N entries where N is controlled by the --top
        argument. Each entry shows the domain name and the number of times
        it was queried during the current session.
        Args:
            args (argparse.Namespace): The parsed command-line arguments used
                                    to determine how many top entries to
                                    display via the top attribute.
        """
        top_queries = sorted(self._query_log.items(), 
                            key=lambda item: item[1],
                            reverse=True)[:args.top]
        msg = f"The top {args.top} queries are:"
        self.output.info(msg)
        
        for domain, value in top_queries:
            msg = (
                f"\t Domain: {domain} --> Amount Queried: {value}"
            )
            self.output.info(msg)
