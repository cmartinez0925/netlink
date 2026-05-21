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
from typing import Any

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

    ICMP_TYPES = {
        0: 'Echo Reply',
        3: 'Destination Unreachable',
        4: 'Source Quench',
        5: 'Redirect',
        8: 'Echo Request',
        9: 'Router Advertisement',
        10: 'Router Solicitation',
        11: 'Time Exceeded',
        12: 'Parameter Problem',
        13: 'Timestamp Request',
        14: 'Timestamp Reply',
    }

    ICMP_CODES = {
        3: {  # Destination Unreachable
            0: 'Net Unreachable',
            1: 'Host Unreachable',
            2: 'Protocol Unreachable',
            3: 'Port Unreachable',
            4: 'Fragmentation Needed',
            5: 'Source Route Failed',
            6: 'Destination Network Unknown',
            7: 'Destination Host Unknown',
            9: 'Network Administratively Prohibited',
            10: 'Host Administratively Prohibited',
            11: 'Network Unreachable for TOS',
            12: 'Host Unreachable for TOS',
            13: 'Communication Administratively Prohibited',
        },
        5: {  # Redirect
            0: 'Redirect for Network',
            1: 'Redirect for Host',
            2: 'Redirect for TOS and Network',
            3: 'Redirect for TOS and Host',
        },
        11: {  # Time Exceeded
            0: 'TTL Exceeded in Transit',
            1: 'Fragment Reassembly Time Exceeded',
        },
        12: {  # Parameter Problem
            0: 'Pointer Indicates Error',
            1: 'Missing Required Option',
            2: 'Bad Length',
        },
    }

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
            f"{'Packet' if len(pkts) == 1 else 'Packets'}\n"
        )
        self.output.info(msg)
        self.output.info("Protocol Summary:")
        for proto, count in sorted(self._protocol_count.items()):
            packet_or_packets = 'packet' if count == 1 else 'packets'
            self.output.info(f"\t{proto:<14} {count} {packet_or_packets}")

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
        data: dict[str, Any] = dict()
        
        protocol = 'Other'
        pkt_size_print =f"({PKT_SIZE} {'byte' if PKT_SIZE == 1 else 'bytes'})"
        terminal_printout = f"[Other] {pkt_size_print}"

        if pkt.haslayer(IP):
            terminal_printout, data = self._inspect_ip(pkt, IP, args) #type: ignore
        elif pkt.haslayer(IPv6):
            terminal_printout, data = self._inspect_ip(pkt, IPv6, args) #type: ignore
        elif pkt.haslayer(ARP):
            protocol = 'ARP'
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc
            dst_ip = pkt[ARP].pdst
            dst_mac = pkt[ARP].hwdst

            data = {
                'protocol': protocol,
                'src_ip': src_ip,
                'src_mac': src_mac,
                'dst_ip': dst_ip,
                'dst_mac': dst_mac,
            }

            self._increase_count(protocol)

            if args.verbose:
                #NO NEED FOR VERBOSE AT THE MOMENT
                pass

            terminal_printout = (
                f"[{protocol}] {src_ip} ({src_mac}) --> {dst_ip} ({dst_mac}) "
                f"{pkt_size_print}"
            )
        elif pkt.haslayer(Dot1Q):
            protocol = 'VLAN'
            src_mac = pkt[Ether].src if pkt.haslayer(Ether) else 'None'
            dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else 'None'
            vlan_id = pkt[Dot1Q].vlan

            data = {
                'protocol': protocol,
                'src_mac': src_mac,
                'dst_mac': dst_mac,
                'vlan_id': vlan_id,
            }

            self._increase_count(protocol)

            if args.verbose:
                #NO NEED FOR VERBOSE AT THE MOMENT
                pass

            terminal_printout = (
                f"[{protocol}] id={vlan_id} src={src_mac} --> dst={dst_mac} "
                f"{pkt_size_print}"
            )
        elif pkt.haslayer(STP):
            protocol = 'STP'
            proto = pkt[STP].proto
            version = pkt[STP].version
            
            self._increase_count(protocol)
            
            if args.verbose:
                #NO NEED FOR VERBOSE AT THE MOMENT
                pass

            terminal_printout = (
                f"[{protocol}] proto={proto} version={version} {pkt_size_print}"
            )


        self.output.info(terminal_printout)
        self.output.record(data)
    
    def _inspect_ip(self, pkt: Packet, ip_version: IP|IPv6, 
                    args: argparse.Namespace) -> tuple[str, dict[str, Any]]:
        """
        Inspects an IP or IPv6 packet and extracts protocol information for
        display. Determines the highest-level protocol present in the packet
        by checking layers in order from most specific to most generic:
        TLS → HTTP → DNS → DHCP → TCP → UDP → ICMP. Extracts source and
        destination IP addresses, ports where applicable, and additional
        protocol-specific fields for verbose output. Returns a formatted
        one-line summary string for default output or an enriched multi-line
        string when verbose mode is enabled.
        Args:
            pkt (Packet): The captured packet object provided by Scapy.
            ip_version (IP | IPv6): The IP layer class to use for address
                                    extraction. Pass IP for IPv4 packets or
                                    IPv6 for IPv6 packets.
            args (argparse.Namespace): The parsed command-line arguments used
                                    to check verbose and deep_inspect flags.
        Returns:
            str: A formatted string containing the protocol, source and
                destination addresses and ports, packet size, and optionally
                additional protocol-specific fields when verbose is enabled.
        """
        PKT_SIZE = len(pkt)

        src_ip = None
        src_port = None
        dst_ip = None
        dst_port = None
        protocol = 'Other'
        data: dict[str, Any] = dict()

        pkt_size_print =f"({PKT_SIZE} {'byte' if PKT_SIZE == 1 else 'bytes'})"
        terminal_printout = f"[Other] {pkt_size_print}"
        additional_data = ''

        if pkt.haslayer(ip_version): #type: ignore
            src_ip = pkt[ip_version].src #type: ignore
            dst_ip = pkt[ip_version].dst #type: ignore

            if pkt.haslayer(TLS):
                data, additional_data = self._parse_TLS(pkt, src_ip, dst_ip)
            elif pkt.haslayer(HTTP):
                data, additional_data = self._parse_HTTP(pkt, src_ip, dst_ip)
            elif pkt.haslayer(DNS):
                data, additional_data = self._parse_DNS(pkt, src_ip, dst_ip)
            elif pkt.haslayer(DHCP):
                data, additional_data = self._parse_DHCP(pkt, src_ip, dst_ip)
            elif pkt.haslayer(TCP):
                data, additional_data = self._parse_TCP(pkt, src_ip, dst_ip)
            elif pkt.haslayer(UDP):
                protocol = 'UDP'
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                length = pkt[UDP].len
                chksum = pkt[UDP].chksum

                data = {
                    'protocol': protocol,
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'length': length,
                    'chksum': chksum,
                }

                self._increase_count(protocol)

                if args.verbose:
                    additional_data = (
                        f"\t<Additional_Data>\n"
                        f"\tLEN: {length}\n"
                        f"\tCHKSUM: {chksum}"
                    )
            elif pkt.haslayer(ICMP):
                protocol = 'ICMP'
                icmp_type = self.ICMP_TYPES.get(pkt[ICMP].type, 'Unknown')
                icmp_code = self.ICMP_CODES.get(
                    pkt[ICMP].type, {}).get(
                        pkt[ICMP].code, 'N/A')
                icmp_id = pkt[ICMP].id
                icmp_seq = pkt[ICMP].seq

                data = {
                    'protocol': protocol,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'type': icmp_type,
                    'code': icmp_code,
                    'id': icmp_id,
                    'seq': icmp_seq,
                }

                self._increase_count(protocol)

                if args.verbose:
                    additional_data = (
                        f"\t<Additional_Data>\n"
                        f"\tType: {icmp_type}\n"
                        f"\tCode: {icmp_code}\n"
                        f"\tID: {icmp_id}\n"
                        f"\tSEQ: {icmp_seq}"
                    )
            else:    
                protocol = 'IPv4' if ip_version == IP else 'IPv6'
                data = {
                    'protocol': protocol,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                }
                self._increase_count(protocol)

            protocol = data.get('protocol', 'Other')
            src_port = data.get('src_port', None)
            dst_port = data.get('dst_port', None)
            
            if args.verbose:
                terminal_printout = (
                    f"[{protocol}] {src_ip}:{src_port} --> {dst_ip}:{dst_port} "
                    f"{pkt_size_print}"
                )
                if additional_data:
                    terminal_printout += f"\n{additional_data}"
            else:
                terminal_printout = (
                    f"[{protocol}] {src_ip}:{src_port} --> {dst_ip}:{dst_port} "
                    f"{pkt_size_print}"
                )      
        
        return terminal_printout, data
    
    def _increase_count(self, protocol: str) -> None:
        """
        Increments the packet count for the specified protocol in the internal
        protocol count dictionary. If the protocol has not been seen before it
        is initialized to 1. Used to build the protocol summary displayed at
        the end of each sniffing session.
        Args:
            protocol (str): The protocol name to increment the count for
                            e.g. 'TCP', 'DNS', 'TLS'.
        """
        count = self._protocol_count.get(protocol, 0)
        count += 1
        self._protocol_count[protocol] = count

    def _parse_TLS(self, pkt: Packet, src_ip: Any, dst_ip: Any) -> tuple[dict,str]:
        """
        Parses a TLS packet and extracts protocol metadata for display and
        recording. Extracts source and destination ports from the underlying
        TCP layer, along with the TLS record type and version. Builds a
        structured data dictionary for JSON recording and optionally generates
        additional verbose output showing TLS-specific fields.
        Args:
            pkt (Packet): The captured packet object provided by Scapy.
            src_ip (Any): The source IP address already extracted from the
                        IP or IPv6 layer by the calling method.
            dst_ip (Any): The destination IP address already extracted from
                        the IP or IPv6 layer by the calling method.
        Returns:
            tuple[dict, str]: A tuple containing the structured data dictionary
                            for recording and a string of additional verbose
                            output. The additional data string is empty when
                            verbose mode is not enabled.    
        """
        protocol = 'TLS'
        src_port = pkt[TCP].sport if pkt.haslayer(TCP) else 'None'
        dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else 'None'
        tls_type = pkt[TLS].type
        tls_version = pkt[TLS].version

        data = {
            'protocol': protocol,
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'tls_type': tls_type,
            'tls_version': tls_version,
        }

        self._increase_count(protocol)

        additional_data = (
            f"\t<Additional_Data>\n"
            f"\tType: {tls_type}\n"
            f"\tVersion: {tls_version}"
        )

        return data, additional_data
    
    def _parse_HTTP(self, pkt: Packet, src_ip: Any, dst_ip: Any) -> tuple[dict,str]:
        """
        Parses an HTTP packet and extracts protocol metadata for display and
        recording. Handles three HTTP sub-types: HTTPRequest containing the
        method, path, and HTTP version; HTTPResponse containing the HTTP
        version, status code, and content length; and generic HTTP for packets
        that have the HTTP layer but cannot be classified as either request or
        response. All string fields are decoded from bytes using UTF-8 with
        replacement for invalid characters. Extracts source and destination
        ports from the underlying TCP layer.
        Args:
            pkt (Packet): The captured packet object provided by Scapy.
            src_ip (Any): The source IP address already extracted from the
                        IP or IPv6 layer by the calling method.
            dst_ip (Any): The destination IP address already extracted from
                        the IP or IPv6 layer by the calling method.
        Returns:
            tuple[dict, str]: A tuple containing the structured data dictionary
                            for recording and a string of additional verbose
                            output. The additional data string contains
                            protocol-specific fields for all HTTP sub-types
                            regardless of verbose mode since HTTP fields are
                            always useful to display.        
        """
        src_port = pkt[TCP].sport if pkt.haslayer(TCP) else 'None'
        dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else 'None'

        if pkt.haslayer(HTTPRequest):
            protocol = 'HTTP Request'
            method = pkt[HTTPRequest].Method.decode(
                'utf-8', errors='replace'
                ) if pkt[HTTPRequest].Method else 'N/A'
            path = pkt[HTTPRequest].Path.decode(
                'utf-8', errors='replace'
                ) if pkt[HTTPRequest].Path else 'N/A'
            http_version = pkt[HTTPRequest].Http_Version.decode(
                'utf-8', errors='replace'
                ) if pkt[HTTPRequest].Http_Version else 'N/A'

            data = {
                'protocol': protocol,
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'method': method,
                'path': path,
                'http_version': http_version,
            }

            self._increase_count(protocol)

            additional_data = (
                f"\t<Additional_Data>\n"
                f"\tMethod: {method}\n" 
                f"\tPath: {path}\n"
                f"\tVersion: {http_version}"
            )
        elif pkt.haslayer(HTTPResponse):
            protocol = 'HTTP Response'
            http_version = pkt[HTTPResponse].Http_Version.decode(
                'utf-8', errors='replace'
                ) if pkt[HTTPResponse].Http_Version else 'N/A'
            status_code = pkt[HTTPResponse].Status_Code.decode(
                'utf-8', errors='replace'
                ) if pkt[HTTPResponse].Status_Code else 'N/A'
            content_length = pkt[HTTPResponse].Content_Length.decode(
                'utf-8', errors='replace'
                ) if pkt[HTTPResponse].Content_Length else 'N/A'

            data = {
                'protocol': protocol,
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'http_version': http_version,
                'status_code': status_code,
                'content_length': content_length,
            }

            self._increase_count(protocol)

            additional_data = (
                f"\t<Additional_Data>\n"
                f"\tVersion: {http_version}\n"
                f"\tStatus Code: {status_code}\n"
                f"\tContent Length: {content_length}"
            )
        else:
            protocol = 'HTTP'

            data = {
                'protocol': protocol,
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
            }

            self._increase_count(protocol)

            additional_data = ""

        return data, additional_data
    
    def _parse_DNS(self, pkt: Packet, src_ip: Any, dst_ip: Any) -> tuple[dict,str]:
        """
        Parses a DNS packet and extracts protocol metadata for display and
        recording. Determines whether the packet is a query or response using
        the qr flag and extracts the domain name from the question record if
        present, falling back to the answer record name for responses that
        omit the question section. Extracts source and destination ports from
        the underlying UDP layer.
        Args:
            pkt (Packet): The captured packet object provided by Scapy.
            src_ip (Any): The source IP address already extracted from the
                        IP or IPv6 layer by the calling method.
            dst_ip (Any): The destination IP address already extracted from
                        the IP or IPv6 layer by the calling method.
        Returns:
            tuple[dict, str]: A tuple containing the structured data dictionary
                            for recording and a string of additional verbose
                            output containing the query or response indicator
                            and the domain name.
        """
        protocol = 'DNS'
        src_port = pkt[UDP].sport if pkt.haslayer(UDP) else 'None'
        dst_port = pkt[UDP].dport if pkt.haslayer(UDP) else 'None'
        query_response = 'Query' if pkt[DNS].qr == 0 else 'Response'
        domain = pkt[DNS].qd.qname.decode() if pkt[DNS].qd else (
            pkt[DNS].an.rrname.decode() if pkt[DNS].an else 'N/A'
        )
        resolve_addr = str(pkt[DNS].an.rdata) if pkt[DNS].an else 'N/A'

        data = {
            'protocol': protocol,
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'query_response': query_response,
            'domain': domain,
            'resolve_addr': resolve_addr,
        }

        self._increase_count(protocol)

        additional_data = (
            f"\t<Additional_Data>\n"
            f"\tQR: {query_response}\n"
            f"\tDomain: {domain}\n"
            f"\tAddress: {resolve_addr}"
        )

        return data, additional_data
    
    def _parse_DHCP(self, pkt: Packet, src_ip: Any, dst_ip: Any) -> tuple[dict,str]:
        """
        Parses a DHCP packet and extracts protocol metadata for display and
        recording. Extracts source and destination ports from the underlying
        UDP layer and collects all DHCP options from the packet excluding the
        end terminator. DHCP options are formatted as a comma-separated string
        containing each option tuple e.g. ('message-type', 1), ('server_id',
        '192.168.1.1'). Returns N/A if no options are present.
        Args:
            pkt (Packet): The captured packet object provided by Scapy.
            src_ip (Any): The source IP address already extracted from the
                        IP or IPv6 layer by the calling method.
            dst_ip (Any): The destination IP address already extracted from
                        the IP or IPv6 layer by the calling method.
        Returns:
            tuple[dict, str]: A tuple containing the structured data dictionary
                            for recording and a string of additional verbose
                            output containing all DHCP options present in
                            the packet.
        """
        protocol = 'DHCP'
        src_port = pkt[UDP].sport if pkt.haslayer(UDP) else 'None'
        dst_port = pkt[UDP].dport if pkt.haslayer(UDP) else 'None'
        options = pkt[DHCP].options
        if options:
            options_str = ', '.join(
                str(opt) for opt in options if opt != 'end')
        else:
            options_str = 'N/A'

        data = {
            'protocol': protocol,
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'options': options_str,
        }

        self._increase_count(protocol)

        additional_data = (
            f"\t<Additional_Data>\n"
            f"\tOptions: {options_str}"
        )

        return data, additional_data
    
    def _parse_TCP(self, pkt: Packet, src_ip: Any, dst_ip: Any) -> tuple[dict,str]:
        """
        Parses a TCP packet and extracts protocol metadata for display and
        recording. Extracts source and destination ports, TCP control flags,
        sequence and acknowledgment numbers, receive window size, and checksum.
        TCP flags are converted from Scapy's FlagValue type to a string
        representation e.g. 'S' for SYN, 'SA' for SYN-ACK, 'FA' for FIN-ACK.
        Args:
            pkt (Packet): The captured packet object provided by Scapy.
            src_ip (Any): The source IP address already extracted from the
                        IP or IPv6 layer by the calling method.
            dst_ip (Any): The destination IP address already extracted from
                        the IP or IPv6 layer by the calling method.
        Returns:
            tuple[dict, str]: A tuple containing the structured data dictionary
                            for recording and a string of additional verbose
                            output containing TCP flags, sequence number,
                            acknowledgment number, window size, and checksum
                            formatted in aligned columns for readability.
        """
        protocol = 'TCP'
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        flag = str(pkt[TCP].flags)
        seq = pkt[TCP].seq
        ack = pkt[TCP].ack
        window = pkt[TCP].window
        chksum = pkt[TCP].chksum

        data = {
            'protocol': protocol,
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'flag': flag,
            'seq': seq,
            'ack': ack,
            'window': window,
            'chksum': chksum,
        }

        self._increase_count(protocol)

        additional_data = (
            f"\t<Additional_Data>\n"
            f"\tFlags: {flag:<12} SEQ: {seq:<24}\n"
            f"\tACK: {ack:<12}   Window: {window:<24}\n"
            f"\tCHKSUM: {chksum}"
        )

        return data, additional_data
    
    def _parse_UDP(self, pkt: Packet, src_ip: Any, dst_ip: Any) -> tuple[dict,str]:
        """
        
        """
        protocol = 'UDP'
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        length = pkt[UDP].len
        chksum = pkt[UDP].chksum

        data = {
            'protocol': protocol,
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'length': length,
            'chksum': chksum,
        }

        self._increase_count(protocol)

        additional_data = (
            f"\t<Additional_Data>\n"
            f"\tLEN: {length}\n"
            f"\tCHKSUM: {chksum}"
        )

        return data, additional_data