"""
Author: Chris Martinez
Date: 24 April 2026
Version: 1.0.0
Name: __init__.py (arp_monitor)
Description: This module monitors ARP traffic on the network and detects
potential ARP spoofing attacks by tracking IP-to-MAC address mappings and
alerting on inconsistencies.
"""

import argparse

from scapy.all import sniff
from scapy.layers.l2 import ARP
from scapy.packet import Packet
from netlink.core.base_module import BaseModule
from netlink.core.output import OutputManager

class ARPMonitor(BaseModule):
    """
    The ARPMonitor class passively monitors ARP traffic on the network and 
    maintains a table of IP-to-MAC address mappings. It detects potential 
    ARP spoofing attacks by alerting when a previously seen IP address is 
    claimed by a different MAC address than what was originally recorded.
    """

    ############################################################################
    # Class Level Attributes
    ############################################################################
    NAME = "arp_monitor"
    DESCRIPTION = (
        "Monitor ARP traffic on the network and detect potential ARP spoofing "
        "attacks by tracking IP-to-MAC address mappings and alearting on "
        "inconsistencies."
    )
    REQUIRES_ROOT = True

    ARP_REQUEST = 1
    ARP_REPLY = 2

    ############################################################################
    # Constructor
    ############################################################################
    def __init__(self, iface: str, output: OutputManager):
        """
        Initializes the ARPMonitor with the given interface and output
        handler.
        Args:
            iface (str): The network interface to use for the module.
            output (OutputManager): An instance of the Output class for 
                            handling output and logging.
        """
        super().__init__(iface, output)
        self._arp_table: dict[str, str] = dict()

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
            "Monitor ARP traffic on the network and detect potential ARP "
            "spoofing attacks. Runs indefinitely by default (--count 0) until "
            "stopped with Ctrl+C or --timeout is reached."
        )
        
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
            '--timeout',
            type=int,
            action='store',
            dest='timeout',
            default=None,
            help="Stop sniffing after N seconds (Default=None)"
        )

    def run(self, args: argparse.Namespace) -> None:
        """
        Executes the main functionality of the ARPMonitor module. This method is
        called by the Engine when the user runs this module from the CLI.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                       specific to the sniffer module.
        Returns:
            bool: True if the module executed successfully, False otherwise.
        """
        sniff_kwargs = {
            'iface': self.iface,
            'count': args.count,
            'timeout': args.timeout,
            'prn': self._process_packet,
            'filter': "arp",
        }

        pkts = sniff(**sniff_kwargs)
        msg = f"There are {len(self._arp_table)} unique IP Addresses"
        self.output.info(msg)


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

    def _process_packet(self, pkt: Packet) -> None:
        """
        Processes each captured ARP packet and updates the internal ARP table.
        This method is called by Scapy for each ARP packet captured during 
        monitoring. It extracts the IP and MAC address from ARP reply packets
        and compares them against the known IP-to-MAC mappings stored in 
        self._arp_table. If a new IP-MAC mapping is discovered it is added to 
        the table. If an existing IP address is claimed by a different MAC 
        address, a potential ARP spoofing attack is flagged and logged.
        Args:
            pkt (Packet): The captured packet object provided by Scapy.
        """
        if ARP in pkt and pkt[ARP].op == self.ARP_REPLY:
            ip_addr = pkt[ARP].psrc
            new_mac = pkt[ARP].hwsrc

            if ip_addr not in self._arp_table:
                self._arp_table[ip_addr] = new_mac
                msg = f"{ip_addr}:{new_mac} added to ARP Monitor table"
                self.output.info(msg)
                new_event_mapped = {
                    'event': 'new',
                    'ip': ip_addr,
                    'mac': new_mac,
                }
                self.output.record(new_event_mapped)
            else:
                prev_mac = self._arp_table[ip_addr]
                if prev_mac == new_mac:
                    return # Nothing has changed, just return
                else:
                    msg = (
                        f"Possible MAC Spoofing detected:\n"
                        f"\tIP Address: {ip_addr}\n"
                        f"\tPrevious MAC Address: {prev_mac}\n"
                        f"\tNew MAC Address: {new_mac}\n"
                    )
                    self.output.warn(msg)
                    self._arp_table[ip_addr] = new_mac
                    spoof_event_mapped = {
                        'event': 'spoof_detected',
                        'ip': ip_addr,
                        'prev_mac': prev_mac,
                        'new_mac': new_mac,
                    }
                    self.output.record(spoof_event_mapped)
