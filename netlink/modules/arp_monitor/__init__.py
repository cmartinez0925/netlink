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
import ipaddress
import macaddress
import sys

from datetime import datetime, UTC
from functools import partial
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
        self._whitelist: dict[str, str] = dict()

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

        parser.add_argument(
            '--whitelist',
            type=str,
            action='store',
            dest='whitelist',
            default=None,
            help=(
                "Comma-separated list of trusted IP=MAC pairs to ignore during "
                "monitoring. Format: '192.168.1.254=2c:c1:f4:f2:c6:50' or "
                "multiple entries: '192.168.1.254=2c:c1:f4:f2:c6:50,"
                "192.168.1.1=aa:bb:cc:dd:ee:ff'. Whitelisted pairs will never "
                "trigger alerts."
            )
        )

        parser.add_argument(
            '--alert-only',
            action='store_true',
            dest='alert_only',
            default=False,
            help="Only shows messages for suspect ARP spoofs detected"
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
        if args.whitelist:
            self._append_whitelist(args.whitelist)

        prn = partial(self._process_packet, args=args)

        sniff_kwargs = {
            'iface': self.iface,
            'count': args.count,
            'timeout': args.timeout,
            'prn': prn,
            'filter': "arp",
        }

        sniff(**sniff_kwargs)

        if len(self._arp_table) == 1:
            msg = f"There is 1 unique IP Address"
        else:
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

    def _process_packet(self, pkt: Packet, args: argparse.Namespace) -> None:
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
        if pkt.haslayer(ARP):
            if pkt[ARP].op == self.ARP_REPLY:
                ip = pkt[ARP].psrc
                new_mac = pkt[ARP].hwsrc

                if ip in self._whitelist:
                    if self._whitelist[ip] == new_mac:
                        # IP/MAC pair in whitelist, no need to process further
                        return
                
                if ip not in self._arp_table:
                    self._append_arp_table(ip, new_mac, args)
                else:
                    prev_mac = self._arp_table[ip]
                    if prev_mac == new_mac:
                        return # Nothing has changed, just return
                    else:
                        self._update_arp_table(ip, prev_mac, new_mac)

    def _append_arp_table(self, 
                          ip: str, 
                          new_mac: str, 
                          args: argparse.Namespace) -> None:
        """
        Adds a new IP-to-MAC mapping to the internal ARP table and records
        the event. Generates a timestamp for the event and logs an info
        message unless --alert-only is enabled in which case new mappings
        are silently recorded without terminal output. Always records the
        event to the output for JSON logging regardless of alert_only.
        Args:
            ip (str): The IP address of the newly discovered host.
            new_mac (str): The MAC address associated with the IP address.
            args (argparse.Namespace): The parsed command-line arguments used
                                    to check the alert_only flag. 
        """
        self._arp_table[ip] = new_mac
        timestamp = datetime.now(UTC).isoformat(sep=' ')
        new_event_mapped = {
            'event': 'new',
            'timestamp': timestamp,
            'ip': ip,
            'mac': new_mac,
        }

        if not args.alert_only:
            msg = f"[{timestamp}] {ip} -> {new_mac} added to ARP Monitor table"
            self.output.info(msg)

        self.output.record(new_event_mapped)

    def _update_arp_table(self, ip: str, prev_mac: str, new_mac: str) -> None:
        """
        Updates an existing IP-to-MAC mapping in the ARP table when a
        different MAC address claims an already known IP address. Generates
        a timestamp and always emits a warning regardless of --alert-only
        since a MAC address change on a known IP is a potential spoofing
        attack. Records the spoof event with the previous and new MAC
        addresses for forensic logging.
        Args:
            ip (str): The IP address whose MAC mapping has changed.
            prev_mac (str): The previously recorded MAC address for this IP.
            new_mac (str): The new MAC address claiming ownership of this IP.
        """
        timestamp = datetime.now(UTC).isoformat(sep=' ')

        msg = (
            f"[{timestamp}] Possible MAC Spoofing detected:\n"
            f"\tIP Address: {ip}\n"
            f"\tPrevious MAC Address: {prev_mac}\n"
            f"\tNew MAC Address: {new_mac}\n"
        )

        spoof_event_mapped = {
            'event': 'spoof_detected',
            'timestamp': timestamp,
            'ip': ip,
            'prev_mac': prev_mac,
            'new_mac': new_mac,
        }

        self._arp_table[ip] = new_mac
        self.output.warn(msg)
        self.output.record(spoof_event_mapped)                  

    def _append_whitelist(self, whitelist: str) -> None:
        """
        Parses a comma-separated whitelist string of IP=MAC pairs and
        populates the internal whitelist dictionary. Each entry is validated
        using the ipaddress module for IP addresses and the macaddress module
        for MAC addresses. Exits with an error if any entry is malformed or
        contains an invalid IP or MAC address. Whitelisted IP/MAC pairs are
        excluded from ARP table monitoring and will never trigger alerts.
        Args:
            whitelist (str): A comma-separated string of IP=MAC pairs e.g.
                            '192.168.1.254=2c:c1:f4:f2:c6:50,192.168.1.1=
                            aa:bb:cc:dd:ee:ff'. 
        """
        ip_mac_pairs = whitelist.split(',')

        for pair in ip_mac_pairs:
            ip_and_mac = pair.split('=')

            if len(ip_and_mac) != 2:
                self.output.error(
                    f"Invalid whitelist entry '{pair}'. "
                    f"Format must be IP=MAC "
                    f"e.g. 192.168.1.254=2c:c1:f4:f2:c6:50"
                )
                sys.exit(1)
                
            ip = ip_and_mac[0]
            mac = ip_and_mac[1]
            
            try:
                ipaddress.ip_address(ip)
            except ValueError as e:
                self.output.error(f"Invalid ip address: {e}")
                sys.exit(1)

            try:
                macaddress.MAC(mac)
            except ValueError as e:
                self.output.error(f"Invalid MAC address: {e}")
                sys.exit(1)
        
            self._whitelist[ip] = mac
