"""
Author: Chris Martinez
Date: 13 June 2026
Version: 1.0.0
Name: __init__.py (banner_grab)
Description: This module is establishes a TCP handshake with a specified target
and port. Once the handshake is established it pull information from the banner
that is sent from the service and provides it to the user.
"""
import argparse
import ipaddress
import socket

from netlink.core.base_module import BaseModule
from netlink.core.output import OutputManager

class BannerGrab(BaseModule):
    """
    
    """
    ############################################################################
    # Class Level Attributes
    ############################################################################
    NAME = "banner_grab"
    DESCRIPTION = "TCP Banner Grabber"
    REQUIRES_ROOT = False

    SERVICES = {
        21:   {'name': 'FTP',        'probe': False},
        22:   {'name': 'SSH',        'probe': False},
        23:   {'name': 'TELNET',     'probe': False},
        25:   {'name': 'SMTP',       'probe': False},
        80:   {'name': 'HTTP',       'probe': True},
        110:  {'name': 'POP3',       'probe': False},
        143:  {'name': 'IMAP',       'probe': False},
        443:  {'name': 'HTTPS',      'probe': True},
        3306: {'name': 'MYSQL',      'probe': False},
        3389: {'name': 'RDP',        'probe': False},
        8000: {'name': 'HTTP-ALT',   'probe': True},
        8008: {'name': 'HTTP-ALT',   'probe': True},
        8080: {'name': 'HTTP-PROXY', 'probe': True},
        8443: {'name': 'HTTPS-ALT',  'probe': True},
    }

    ############################################################################
    # Constructor
    ############################################################################
    def __init__(self, iface: str, output: OutputManager):
        """
        
        """
        super().__init__(iface, output)

    ############################################################################
    # Abstract Required Methods
    ############################################################################
    def add_args(self, parser: argparse.ArgumentParser) -> None:
        """

        """
        parser.description = (
            "Establishes a TCP Handshake on a specified target IP and port to "
            "banner grab the services and parse information from the banner."
        )

        parser.add_argument(
            '-t',
            '--target',
            type=str,
            action='store',
            dest='target',
            required=True,
            help="Target IP to grab the banner"
        )

        parser.add_argument(
            '-p',
            '--port',
            type=int,
            action='store',
            dest='port',
            required=True,
            help="Port (Service) to grab the banner"
        )

        parser.add_argument(
            '--timeout',
            type=int,
            action='store',
            dest='timeout',
            default=None,
            help="Stop sending the packet after N seconds (Default=None)"    
        )


        parser.add_argument(
            '--probe',
            action='store_true',
            dest='probe',
            default=False,
            help="Send probe to get a response from service (default: False)"
        )

    def run(self, args: argparse.Namespace) -> None:
        """
        
        """
        pass

    ############################################################################
    # Methods
    ############################################################################

    def validate_args(self, args: argparse.Namespace) -> bool:
        """
        
        """
        try:
            ipaddress.ip_address(args.target)
        except ValueError:
            msg = "A valid IPv4/IPv6 address for the target required"
            self.output.error(msg)
            return False
        
        if args.port < 1 or args.port > 65535:
            msg = "Provide a port number between 1 - 65,535"
            self.output.error(msg)
            return False

        if args.timeout is not None and args.timeout < 0:
            msg = "Timeout cannot be a negative number"
            self.output.error(msg)
            return False
        
        return True
