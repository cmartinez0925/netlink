"""
Author: Chris Martinez
Date: 13 June 2026
Version: 1.0.0
Name: __init__.py (banner_grab)
Description: This module establishes a TCP connection with a specified target 
and port, sends an optional probe to trigger a service response, and extracts 
the banner returned by the service. The banner typically contains the service
name and version which can be used to identify software and assess
potential vulnerabilities. Supports both IPv4 and IPv6 targets and
automatically determines whether a probe is needed based on a built in
service dictionary. Should only be used against systems you own or have
explicit written permission to test.
"""
import argparse
import ipaddress
import socket

from netlink.core.base_module import BaseModule
from netlink.core.output import OutputManager

class BannerGrab(BaseModule):
    """
    Performs TCP banner grabbing by establishing a full connection to a
    target host and port using Python's socket module and reading the
    service response. Maintains a built in dictionary of known services and
    their probe requirements. Automatically sends the appropriate probe for
    known services that require one such as HTTP and falls back to user
    provided probe data for unknown services. Supports both IPv4 and IPv6.
    """
    ############################################################################
    # Class Level Attributes
    ############################################################################
    NAME = "banner_grab"
    DESCRIPTION = "TCP Banner Grabber"
    REQUIRES_ROOT = False

    RECV_SIZE = 4096
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
        Initializes the BannerGrab module with the given interface and output
        handler.
        Args:
            iface (str): The network interface to use for the module.
            output (OutputManager): An instance of the Output class for
                            handling output and logging.
        """
        super().__init__(iface, output)
        self.target_is_ipv6 = False

    ############################################################################
    # Abstract Required Methods
    ############################################################################
    def add_args(self, parser: argparse.ArgumentParser) -> None:
        """
        Adds module-specific arguments to the argument parser. This method is
        called by the Engine when setting up the CLI for this module. Defines
        arguments for target IP, port, timeout, probe flag, and custom probe
        data.
        Args:
            parser (argparse.ArgumentParser): The argument parser to which
                                            module-specific args are added.
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
            type=float,
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

        parser.add_argument(
            '--data',
            action='store',
            dest='data',
            default=None,
            help="Data to send along with the probe"
        )

    def run(self, args: argparse.Namespace) -> None:
        """
        Executes the main functionality of the BannerGrab module. Creates a
        TCP socket, connects to the target, optionally sends a probe based on
        the known service dictionary or user provided data, reads the banner
        response, and displays and records the result. Handles connection
        failures, timeouts, and unexpected errors gracefully. Always closes
        the socket on exit.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                    specific to the BannerGrab module.
        """
        SERVER_ADDR = (args.target, args.port)
        HTTP_DATA = f"GET / HTTP/1.0\r\nHost: {args.target}\r\n\r\n"

        service = self.SERVICES.get(args.port)
        service_name = 'unknown'
        service_requires_probe = False

        if service:
            service_name = service.get('name', 'unknown')
            service_requires_probe = service.get('probe', False)

        if service_requires_probe:
            data = args.data if args.data else HTTP_DATA
        else:
            data = None

        if not service and args.probe: #service is unknown but still probe
            data = args.data if args.data else None

        if self.target_is_ipv6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            sock.settimeout(args.timeout)
            sock.connect(SERVER_ADDR)

            if data is not None:
                sock.sendall(data.encode())

            banner = sock.recv(self.RECV_SIZE).decode('utf-8', errors='replace')
            record = {
                'target': args.target,
                'port': args.port,
                'service': service_name,
                'banner': banner,
            }
            self.output.record(record)
            self.output.info("Banner Information Below:")
            self.output.info(f"{banner}")
        except KeyboardInterrupt:
            self.output.error("Keyboard interrupted")
        except socket.timeout:
            self.output.error("Connection timed out")
        except ConnectionRefusedError:
            self.output.error("Connection refused")
        except Exception as e:
            self.output.error(f"Error: {e}")
        finally:
            sock.close()
        
    ############################################################################
    # Methods
    ############################################################################

    def validate_args(self, args: argparse.Namespace) -> bool:
        """
        Validates the provided arguments for the BannerGrab module. Checks
        that target is a valid IPv4 or IPv6 address, that port is between 1
        and 65535, and that timeout if provided is not negative. Also sets
        the target_is_ipv6 flag based on the address type for use during
        socket creation.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                        specific to the BannerGrab module.
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
            ipaddress.IPv4Address(args.target)
            self.target_is_ipv6 = False
        except ipaddress.AddressValueError:
            self.target_is_ipv6 = True
        
        if args.port < 1 or args.port > 65535:
            msg = "Provide a port number between 1 - 65,535"
            self.output.error(msg)
            return False

        if args.timeout is not None and args.timeout < 0:
            msg = "Timeout cannot be a negative number"
            self.output.error(msg)
            return False
        
        return True
