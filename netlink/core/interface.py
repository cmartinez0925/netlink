"""
Author: Chris Martinez
Date: 1 April 2026
Version: 1.0.0
Name: interface.py
Description: This module defines the Interface class, which serves as a
base class for all network interface-related modules in the Netlink
framework. The Interface class provides common functionality and 
structure for modules that interact with network interfaces, ensuring
consistency and ease of development across the framework.
"""

import os
import sys

from scapy.all import conf
from scapy.all import get_if_list
from scapy.all import IFACES

class InterfaceManager:
    """
    The InterfaceManager class provides functionality for managing 
    network interfaces within the Netlink framework. It allows modules
    to retrieve and validate network interfaces, ensuring that they are 
    properly configured and available for use.
    """

    ############################################################################
    # Static Methods
    ############################################################################
    @staticmethod
    def require_root(module_name: str) -> None:
        """
        Checks if the current user has root privileges. If not, it 
        prints an error message and exits the program.
        Args:
            module_name (str): The name of the module that requires
                                 root privileges. This is used for error
                                 messaging.
        """
        ROOT = 0
        if os.geteuid() != ROOT:
            err_msg = (
                f"Error: {module_name} requires root privileges. "
                "Please run as root.\n"
            )
            sys.stderr.write(err_msg)
            sys.exit(1)

    @staticmethod
    def resolve(iface: str|None=None) -> str:
        """
        Resolves the given interface name to a valid network interface. 
        If no interface is provided, it returns the default interface.
        Args:
            iface (str|None): The name of the network interface to 
                              resolve.
                              If None, the default interface will be 
                              used.
        Returns:
            str: The resolved network interface name.
        """
        iface_list = get_if_list()

        if iface is not None:
            # Check iface is in the list of available interfaces
            if iface in iface_list:
                return iface
            # iface is provided but not found in the list of interfaces
            err_msg = (
                f"Error: Interface '{iface}' not found. Available "
                f"interfaces: {', '.join(iface_list)}\n" 
            )
            sys.stderr.write(err_msg)
            sys.stderr.flush()
            sys.exit(1)      
        else:
            # Try to get default iface from scapy conf
            if conf.iface:
                return str(conf.iface)

        # No default interface found and no iface provided by user
        # This is not in a else block because pylance will complain
        # a return value is not guaranteed    
        err_msg = (
            "Error: No default interface found. Please specify an "
            "interface using the --iface argument.\n"
        )
        sys.stderr.write(err_msg)
        sys.stderr.flush()
        sys.exit(1)

    @staticmethod
    def list_interfaces() -> list[dict]:
        """
        Retrieves a list of available network interfaces on the system.
        Returns:
            list[dict]: A list of dictionaries, each containing the name
                        of an available network interface.
        """
        interfaces = []

        for name, iface in IFACES.items():
            ipv4 = getattr(iface, 'ip', None) or "N/A"
            ipv6 = getattr(iface, 'ipv6', None) or "N/A"
            mac = getattr(iface, 'mac', None) or "N/A"

            data = {
                'name': name,
                'ipv4': ipv4,
                'ipv6': ipv6,
                'mac': mac,
            }

            interfaces.append(data)

        return interfaces
