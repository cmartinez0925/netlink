# ARGS
    # --target the victim's IP address
    #--domain the domain to spoof (e.g. google.com)
    #--spoof-ip the fake IP address to redirect the victim to
    #--ttl optional, how long the victim caches the fake record

#Data for the response pkt (DNSRR)
    #rrname = pkt[DNS].qd.qname
    #type = 1 (A Record aka IPv4)
    #ttl = This is either similar to the dns server you are pretending to be or as long as we need it to be to accomplish our goal
    #rdata = This is the actual IP Address

#sniff
    # BPF Filter = 'udp and port 53'


"""
Author: Chris Martinez
Date: 2 June 2026
Version: 1.0.0
Name: __init__.py (dns_spoof)
Description: 
"""

import argparse

from netlink.core.base_module import BaseModule
from netlink.core.output import OutputManager

class DNSSpoof(BaseModule):
    """

    """

    ####################################################################
    # Class Level Attributes
    ####################################################################
    NAME: str = "dns_spoof"
    DESCRIPTION: str = ""
    REQUIRES_ROOT: bool = True

    ####################################################################
    # Constructor
    ####################################################################
    def __init__(self, iface: str, output: OutputManager):
        """

        """
        super().__init__(iface, output)
       

    ####################################################################
    # Abstract Required Methods
    ####################################################################
    def add_args(self, parser: argparse.ArgumentParser) -> None:
        """

        """
        pass

    def run(self, args: argparse.Namespace) -> None:
        """

        """
        pass

    ####################################################################
    # Methods
    ####################################################################
    def validate_args(self, args: argparse.Namespace) -> bool:
        """

        """
        return True