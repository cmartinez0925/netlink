"""
Author: Chris Martinez
Date: 15 April 2026
Version: 1.0.0
Name: __init__.py (scanner)
Description: This module is responsible for scanning hosts on the network to 
identify open ports and services. It uses TCP SYN scanning toprobe specified 
ports on target hosts and determines if they are open,closed, or filtered. The 
module can be used to quickly assess the attack surface of a host by identifying
which services are running and potentially vulnerable.
"""
import argparse
import ipaddress
import logging
import random
import signal

from scapy.all import sr1, send
from scapy.layers.inet import IP, TCP
from types import FrameType

from netlink.core.base_module import BaseModule
from netlink.core.output import OutputManager



class Scanner(BaseModule):
    """
    The Scanner class is responsible for scanning hosts on the network
    to identify open ports and services.
    """
    ############################################################################
    # Class Level Attributes
    ############################################################################
    NAME = "scanner"
    DESCRIPTION = "SYN port scanner"
    REQUIRES_ROOT = True   

    SERVICES = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        69: "TFTP",
        80: "HTTP",
        88: "KERBEROS",
        110: "POP3",
        111: "RPCBIND",
        119: "NNTP",
        123: "NTP",
        135: "MSRPC",
        137: "NETBIOS-NS",
        138: "NETBIOS-DGM",
        139: "NETBIOS-SSN",
        143: "IMAP",
        161: "SNMP",
        162: "SNMP-TRAP",
        179: "BGP",
        194: "IRC",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB",
        464: "KERBEROS-PW",
        465: "SMTPS",
        500: "ISAKMP",
        512: "REXEC",
        513: "RLOGIN",
        514: "SYSLOG",
        515: "LPD",
        520: "RIP",
        587: "SMTP-SUBMISSION",
        631: "IPP",
        636: "LDAPS",
        666: "DOOM",
        873: "RSYNC",
        902: "VMWARE",
        989: "FTPS-DATA",
        990: "FTPS",
        993: "IMAPS",
        995: "POP3S",
        1080: "SOCKS",
        1194: "OPENVPN",
        1433: "MSSQL",
        1434: "MSSQL-MONITOR",
        1521: "ORACLE",
        1723: "PPTP",
        1883: "MQTT",
        2049: "NFS",
        2121: "FTP-ALT",
        2181: "ZOOKEEPER",
        2375: "DOCKER",
        2376: "DOCKER-TLS",
        3000: "DEV-SERVER",
        3306: "MYSQL",
        3389: "RDP",
        3690: "SVN",
        4443: "HTTPS-ALT",
        4444: "METASPLOIT",
        4505: "SALT-MASTER",
        4506: "SALT-MASTER",
        5000: "FLASK",
        5432: "POSTGRESQL",
        5900: "VNC",
        5985: "WINRM-HTTP",
        5986: "WINRM-HTTPS",
        6379: "REDIS",
        6443: "KUBERNETES",
        6666: "IRC-ALT",
        7001: "WEBLOGIC",
        8000: "HTTP-ALT",
        8008: "HTTP-ALT",
        8080: "HTTP-PROXY",
        8443: "HTTPS-ALT",
        8888: "JUPYTER",
        9000: "SONARQUBE",
        9090: "PROMETHEUS",
        9200: "ELASTICSEARCH",
        9300: "ELASTICSEARCH",
        9418: "GIT",
        10000: "WEBMIN",
        11211: "MEMCACHED",
        27017: "MONGODB",
        27018: "MONGODB",
        50000: "DB2",
        50070: "HADOOP",
        61616: "ACTIVEMQ",
    }

    ############################################################################
    # Constructor
    ############################################################################
    def __init__(self, iface: str, output: OutputManager):
        super().__init__(iface, output)
        self.keyboard_interrupted = False

    ############################################################################
    # Methods
    ############################################################################
    def add_args(self, parser):
        """
        Adds module-specific arguments to the argument parser. This method is
        called by the Engine when setting up the CLI for this module.
        Args:
            parser (argparse.ArgumentParser): The argument parser to which
                                              module-specific args are added.
        """
        parser.description = (
            "Perform a TCP SYN scan on the specified target to identify open "
            "ports. Sends SYN packets to each port and analyzes responses — "
            "SYN-ACK means open, RST means closed, no response means filtered. "
            "Requires root."
        )
        
        parser.add_argument(
            '-t',
            '--target',
            type=str,
            action='store',
            dest='target',
            required=True,
            help=(
                "Target IP range to scan (e.g., 192.168.1.1/24)"
            )
        )

        parser.add_argument(
            '--timeout',
            type=float,
            action='store',
            dest='timeout',
            default=2,
            help="Timeout in seconds to wait for responses (default: 2)"
        )    

        parser.add_argument(
            '-p',
            '--ports',
            type=str,
            action='store',
            dest='ports',
            default='1-1024',
            help="Ports to scan (e.g., 1-1024 or 80, 443) (default: 1-1024)"
        )

        parser.add_argument(
            '--verbose',
            action='store_true',
            dest='verbose',
            default=False,
            help="Dipslays if port is filtered or closed",
        )

    def run(self, args: argparse.Namespace) -> None:
        """
        Executes the main functionality of the Scanner module. This method is
        called by the Engine after validating the arguments. It performs a SYN
        scan on the specified target and ports, and outputs the results.
        Args:
            args (argparse.Namespace): The parsed command-line arguments 
                                       specific to the Scanner module.
        """
        SYN_ACK = 0x12
        RST_ACK = 0x14
        LOWER_PORT = 1024
        UPPER_PORT = 65535

        # So MAC Broadcast warning don't appear, excessive on linux
        # Will need to readdress this later
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)     

        network = ipaddress.ip_network(args.target, strict=False).hosts()
        ports = self.parse_ports(args.ports)
        host_os = 'Unknown'
        ports_open = 0
        
        self.keyboard_interrupted = False
        signal.signal(signal.SIGINT, self._sigint_handler)
        
        try:
            for host in network:
                if self.keyboard_interrupted:
                    break

                host = str(host) #type: ignore
                ports_open = 0

                for port in ports:
                    if self.keyboard_interrupted:
                        break

                    my_port = random.randint(LOWER_PORT, UPPER_PORT)
                    pkt = IP(dst=host)/TCP(sport=my_port, dport=port, flags='S')
                    response = sr1(pkt, timeout=args.timeout, verbose=0)
                    service = self.SERVICES.get(port, 'Unknown')

                    if response is None:
                        if args.verbose:
                            data = {
                                'host': host,
                                'port': port,
                                'service': service,
                                'status': 'filtered',
                                'host_os': host_os,
                            }
                            msg = f"{host}:{port} ({service}) is filtered"
                            self.output.info(msg)
                            self.output.record(data)
                        continue

                    if response.haslayer(IP):
                        ttl = response[IP].ttl
                        host_os = self._guess_os(ttl)
                        
                    if response.haslayer(TCP):
                        if response[TCP].flags == SYN_ACK:
                            # PORT IS OPEN
                            data = {
                                'host': host,
                                'port': port,
                                'service': service,
                                'status': 'open',
                                'host_os': host_os,
                            }
                            msg = (
                                f"{host}:{port} ({service}) is open "
                                f"Host OS: [{host_os}]"
                            )
                            self.output.success(msg)
                            self.output.record(data)
                            ports_open += 1

                            # Properly close down connection
                            pkt = IP(dst=host)/TCP(
                                sport=my_port, dport=port, flags='R')
                            send(pkt, verbose=0)
                        elif response[TCP].flags == RST_ACK:
                            # PORT IS CLOSED
                            if args.verbose:
                                data = {
                                    'host': host,
                                    'port': port,
                                    'service': service,
                                    'status': 'closed',
                                    'host_os': host_os,
                                }
                                msg = (
                                    f"{host}:{port} ({service}) is closed "
                                    f"Host OS: [{host_os}]"
                                )
                                self.output.info(msg)
                                self.output.record(data)
                            continue
                
                if not self.keyboard_interrupted:
                    self.output.info(f"{host} has {ports_open} ports open\n")       
        finally:
            if self.keyboard_interrupted:
                self.output.warn("KeyboardInterrupt: Scan ended by user")
                self.output.info(f"{host} has {ports_open} ports open\n")  
            signal.signal(signal.SIGINT, signal.SIG_DFL)


    @staticmethod
    def parse_ports(ports_str: str) -> list[int]:
        """
        Parses a string of ports and returns a list of integers.
        The input string can contain individual ports separated by commas, 
        and port ranges specified with a hyphen.
        Args:
            ports_str (str): A string representing ports to scan (e.g., "80,443,
                             1000-2000").
        Returns:
            list[int]: A list of port numbers to scan.
        """
        ports: list[int] = list()

        ports_str_list = ports_str.split(',')

        for port in ports_str_list:
            if '-' in port:
                temp_list = port.split('-')
                start = int(temp_list[0])
                end = int(temp_list[1]) + 1
                ports.extend(range(start, end))
            else:
                ports.append(int(port))

        return ports

    def validate_args(self, args: argparse.Namespace) -> bool:
        """
        Validates the module-specific arguments provided by the user. This 
        method is called by the Engine before running the module. It checks if
        the target argument is a valid IP address or CIDR range and if the
        timeout is a non-negative number.
        Args:
            args (argparse.Namespace): The parsed command-line arguments 
                                        specific to the module.
        Returns:
            bool: True if the arguments are valid, False otherwise.
        """
        if not args.target:
            self.output.warn("Please provide a target")
            return False

        if not args.ports:
            self.output.warn("Please provide a port(s) to scan")
            return False

        return True
    
    def _guess_os(self, ttl: int) -> str:
        """
        Attempts to identify the operating system of a host based on the
        Time To Live (TTL) value from an IP response packet. Different
        operating systems use different default TTL values when sending
        packets. This is a heuristic guess and not guaranteed to be accurate
        as TTL values decrease with each network hop and can be modified.
        Args:
            ttl (int): The TTL value extracted from the IP layer of a
                    response packet.
        Returns:
            str: A string representing the likely operating system based
                on the TTL value. Possible values are 'Linux/Unix/Mac',
                'Windows', 'Network Device', or 'Unknown'.
        """
        LINUX_UNIX_MAC = 64
        WINDOWS = 128
        NETWORK_DEVICE = 255

        if ttl == LINUX_UNIX_MAC:
            host_os = 'Linux/Unix/Mac'
        elif ttl == WINDOWS:
            host_os = 'Windows'
        elif ttl == NETWORK_DEVICE:
            host_os = 'Network Device' 
        else:
            host_os = 'Unknown'
        return host_os
    
    def _sigint_handler(self, sig: int, frame: FrameType|None) -> None:
        """
        Handles the SIGINT signal (Ctrl+C) by setting the interrupted flag
        to True. This allows the scanner to exit gracefully after the current
        packet send/receive cycle completes rather than terminating abruptly
        mid-scan.
        Args:
            sig (int): The signal number received. Will be signal.SIGINT (2)
                    when triggered by Ctrl+C.
            frame (FrameType | None): The current stack frame at the time the
                                    signal was received. Not used but required
                                    by the signal handler interface.
        """
        self.keyboard_interrupted = True
