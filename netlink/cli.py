"""
Author: Chris Martinez
Date: 06 April 2026
Version: 1.0.0
Name: cli.py
Description: This module defines the command-line interface for the 
Netlink framework. It uses the argparse library to parse command-line
arguments and options, allowing users to interact with the framework and
execute modules based on their specified requirements. The CLI provides
a user-friendly interface for running modules, specifying options, and
managing the overall execution of the framework from the command line.
"""

import argparse
import sys

from netlink.core.engine import Engine
from netlink.core.interface import InterfaceManager

def main():
    """
    The main function serves as the entry point for the Netlink 
    framework when executed from the command line. It initializes the
    Engine, sets up the argument parser, and handles the execution of
    modules based on user input.
    """
    # Initialize the Engine
    engine = Engine()

    ####################################################################
    # Terminal Arguments Setup (Global)
    #################################################################### 
    parser = argparse.ArgumentParser(
        description="Netlink: A modular network reconnaissance framework"
    )

    parser.add_argument(
        '-i', 
        '--iface', 
        type=str, 
        action='store',
        dest='iface',
        default=None,
        help="Network interface to use"
    )

    parser.add_argument(
        '-j',
        '--json',
        action='store_true',
        dest='json_mode',
        default=False,
        help="Output results in JSON format"
    )

    parser.add_argument(
        '-o',
        '--outfile',
        type=str,
        action='store',
        dest='outfile',
        default=None,
        help="Write output to a file instead of the console"
    )

    parser.add_argument(
        '--list-ifaces',
        action='store_true',
        dest='list_ifaces',
        help="List available network interfaces"
    )

    ####################################################################
    # Terminal Arguments Setup (Subparser)
    ####################################################################
    subparsers = parser.add_subparsers(
        dest='module',
        metavar='MODULE',
        help='Module to execute'
    )

    # Add a subparser for each available module in the Engine
    for mod_name, mod_cls in engine.modules.items():
        mod_parser = subparsers.add_parser(
            mod_name,
            help=mod_cls.DESCRIPTION
        )

        # Allow each module to add its own specific arguments
        mod_instance = mod_cls.__new__(mod_cls) #type: ignore
        mod_instance.add_args(mod_parser)

    # Parse the command-line arguments
    args = parser.parse_args()

    ####################################################################
    # Handle Global Arguments
    ####################################################################
    # If the user specified the --list-ifaces option, list available
    # network interfaces and exit
    if args.list_ifaces:
        iface_list = InterfaceManager.list_interfaces()
        engine.output_manager.header("Available Network Interfaces")
        title_line = (
            f"{"Name":<16} {"IPv4":<18} "
            f"{"IPv6":<42} MAC"   
        )
        print(title_line)
        print('-' * 96)
            
        for iface in iface_list:
            msg = (
                f"{iface['name']:<16} {iface['ipv4']:<18} "
                f"{iface['ipv6']:<42} {iface['mac']}"     
            )
            print(msg)
        print()
        sys.exit(0)

    # Handle no module specified case
    if args.module is None:
        parser.print_help()
        sys.exit(0)

    # Apply global output settings (JSON mode and output file) to the
    # OutputManager instance
    engine.output_manager.json_mode = args.json_mode

    # Handle output file argument. If an output file is specified,
    # open the file and set it as the output destination for the
    # OutputManager instance. The file will be closed when the
    # OutputManager instance is destroyed.
    if args.outfile is not None:
        engine.output_manager.outfile = open(args.outfile, 'w')
    
    ####################################################################
    # Run the specified module with the provided arguments
    ####################################################################
    engine.run(args.module, args)

########################################################################
# Run Module
########################################################################
if __name__ == "__main__":
    main()