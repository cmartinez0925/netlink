"""
Author: Chris Martinez
Date: 30 March 2026
Version: 1.0.0
Name: base_module.py
Description: This module serves as the base class for all modules in the 
Netlink framework.  It provides common functionality and structure that 
all modules will inherit, ensuring consistency and ease of development 
across the framework.
"""

import argparse

from abc import ABC, abstractmethod
from netlink.core.output import OutputManager

class BaseModule(ABC):
    """
    Base class for all modules in the Netlink framework. This class
    provides common functionality and structure that all modules will
    inherit, ensuring consistency and ease of development across the
    framework.
    """

    ####################################################################
    # Class Level Attributes
    ####################################################################
    NAME: str = ""
    DESCRIPTION: str = ""
    REQUIRES_ROOT: bool = True

    ####################################################################
    # Constructor
    ####################################################################
    def __init__(self, iface: str, output: OutputManager):
        """
        Initializes the BaseModule with the given interface and output
        handler.
        Args:
            iface (str): The network interface to use for the module.
            output (OutputManager): An instance of the Output class for 
                            handling output and logging.
        """
        self.iface = iface
        self.output = output

    ####################################################################
    # Abstract Methods
    ####################################################################
    @abstractmethod
    def add_args(self, parser: argparse.ArgumentParser) -> None:
        """
        Abstract method to add module-specific arguments to the argument
        parser. Each module must implement this method to define its own
        command-line arguments.
        Args:
            parser (argparse.ArgumentParser): The argument parser to 
                                              which module-specific args
                                              will be added.
        """
        pass

    @abstractmethod
    def run(self, args: argparse.Namespace) -> None:
        """
        Abstract method to execute the module's main functionality. Each
        module must implement this method to define its own behavior 
        when executed.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                       specific to the module.
        """
        pass

    ####################################################################
    # Regular Methods (Non-abstract)
    ####################################################################
    def validate_args(self, args: argparse.Namespace) -> bool:
        """
        Validates the provided arguments for the module. This method can
        be overridden by modules to implement custom validation logic.
        By default, it returns True, indicating that the arguments are
        valid.
        Args:
            args (argparse.Namespace): The parsed command-line arguments
                                       specific to the module.
        Returns:
            bool: True if the arguments are valid, False otherwise.
        """
        return True
