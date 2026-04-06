"""
Author: Chris Martinez
Date: 04 April 2026
Version: 1.0.0
Name: engine.py
Description: This module defines the Engine class, which serves as the
core component of the Netlink framework. The Engine class is responsible
for managing the execution of modules, handling command-line arguments, 
and orchestrating the overall flow of the framework. It provides methods
for initializing the framework, loading modules, and executing the main
logic of the framework based on user input and module requirements.
"""

import importlib
import pkgutil
import inspect
import netlink.modules as netlink_modules

from netlink.core.base_module import BaseModule
from netlink.core.interface import InterfaceManager
from netlink.core.output import OutputManager

class Engine:
    """
    The Engine class serves as the core component of the Netlink 
    framework. It is responsible for managing the execution of modules, 
    handling command-line arguments, and orchestrating the overall flow 
    of the framework.
    """

    ####################################################################
    # Constructor
    ####################################################################
    def __init__(self):
        """
        Initializes the Engine instance. This includes setting up the
        output manager and preparing the list of available modules.
        """
        self.output_manager = OutputManager()
        self.modules = dict()
        self._discover_modules()

    ####################################################################
    # Methods
    ####################################################################
    def _discover_modules(self) -> None:
        """
        Discovers and loads all modules available in the netlink.modules
        package. This method uses the pkgutil module to find all 
        submodules in the netlink.modules package, imports them, and 
        checks for classes that inherit from BaseModule. Valid modules 
        are added to the self.modules dictionary with their NAME 
        attribute as the key.
        """
        path = netlink_modules.__path__
        mods_iter = pkgutil.iter_modules(path)

        # Iterate through all discovered modules and import them
        for mod_info in mods_iter:
            # Import the module and inspect its classes 
            mod_path = f"netlink.modules.{mod_info.name}"
            mod = importlib.import_module(mod_path)
            mod_classes = inspect.getmembers(mod, inspect.isclass)

            # Check each class in the module to see if it is a subclass
            # of BaseModule (but not BaseModule itself) and add it to 
            # the modules dictionary
            for _, cls in mod_classes:
                if issubclass(cls, BaseModule) and cls is not BaseModule:
                    if cls.NAME in self.modules:
                        # If a module with the same name already exists,
                        # log an error and skip adding this module to
                        # prevent overwriting the existing module
                        err_msg = (
                            f"Error: Duplicate module name '{cls.NAME}'"
                            f" found in {mod_path}. All module names"
                            " must be unique."
                        )
                        self.output_manager.error(err_msg)
                    else:
                        self.modules[cls.NAME] = cls 

    def run(self, mod_name: str, args) -> None:
        """
        Executes the specified module with the given arguments. This 
        method checks if the module exists, validates any requirements 
        (such as root privileges), and then runs the module's main 
        logic.
        Args:
            mod_name (str): The name of the module to execute.
            args: The command-line arguments to pass to the module.
        """
        # Check if the specified module exists
        if mod_name not in self.modules:
            err_msg = f"Error: Module '{mod_name}' not found."
            self.output_manager.error(err_msg)
            return
        
        # Check if the module requires root privileges and if so, ensure
        # the user has them
        mod_cls = self.modules[mod_name]
        if mod_cls.REQUIRES_ROOT:
            InterfaceManager.require_root(mod_cls.NAME)
        
        # Resolve the network interface to use for the module
        iface = InterfaceManager.resolve(getattr(args, 'iface', None))

        # Instantiate the module and run it with the provided arguments
        mod_instance = mod_cls(iface, self.output_manager)

        # Validate the module's arguments before running. If validation
        # fails, log an error and do not run the module.
        if not mod_instance.validate_args(args):
            err_msg = f"Error: Invalid args for module '{mod_cls.NAME}'"
            self.output_manager.error(err_msg)
            return

        # Log the module being run and execute the module's main logic
        mod_header_msg = f"Running module: {mod_cls.NAME}"
        self.output_manager.header(mod_header_msg)
        mod_instance.run(args)
