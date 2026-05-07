"""
Author: Chris Martinez
Date: 30 March 2026
Version: 1.0.0
Name: output.py
Description: This module defines the Output class, which is responsible
for handling all output and logging functionality within the Netlink
framework. The Output class provides methods for logging messages at
various levels (info, warning, error) and for formatting output in a
consistent manner across the framework.
"""

import json
from rich.console import Console
from rich.panel import Panel

class OutputManager:
    """
    The OutputManager class is responsible for handling all output and
    logging functionality.
    """

    ############################################################################
    # Constructor
    ############################################################################
    def __init__(self, json_mode: bool=False, outfile: str|None=None):
        """
        Initializes OutputManager with the specified output settings.
        Args:
            json_mode (bool): If True, output will be formatted as JSON.
            outfile (str): If specified, output will be written to this 
                           file instead of the console.
        """
        self.json_mode = json_mode
        self.console = Console() 
        self._results: list = []

        if outfile is not None:
            self.outfile = open(outfile, 'w')
        else:
            self.outfile = None #type: ignore

    ############################################################################
    # Destructor
    ############################################################################
    def __del__(self):
        """
        Destructor for the OutputManager class. If an output file was
        specified, this method will close the file when the 
        OutputManager instance is destroyed.
        """
        if hasattr(self, 'outfile') and self.outfile is not None:
            try:
                self.outfile.close()
            except Exception:
                pass

    ############################################################################
    # Methods
    ############################################################################
    def header(self, msg: str) -> None:
        """
        Displays a header message in the console.
        Args:
            msg (str): The header message to display.
        """
        if self.json_mode:
            return
        panel = Panel(msg, expand=False)
        self.console.print(panel)

    def info(self, msg: str) -> None:
        """
        Logs an informational message.
        Args:
            msg (str): The informational message to log.
        """
        if self.json_mode:
            return
        self.console.print(f"[turquoise2][*][/turquoise2] {msg}", 
                           style="white")

    def success(self, msg: str) -> None:
        """
        Logs a success message.
        Args:
            msg (str): The success message to log.
        """
        if self.json_mode:
            return
        self.console.print(f"[green][+][/green] {msg}", style="white")
    
    def warn(self, msg: str) -> None:
        """
        Logs a warning message.
        Args:
            msg (str): The warning message to log.
        """
        if self.json_mode:
            return
        self.console.print(f"[yellow2][!][/yellow2] {msg}", 
                           style="white")

    def error(self, msg: str) -> None:
        """
        Logs an error message.
        Args:
            msg (str): The error message to log.
        """
        if self.json_mode:
            return
        self.console.print(f"[red][X][/red] {msg}", style="white")
    
    def record(self, data: dict) -> None:
        """
        Records a result to be included in the final output. This method
        is used to accumulate results that will be outputted at the end 
        of the execution.
        Args:
            data (dict): The result data to record.
        """
        self._results.append(data)
        json_data = json.dumps(data, indent=4)

        if self.json_mode:
            self.console.print(json_data)

        if self.outfile is not None:
            self.outfile.write(json_data + '\n')
    
    def flush(self) -> None:
        """
        Flushes the output file buffer to disk if an output file is open. Useful
        for ensuring results are written during long-running sessions.
        """
        if self.outfile is not None:
            try:
                self.outfile.flush()
            except Exception:
                pass