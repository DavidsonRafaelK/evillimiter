import enum
import collections
import os

try:
    import readline
except ImportError:
    readline = None

from .parser import CommandParser
from evillimiter.console.io import IO
from evillimiter.common.config import history_file_path


HISTORY_LENGTH = 1000


class CommandMenu(object):
    def __init__(self):
        self.prompt = '>>> '
        self.parser = CommandParser()
        self._active = False

        if readline is not None:
            readline.set_history_length(HISTORY_LENGTH)
            try:
                readline.read_history_file(history_file_path())
            except (FileNotFoundError, OSError):
                pass

    def argument_handler(self, args):
        """
        Handles command-line arguments.
        """
        pass

    def interrupt_handler(self):
        """
        Handles a keyboard interrupt in the input loop.
        """
        self.stop()

    def start(self):
        """
        Starts the menu input loop.
        Commands will be processed and handled.
        """
        self._active = True

        while self._active:
            try:
                command = IO.input(self.prompt)
            except KeyboardInterrupt:
                self.interrupt_handler()
                break

            # split command by spaces and parse the arguments
            parsed_args = self.parser.parse(command.split())
            if parsed_args is not None:
                self.argument_handler(parsed_args)

    def stop(self):
        """
        Breaks the menu input loop
        """
        self._active = False

        if readline is not None:
            try:
                os.makedirs(os.path.dirname(history_file_path()), exist_ok=True)
                readline.write_history_file(history_file_path())
            except OSError:
                pass
