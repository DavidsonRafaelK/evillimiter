import re
import logging
import colorama

from . import shell


class IO(object):
    _ANSI_CSI_RE = re.compile('\001?\033\\[((?:\\d|;)*)([a-zA-Z])\002?')

    Back = colorama.Back
    Fore = colorama.Fore
    Style = colorama.Style

    colorless = False
    _logger = None

    @staticmethod
    def initialize(colorless=False, log_file=None):
        """
        Initializes console input and output. If log_file is given,
        every ok()/error() message is additionally appended there
        (plain text, ANSI stripped) - opt-in, no file is touched
        otherwise.
        """
        IO.colorless = colorless
        if not colorless:
            colorama.init(autoreset=True)

        if log_file:
            try:
                handler = logging.FileHandler(log_file)
            except OSError as e:
                IO.error('could not open log file {}: {}.'.format(log_file, e))
                return

            handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
            logger = logging.getLogger('evillimiter')
            logger.setLevel(logging.INFO)
            logger.addHandler(handler)
            IO._logger = logger

    @staticmethod
    def print(text, end='\n', flush=False):
        """
        Writes a given string to the console.
        """
        if IO.colorless:
            text = IO._remove_colors(text)

        print(text, end=end, flush=flush)

    @staticmethod
    def ok(text, end='\n'):
        """
        Print a success status message
        """
        IO.print('{}OK{}   {}'.format(IO.Style.BRIGHT + IO.Fore.LIGHTGREEN_EX, IO.Style.RESET_ALL, text), end=end)
        if IO._logger:
            IO._logger.info(IO._remove_colors(text))

    @staticmethod
    def error(text):
        """
        Print an error status message
        """
        IO.print('{}ERR{}  {}'.format(IO.Style.BRIGHT + IO.Fore.LIGHTRED_EX, IO.Style.RESET_ALL, text))
        if IO._logger:
            IO._logger.error(IO._remove_colors(text))

    @staticmethod
    def spacer():
        """
        Prints a blank line for attraction purposes
        """
        IO.print('')

    @staticmethod
    def input(prompt):
        """
        Prompts the user for input.
        """
        if IO.colorless:
            prompt = IO._remove_colors(prompt)

        return input(prompt)

    @staticmethod
    def clear():
        """
        Clears the terminal screen
        """
        shell.execute('clear')

    @staticmethod
    def _remove_colors(text):
        edited = text

        for match in IO._ANSI_CSI_RE.finditer(text):
                s, e = match.span()
                edited = edited.replace(text[s:e], '')

        return edited
