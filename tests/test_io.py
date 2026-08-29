import os
import logging
import tempfile
import unittest

# console.shell and console.io have a circular import that only resolves when
# shell is loaded first (as the app's globals module does at startup).
import evillimiter.console.shell  # noqa: F401
from evillimiter.console.io import IO


class IOLogFileTest(unittest.TestCase):
    def setUp(self):
        fd, self.log_path = tempfile.mkstemp(suffix='.log')
        os.close(fd)

    def tearDown(self):
        # IO._logger and the 'evillimiter' logger are module-level state -
        # reset both so tests don't leak handlers/log files into each other
        logger = logging.getLogger('evillimiter')
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()
        IO._logger = None
        IO.colorless = False
        os.remove(self.log_path)

    def _read_log(self):
        with open(self.log_path, 'r') as f:
            return f.read()

    def test_no_log_file_writes_nothing(self):
        IO.initialize(colorless=True, log_file=None)
        IO.ok('host limited')

        self.assertIsNone(IO._logger)
        self.assertEqual(self._read_log(), '')

    def test_ok_and_error_are_appended_to_log_file(self):
        IO.initialize(colorless=True, log_file=self.log_path)
        IO.ok('host limited')
        IO.error('limit failed')

        content = self._read_log()
        self.assertIn('INFO', content)
        self.assertIn('host limited', content)
        self.assertIn('ERROR', content)
        self.assertIn('limit failed', content)

    def test_log_file_strips_ansi_color_codes(self):
        IO.initialize(colorless=False, log_file=self.log_path)
        IO.ok('{}colored{}'.format(IO.Fore.LIGHTYELLOW_EX, IO.Style.RESET_ALL))

        content = self._read_log()
        self.assertIn('colored', content)
        self.assertNotIn('\033[', content)

    def test_unwritable_log_path_reports_error_but_does_not_raise(self):
        IO.initialize(colorless=True, log_file='/nonexistent-dir/evillimiter.log')
        self.assertIsNone(IO._logger)


if __name__ == '__main__':
    unittest.main()
