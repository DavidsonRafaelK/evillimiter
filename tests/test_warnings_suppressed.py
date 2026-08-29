import io
import logging
import unittest

# importing the package runs evillimiter/__init__.py, which is what
# installs the filters/level under test.
import evillimiter  # noqa: F401
from scapy.error import warning as scapy_warning


class ScapyRuntimeWarningsSuppressedTest(unittest.TestCase):
    """
    bitbrute/evillimiter#106: scan spammed
    "WARNING: Mac address to reach destination not found. Using broadcast."
    for every unanswered ARP probe. That message is scapy's normal,
    expected behavior for a broadcast ARP scan, not a real problem -
    evillimiter/__init__.py raises the 'scapy.runtime' logger to ERROR
    to drop it (and other routine scapy runtime noise) without hiding
    actual errors.
    """

    def test_scapy_runtime_logger_level_is_error(self):
        self.assertGreaterEqual(logging.getLogger('scapy.runtime').getEffectiveLevel(), logging.ERROR)

    def test_mac_not_found_warning_produces_no_output(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger('scapy.runtime')
        logger.addHandler(handler)
        try:
            scapy_warning('MAC address to reach destination not found. Using broadcast.')
        finally:
            logger.removeHandler(handler)

        self.assertEqual(stream.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
