import unittest

# console.shell and console.io have a circular import that only resolves when
# shell is loaded first (as the app's globals module does at startup).
import evillimiter.console.shell  # noqa: F401
import evillimiter
from evillimiter.evillimiter import get_version, get_description


class VersionAndDescriptionTest(unittest.TestCase):
    """
    get_version()/get_description() used to regex-parse __init__.py's
    source text off disk instead of reading the already-imported
    module attributes. That broke under PyInstaller (and any other
    packaging that doesn't ship loose .py files) - evillimiter.py is
    a submodule of the evillimiter package, so __init__.py has always
    already run by the time this code executes; there was never a
    reason to re-read it from disk.
    """
    def test_get_version_matches_package_attribute(self):
        self.assertEqual(get_version(), evillimiter.__version__)

    def test_get_description_matches_package_attribute(self):
        self.assertEqual(get_description(), evillimiter.__description__)


if __name__ == '__main__':
    unittest.main()
