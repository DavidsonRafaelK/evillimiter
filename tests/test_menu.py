import os
import tempfile
import unittest
from unittest import mock

# console.shell and console.io have a circular import that only resolves when
# shell is loaded first (as the app's globals module does at startup).
import evillimiter.console.shell  # noqa: F401
import evillimiter.menus.menu as menu_module
from evillimiter.menus.menu import CommandMenu


class CommandMenuHistoryTest(unittest.TestCase):
    def test_init_loads_history_file_via_readline(self):
        with mock.patch.object(menu_module, 'readline') as mock_readline, \
             mock.patch.object(menu_module, 'history_file_path', return_value='/fake/history'):
            CommandMenu()

        mock_readline.set_history_length.assert_called_once_with(menu_module.HISTORY_LENGTH)
        mock_readline.read_history_file.assert_called_once_with('/fake/history')

    def test_init_ignores_missing_history_file(self):
        with mock.patch.object(menu_module, 'readline') as mock_readline:
            mock_readline.read_history_file.side_effect = FileNotFoundError

            CommandMenu()  # must not raise

    def test_init_without_readline_available_does_not_raise(self):
        with mock.patch.object(menu_module, 'readline', None):
            CommandMenu()  # must not raise

    def test_stop_writes_history_file_creating_parent_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'nested', 'history')

            with mock.patch.object(menu_module, 'readline') as mock_readline, \
                 mock.patch.object(menu_module, 'history_file_path', return_value=path):
                menu = CommandMenu()
                menu.stop()

            mock_readline.write_history_file.assert_called_once_with(path)
            self.assertTrue(os.path.isdir(os.path.dirname(path)))

    def test_stop_without_readline_available_does_not_raise(self):
        with mock.patch.object(menu_module, 'readline', None):
            menu = CommandMenu()
            menu.stop()  # must not raise

    def test_stop_sets_inactive(self):
        with mock.patch.object(menu_module, 'readline', None):
            menu = CommandMenu()
            menu._active = True
            menu.stop()

        self.assertFalse(menu._active)


if __name__ == '__main__':
    unittest.main()
