import os
import tempfile
import unittest

from evillimiter.common.config import load_config, history_file_path, _default_paths


def _write(content):
    fd, path = tempfile.mkstemp(suffix='.ini')
    with os.fdopen(fd, 'w') as f:
        f.write(content)
    return path


class LoadConfigTest(unittest.TestCase):
    def test_missing_file_returns_empty_dict(self):
        self.assertEqual(load_config(paths=['/nonexistent/evillimiter/config.ini']), {})

    def test_empty_file_returns_empty_dict(self):
        path = _write('')
        try:
            self.assertEqual(load_config(paths=[path]), {})
        finally:
            os.remove(path)

    def test_reads_general_section(self):
        path = _write(
            '[general]\n'
            'interface = eth0\n'
            'gateway_ip = 192.168.1.1\n'
            'gateway_mac = aa:bb:cc:dd:ee:ff\n'
            'netmask = 255.255.255.0\n'
            'colorless = true\n'
            'log_file = /tmp/evillimiter.log\n'
        )
        try:
            config = load_config(paths=[path])
        finally:
            os.remove(path)

        self.assertEqual(config, {
            'interface': 'eth0',
            'gateway_ip': '192.168.1.1',
            'gateway_mac': 'aa:bb:cc:dd:ee:ff',
            'netmask': '255.255.255.0',
            'colorless': True,
            'log_file': '/tmp/evillimiter.log',
        })

    def test_reads_watch_section(self):
        path = _write(
            '[watch]\n'
            'interval = 30\n'
            'range = 192.168.1.1-192.168.1.50\n'
        )
        try:
            config = load_config(paths=[path])
        finally:
            os.remove(path)

        self.assertEqual(config, {
            'watch_interval': 30,
            'watch_range': '192.168.1.1-192.168.1.50',
        })

    def test_partial_general_section_only_returns_present_keys(self):
        path = _write('[general]\ninterface = wlan0\n')
        try:
            config = load_config(paths=[path])
        finally:
            os.remove(path)

        self.assertEqual(config, {'interface': 'wlan0'})

    def test_flush_is_never_read_from_config(self):
        # flush is a one-shot destructive action, not a persisted preference
        path = _write('[general]\nflush = true\n')
        try:
            config = load_config(paths=[path])
        finally:
            os.remove(path)

        self.assertNotIn('flush', config)


class HistoryFilePathTest(unittest.TestCase):
    def test_sits_alongside_config_file(self):
        config_dir = os.path.dirname(_default_paths()[0])
        self.assertEqual(history_file_path(), os.path.join(config_dir, 'history'))


if __name__ == '__main__':
    unittest.main()
