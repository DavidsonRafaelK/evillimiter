import unittest

import evillimiter.console.shell  # noqa: F401 - resolve circular import first
from evillimiter.console.chart import BarChart


class BarChartTest(unittest.TestCase):
    def test_get_on_empty_chart_returns_empty_string(self):
        # get() must not raise IndexError when no values were added
        self.assertEqual(BarChart().get(), '')

    def test_get_renders_added_values(self):
        chart = BarChart()
        chart.add_value(10, 'a')
        chart.add_value(20, 'b')
        self.assertIn('a', chart.get())
        self.assertIn('b', chart.get())


if __name__ == '__main__':
    unittest.main()
