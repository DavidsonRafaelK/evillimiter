"""
Presentation layer for the main menu.

Pure rendering: every function here takes primitive data already
resolved by the caller (ids, ip/mac strings, rates, status flags) and
turns it into terminal output. It holds none of the menu's state and
touches none of the networking subsystems, so the discovered-host list,
its lock and the spoofer/limiter/monitor orchestration stay entirely in
MainMenu. This keeps command dispatch and business orchestration
separate from how results are drawn.
"""
import time
import curses
from terminaltables import SingleTable

from evillimiter.console.io import IO
from evillimiter.console.chart import BarChart


def _header(text):
    return '{}{}{}'.format(IO.Style.BRIGHT, text, IO.Style.RESET_ALL)


def print_hosts_table(rows, force):
    """
    Renders the discovered-hosts table. `rows` is a list of
    (id, ip, mac, name, status) tuples, already resolved (and the status
    string already prettified) by the caller under the hosts lock.
    """
    table_data = [[
        _header('ID'),
        _header('IP address'),
        _header('MAC address'),
        _header('Hostname'),
        _header('Status')
    ]]

    for id_, ip, mac, name, status in rows:
        table_data.append([
            '{}{}{}'.format(IO.Fore.LIGHTYELLOW_EX, id_, IO.Style.RESET_ALL),
            ip,
            mac,
            name,
            status
        ])

    table = SingleTable(table_data, 'Hosts')

    if not force and not table.ok:
        IO.error('table does not fit terminal. resize or decrease font size. you can also force the display (--force).')
        return

    IO.spacer()
    IO.print(table.table)
    IO.spacer()


def print_watch(watch_rows, range_str, interval, history_rows):
    """
    Renders the three watch tables (watchlist, settings, reconnection
    history). `watch_rows` is a list of (id, ip, mac, offline) tuples;
    `history_rows` a list of (mac, old_ip, new_ip, time) tuples.
    """
    watch_table_data = [[
        _header('ID'),
        _header('IP address'),
        _header('MAC address'),
        _header('Status')
    ]]

    set_table_data = [[
        _header('Attribute'),
        _header('Value')
    ]]

    hist_table_data = [[
        _header('ID'),
        _header('Old IP address'),
        _header('New IP address'),
        _header('Time')
    ]]

    set_table_data.append([
        '{}range{}'.format(IO.Fore.LIGHTYELLOW_EX, IO.Style.RESET_ALL),
        range_str
    ])

    set_table_data.append([
        '{}interval{}'.format(IO.Fore.LIGHTYELLOW_EX, IO.Style.RESET_ALL),
        '{}s'.format(interval)
    ])

    for id_, ip, mac, offline in watch_rows:
        if offline:
            status = '{}Offline{}'.format(IO.Fore.LIGHTRED_EX, IO.Style.RESET_ALL)
        else:
            status = '{}Online{}'.format(IO.Fore.LIGHTGREEN_EX, IO.Style.RESET_ALL)

        watch_table_data.append([
            '{}{}{}'.format(IO.Fore.LIGHTYELLOW_EX, id_, IO.Style.RESET_ALL),
            ip,
            mac,
            status
        ])

    for mac, old_ip, new_ip, recon_time in history_rows:
        hist_table_data.append([mac, old_ip, new_ip, recon_time])

    watch_table = SingleTable(watch_table_data, "Watchlist")
    set_table = SingleTable(set_table_data, "Settings")
    hist_table = SingleTable(hist_table_data, 'Reconnection History')

    IO.spacer()
    IO.print(watch_table.table)
    IO.spacer()
    IO.print(set_table.table)
    IO.spacer()
    IO.print(hist_table.table)
    IO.spacer()


def print_analyze(entries):
    """
    Renders the upload/download bar charts. `entries` is a list of
    (upload_value, download_value, prefix) tuples, where the *_value are
    BitRate deltas and `prefix` is the pre-formatted host label.
    """
    upload_chart = BarChart(max_bar_length=29)
    download_chart = BarChart(max_bar_length=29)

    for upload_value, download_value, prefix in entries:
        upload_chart.add_value(upload_value.value, prefix, upload_value)
        download_chart.add_value(download_value.value, prefix, download_value)

    upload_table = SingleTable([[upload_chart.get()]], 'Upload')
    download_table = SingleTable([[download_chart.get()]], 'Download')

    upload_table.inner_heading_row_border = False
    download_table.inner_heading_row_border = False

    IO.spacer()
    IO.print(upload_table.table)
    IO.print(download_table.table)
    IO.spacer()


def monitor_display(stdscr, interval, fetch, id_of):
    """
    curses draw loop for the `monitor` command. `fetch` returns the
    current [(host, result), ...] snapshot (taken under the hosts lock
    by the caller) and `id_of` maps a host to its display id, so this
    loop stays unaware of the menu's host list and locking.
    """
    host_results = fetch()
    hname_max_len = max([len(x[0].name) for x in host_results])

    header_off = [
        ('ID', 5), ('IP address', 18), ('Hostname', hname_max_len + 2),
        ('Current (per s)', 20), ('Total', 16), ('Packets', 0)
    ]

    y_rst = 1
    x_rst = 2

    while True:
        y_off = y_rst
        x_off = x_rst

        stdscr.clear()

        for header in header_off:
            stdscr.addstr(y_off, x_off, header[0])
            x_off += header[1]

        y_off += 2
        x_off = x_rst

        for host, result in host_results:
            result_data = [
                str(id_of(host)),
                host.ip,
                host.name,
                '{}↑ {}↓'.format(result.upload_rate, result.download_rate),
                '{}↑ {}↓'.format(result.upload_total_size, result.download_total_size),
                '{}↑ {}↓'.format(result.upload_total_count, result.download_total_count)
            ]

            for j, string in enumerate(result_data):
                stdscr.addstr(y_off, x_off, string)
                x_off += header_off[j][1]

            y_off += 1
            x_off = x_rst

        y_off += 2
        stdscr.addstr(y_off, x_off, 'press \'ctrl+c\' to exit.')

        try:
            stdscr.refresh()
            time.sleep(interval)
            host_results = fetch()
        except KeyboardInterrupt:
            return


def print_help():
    """
    Prints the command reference. Static text, no menu state.
    """
    spaces = ' ' * 35

    IO.print(
        """
{y}scan (--range [IP range]){r}{}scans for online hosts on your network.
{y}     (--intensity [1,2,3]){r}{}required to find the hosts you want to limit.
{b}{s}e.g.: scan
{s}      scan --range 192.168.178.1-192.168.178.50
{s}      scan --range 192.168.178.1/24
{s}      scan --intensity 3{r}

{y}hosts (--force){r}{}lists all scanned hosts.
{s}contains host information, including IDs.

{y}limit [ID1,ID2,...] [rate]{r}{}limits bandwith of host(s) (uload/dload).
{y}      (--upload) (--download){r}{}{b}e.g.: limit 4 100kbit
{s}      limit 2,3,4 1gbit --download
{s}      limit all 200kbit --upload{r}

{y}block [ID1,ID2,...]{r}{}blocks internet access of host(s).
{y}      (--upload) (--download){r}{}{b}e.g.: block 3,2
{s}      block all --upload{r}

{y}free [ID1,ID2,...]{r}{}unlimits/unblocks host(s).
{b}{s}e.g.: free 3
{s}      free all{r}

{y}add [IP] (--mac [MAC]){r}{}adds custom host to host list.
{s}mac resolved automatically.
{b}{s}e.g.: add 192.168.178.24
{s}      add 192.168.1.50 --mac 1c:fc:bc:2d:a6:37{r}

{y}monitor (--interval [time in ms]){r}{}monitors bandwidth usage of limited host(s).
{b}{s}e.g.: monitor --interval 600{r}

{y}analyze [ID1,ID2,...]{r}{}analyzes traffic of host(s) without limiting
{y}        (--duration [time in s]){r}{}to determine who uses how much bandwidth.
{b}{s}e.g.: analyze 2,3 --duration 120{r}

{y}watch{r}{}detects host reconnects with different IP.
{y}watch add [ID1,ID2,...]{r}{}adds host to the reconnection watchlist.
{b}{s}e.g.: watch add 3,4{r}
{y}watch remove [ID1,ID2,...]{r}{}removes host from the reconnection watchlist.
{b}{s}e.g.: watch remove all{r}
{y}watch set [attr] [value]{r}{}changes reconnect watch settings.
{b}{s}e.g.: watch set interval 120{r}

{y}clear{r}{}clears the terminal window.

{y}quit{r}{}quits the application.
            """.format(
                spaces[len('scan (--range [IP range])'):],
                spaces[len('     (--intensity [1,2,3])'):],
                spaces[len('hosts (--force)'):],
                spaces[len('limit [ID1,ID2,...] [rate]'):],
                spaces[len('      (--upload) (--download)'):],
                spaces[len('block [ID1,ID2,...]'):],
                spaces[len('      (--upload) (--download)'):],
                spaces[len('free [ID1,ID2,...]'):],
                spaces[len('add [IP] (--mac [MAC])'):],
                spaces[len('monitor (--interval [time in ms])'):],
                spaces[len('analyze [ID1,ID2,...]'):],
                spaces[len('        (--duration [time in s])'):],
                spaces[len('watch'):],
                spaces[len('watch add [ID1,ID2,...]'):],
                spaces[len('watch remove [ID1,ID2,...]'):],
                spaces[len('watch set [attr] [value]'):],
                spaces[len('clear'):],
                spaces[len('quit'):],
                y=IO.Fore.LIGHTYELLOW_EX, r=IO.Style.RESET_ALL, b=IO.Style.BRIGHT,
                s=spaces
            )
    )
