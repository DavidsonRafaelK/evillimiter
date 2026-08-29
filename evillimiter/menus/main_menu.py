import time
import curses
import netaddr
import threading

import evillimiter.networking.utils as netutils
from . import views
from .menu import CommandMenu
from evillimiter.networking.utils import BitRate
from evillimiter.console.io import IO
from evillimiter.console.banner import get_main_banner
from evillimiter.networking.host import Host
from evillimiter.networking.limit import Limiter, Direction, LimitApplyError
from evillimiter.networking.spoof import ARPSpoofer
from evillimiter.networking.ndp_spoof import NDPSpoofer
from evillimiter.networking.scan import HostScanner, ScanIntensity
from evillimiter.networking.monitor import BandwidthMonitor
from evillimiter.networking.watch import HostWatcher
from evillimiter.networking.dhcp_listener import DHCPHostnameListener


class MainMenu(CommandMenu):
    def __init__(self, version, interface, gateway_ip, gateway_mac, netmask, watch_interval=None, watch_range=None):
        super().__init__()
        self.prompt = '({}Main{}) >>> '.format(IO.Style.BRIGHT, IO.Style.RESET_ALL)
        self._build_parser()

        self.version = version          # application version
        self.interface = interface      # specified IPv4 interface
        self.gateway_ip = gateway_ip 
        self.gateway_mac = gateway_mac
        self.netmask = netmask

        # range of IP address calculated from gateway IP and netmask
        self.iprange = list(netaddr.IPNetwork('{}/{}'.format(self.gateway_ip, self.netmask)))

        self.dhcp_listener = DHCPHostnameListener(self.interface)
        self.host_scanner = HostScanner(self.interface, self.iprange, self.dhcp_listener)
        self.arp_spoofer = ARPSpoofer(self.interface, self.gateway_ip, self.gateway_mac)
        self.ndp_spoofer = NDPSpoofer(self.interface, netutils.get_default_gateway_ipv6())
        self.limiter = Limiter(self.interface)
        self.bandwidth_monitor = BandwidthMonitor(self.interface, 1)
        self.host_watcher = HostWatcher(self.host_scanner, self._reconnect_callback)

        if watch_interval is not None:
            self.host_watcher.interval = watch_interval

        if watch_range is not None:
            parsed_range = self._parse_iprange(watch_range)
            if parsed_range is not None:
                self.host_watcher.iprange = parsed_range
            else:
                IO.error('invalid watch range in config: {}{}{}.'.format(IO.Fore.LIGHTYELLOW_EX, watch_range, IO.Style.RESET_ALL))

        # holds discovered hosts
        self.hosts = []
        self.hosts_lock = threading.Lock()

        self._print_help_reminder()

        # start the spoof thread
        self.arp_spoofer.start()
        # start the ipv6 (ndp) spoof thread
        self.ndp_spoofer.start()
        # start the bandwidth monitor thread
        self.bandwidth_monitor.start()
        # start the host watch thread
        self.host_watcher.start()
        # start the dhcp hostname listener thread
        self.dhcp_listener.start()

    def _build_parser(self):
        """
        Wires up the command grammar (subparsers, parameters, flags) and
        binds each command to its handler. Kept separate from __init__ so
        dispatch wiring doesn't tangle with subsystem construction.
        """
        self.parser.add_subparser('clear', self._clear_handler)

        hosts_parser = self.parser.add_subparser('hosts', self._hosts_handler)
        hosts_parser.add_flag('--force', 'force')

        scan_parser = self.parser.add_subparser('scan', self._scan_handler)
        scan_parser.add_parameterized_flag('--range', 'iprange')
        scan_parser.add_parameterized_flag('--intensity', 'intensity')

        limit_parser = self.parser.add_subparser('limit', self._limit_handler)
        limit_parser.add_parameter('id')
        limit_parser.add_parameter('rate')
        limit_parser.add_flag('--upload', 'upload')
        limit_parser.add_flag('--download', 'download')

        block_parser = self.parser.add_subparser('block', self._block_handler)
        block_parser.add_parameter('id')
        block_parser.add_flag('--upload', 'upload')
        block_parser.add_flag('--download', 'download')

        free_parser = self.parser.add_subparser('free', self._free_handler)
        free_parser.add_parameter('id')

        add_parser = self.parser.add_subparser('add', self._add_handler)
        add_parser.add_parameter('ip')
        add_parser.add_parameterized_flag('--mac', 'mac')

        monitor_parser = self.parser.add_subparser('monitor', self._monitor_handler)
        monitor_parser.add_parameterized_flag('--interval', 'interval')

        analyze_parser = self.parser.add_subparser('analyze', self._analyze_handler)
        analyze_parser.add_parameter('id')
        analyze_parser.add_parameterized_flag('--duration', 'duration')

        watch_parser = self.parser.add_subparser('watch', self._watch_handler)
        watch_add_parser = watch_parser.add_subparser('add', self._watch_add_handler)
        watch_add_parser.add_parameter('id')
        watch_remove_parser = watch_parser.add_subparser('remove', self._watch_remove_handler)
        watch_remove_parser.add_parameter('id')
        watch_set_parser = watch_parser.add_subparser('set', self._watch_set_handler)
        watch_set_parser.add_parameter('attribute')
        watch_set_parser.add_parameter('value')

        self.parser.add_subparser('help', self._help_handler)
        self.parser.add_subparser('?', self._help_handler)

        self.parser.add_subparser('quit', self._quit_handler)
        self.parser.add_subparser('exit', self._quit_handler)

    def interrupt_handler(self, ctrl_c=True):
        if ctrl_c:
            IO.spacer()

        IO.ok('cleaning up... stand by...')

        self.arp_spoofer.stop()
        self.ndp_spoofer.stop()
        self.bandwidth_monitor.stop()

        for host in self.hosts:
            self._free_host(host)

    def _scan_handler(self, args):
        """
        Handles 'scan' command-line argument
        (Re)scans for hosts on the network
        """
        if args.iprange:
            iprange = self._parse_iprange(args.iprange)
            if iprange is None:
                IO.error('invalid ip range.')
                return
        else:
            iprange = None

        if args.intensity:
            intensity = self._parse_scan_intensity(args.intensity)
            if intensity is None:
                IO.error('invalid intensity level. must be 1 (quick), 2 (normal) or 3 (intense).')
                return
            # sticky: also affects watch's background reconnect sweeps,
            # which share this same scanner, until changed again
            self.host_scanner.set_intensity(intensity)

        with self.hosts_lock:
            for host in self.hosts:
                self._free_host(host)
            
        IO.spacer()
        hosts = self.host_scanner.scan(iprange)

        self.hosts_lock.acquire()
        self.hosts = hosts
        self.hosts_lock.release()

        IO.ok('{}{}{} hosts discovered.'.format(IO.Fore.LIGHTYELLOW_EX, len(hosts), IO.Style.RESET_ALL))
        IO.spacer()

    def _hosts_handler(self, args):
        """
        Handles 'hosts' command-line argument
        Displays discovered hosts
        """
        with self.hosts_lock:
            rows = [
                (
                    self._get_host_id(host, lock=False),
                    host.ip,
                    host.mac,
                    host.name,
                    self._pretty_host_status(host)
                )
                for host in self.hosts
            ]

        views.print_hosts_table(rows, args.force)

    def _pretty_host_status(self, host):
        """
        Host's Status column: appends the assigned rate/direction to
        Limited/Blocked, instead of just the bare status word. `limiter`
        is the source of truth for rate/direction (host only tracks the
        limited/blocked flags), so it's asked directly rather than
        duplicating that state onto Host.
        """
        status = host.pretty_status()
        info = self.limiter.info(host)

        if info is None:
            return status

        rate, direction = info
        detail = str(rate) if rate is not None else None

        if direction != Direction.BOTH:
            direction_str = Direction.pretty_direction(direction)
            detail = '{} {}'.format(detail, direction_str) if detail else direction_str

        return '{} ({})'.format(status, detail) if detail else status

    def _limit_handler(self, args):
        """
        Handles 'limit' command-line argument
        Limits bandwith of host to specified rate
        """
        hosts = self._get_hosts_by_ids(args.id)
        if hosts is None or len(hosts) == 0:
            return

        try:
            rate = BitRate.from_rate_string(args.rate)
        except Exception:
            IO.error('limit rate is invalid.')
            return

        direction = self._parse_direction_args(args)

        for host in hosts:
            self.arp_spoofer.add(host)
            self.ndp_spoofer.add(host)
            self.host_watcher.add(host)

            try:
                self.limiter.limit(host, direction, rate)
            except LimitApplyError as e:
                IO.error('{}{}{r} {} limit only partially applied: {}.'.format(IO.Fore.LIGHTYELLOW_EX, host.ip, Direction.pretty_direction(direction), ', '.join(e.failed_steps), r=IO.Style.RESET_ALL))
            else:
                IO.ok('{}{}{r} {} {}limited{r} to {}.'.format(IO.Fore.LIGHTYELLOW_EX, host.ip, Direction.pretty_direction(direction), IO.Fore.LIGHTRED_EX, rate, r=IO.Style.RESET_ALL))

            self.bandwidth_monitor.add(host)

    def _block_handler(self, args):
        """
        Handles 'block' command-line argument
        Blocks internet communication for host
        """
        hosts = self._get_hosts_by_ids(args.id)
        direction = self._parse_direction_args(args)

        if hosts is not None and len(hosts) > 0:
            for host in hosts:
                if not host.spoofed:
                    self.arp_spoofer.add(host)

                self.ndp_spoofer.add(host)
                self.host_watcher.add(host)

                try:
                    self.limiter.block(host, direction)
                except LimitApplyError as e:
                    IO.error('{}{}{r} {} block only partially applied: {}.'.format(IO.Fore.LIGHTYELLOW_EX, host.ip, Direction.pretty_direction(direction), ', '.join(e.failed_steps), r=IO.Style.RESET_ALL))
                else:
                    IO.ok('{}{}{r} {} {}blocked{r}.'.format(IO.Fore.LIGHTYELLOW_EX, host.ip, Direction.pretty_direction(direction), IO.Fore.RED, r=IO.Style.RESET_ALL))

                self.bandwidth_monitor.add(host)

    def _free_handler(self, args):
        """
        Handles 'free' command-line argument
        Frees the host from all limitations
        """
        hosts = self._get_hosts_by_ids(args.id)
        if hosts is not None and len(hosts) > 0:
            for host in hosts:
                self._free_host(host)

    def _add_handler(self, args):
        """
        Handles 'add' command-line argument
        Adds custom host to host list
        """
        ip = args.ip
        if not netutils.validate_ip_address(ip):
            IO.error('invalid ip address.')
            return

        if args.mac:
            mac = args.mac
            if not netutils.validate_mac_address(mac):
                IO.error('invalid mac address.')
                return
        else:
            mac = netutils.get_mac_by_ip(self.interface, ip)
            if mac is None:
                IO.error('unable to resolve mac address. specify manually (--mac).')
                return

        name = self.dhcp_listener.get(mac) or netutils.get_hostname(ip)

        host = Host(ip, mac, name)

        with self.hosts_lock:
            if host in self.hosts:
                IO.error('host does already exist.')
                return

            self.hosts.append(host) 

        IO.ok('host added.')

    def _monitor_handler(self, args):
        """
        Handles 'monitor' command-line argument
        Monitors hosts bandwidth usage
        """
        def get_bandwidth_results():
            with self.hosts_lock:
                return [x for x in [(y, self.bandwidth_monitor.get(y)) for y in self.hosts] if x[1] is not None]

        interval = 0.5  # in s
        if args.interval:
            if not args.interval.isdigit():
                IO.error('invalid interval.')
                return

            interval = int(args.interval) / 1000    # from ms to s

        if len(get_bandwidth_results()) == 0:
            IO.error('no hosts to be monitored.')
            return

        try:
            curses.wrapper(views.monitor_display, interval, get_bandwidth_results, self._get_host_id)
        except curses.error:
            IO.error('monitor error occurred. maybe terminal too small?')

    def _analyze_handler(self, args):
        hosts = self._get_hosts_by_ids(args.id)
        if hosts is None or len(hosts) == 0:
            IO.error('no hosts to be analyzed.')
            return
        
        duration = 30 # in s
        if args.duration:
            if not args.duration.isdigit():
                IO.error('invalid duration.')
                return

            duration = int(args.duration)

        hosts_to_be_freed = set()
        host_values = {}

        for host in hosts:
            if not host.spoofed:
                hosts_to_be_freed.add(host)

            self.arp_spoofer.add(host)
            self.bandwidth_monitor.add(host)

            host_result = self.bandwidth_monitor.get(host)
            host_values[host] = {}
            host_values[host]['prev'] = (host_result.upload_total_size, host_result.download_total_size)

        IO.ok('analyzing traffic for {}s.'.format(duration))
        time.sleep(duration)

        error_occurred = False
        for host in hosts:
            host_result = self.bandwidth_monitor.get(host)

            if host_result is None:
                # host reconnected during analysis
                IO.error('host reconnected during analysis.')
                error_occurred = True
            else:
                host_values[host]['current'] = (host_result.upload_total_size, host_result.download_total_size)

        IO.ok('cleaning up...')
        for host in hosts_to_be_freed:
            self._free_host(host)

        if error_occurred:
            return

        entries = []
        for host in hosts:
            upload_value = host_values[host]['current'][0] - host_values[host]['prev'][0]
            download_value = host_values[host]['current'][1] - host_values[host]['prev'][1]

            prefix = '{}{}{} ({}, {})'.format(
                IO.Fore.LIGHTYELLOW_EX, self._get_host_id(host), IO.Style.RESET_ALL,
                host.ip,
                host.name
            )

            entries.append((upload_value, download_value, prefix))

        views.print_analyze(entries)

    def _watch_handler(self, args):
        if len(args) == 0:
            iprange = self.host_watcher.iprange
            interval = self.host_watcher.interval
            range_str = '{} addresses'.format(len(iprange)) if iprange is not None else 'default'

            absent_hosts = self.host_watcher.absent_hosts
            watch_rows = [
                (self._get_host_id(host), host.ip, host.mac, host in absent_hosts)
                for host in self.host_watcher.hosts
            ]

            history_rows = [
                (recon['old'].mac, recon['old'].ip, recon['new'].ip, recon['time'])
                for recon in self.host_watcher.log_list
            ]

            views.print_watch(watch_rows, range_str, interval, history_rows)

    def _watch_add_handler(self, args):
        """
        Handles 'watch add' command-line argument
        Adds host to the reconnection watch list
        """
        hosts = self._get_hosts_by_ids(args.id)
        if hosts is None or len(hosts) == 0:
            return

        for host in hosts:
            self.host_watcher.add(host)

    def _watch_remove_handler(self, args):
        """
        Handles 'watch remove' command-line argument
        Removes host from the reconnection watch list
        """
        hosts = self._get_hosts_by_ids(args.id)
        if hosts is None or len(hosts) == 0:
            return

        for host in hosts:
            self.host_watcher.remove(host)

    def _watch_set_handler(self, args):
        """
        Handles 'watch set' command-line argument
        Modifies settings of the reconnection reconnection watcher
        """
        if args.attribute.lower() in ('range', 'iprange', 'ip_range'):
            iprange = self._parse_iprange(args.value)
            if iprange is not None:
                self.host_watcher.iprange = iprange
            else:
                IO.error('invalid ip range.')
        elif args.attribute.lower() in ('interval'):
            if args.value.isdigit():
                self.host_watcher.interval = int(args.value)
            else:
                IO.error('invalid interval.')
        else:
            IO.error('{}{}{} is an invalid settings attribute.'.format(IO.Fore.LIGHTYELLOW_EX, args.attribute, IO.Style.RESET_ALL))

    def _reconnect_callback(self, old_host, new_host):
        """
        Callback that is called when a watched host reconnects
        Method will run in a separate thread
        """
        with self.hosts_lock:
            if old_host in self.hosts:
                self.hosts[self.hosts.index(old_host)] = new_host
            else:
                return

        self.arp_spoofer.remove(old_host, restore=False)
        self.arp_spoofer.add(new_host)
        self.ndp_spoofer.remove(old_host)
        self.ndp_spoofer.add(new_host)

        self.host_watcher.remove(old_host)
        self.host_watcher.add(new_host)

        try:
            self.limiter.replace(old_host, new_host)
        except LimitApplyError as e:
            IO.error('{}{}{r} reconnected as {}{}{r}, but restriction reapply only partially succeeded: {}.'.format(IO.Fore.LIGHTYELLOW_EX, old_host.ip, IO.Fore.LIGHTYELLOW_EX, new_host.ip, ', '.join(e.failed_steps), r=IO.Style.RESET_ALL))
        else:
            IO.ok('{}{}{r} reconnected as {}{}{r}, restriction reapplied.'.format(IO.Fore.LIGHTYELLOW_EX, old_host.ip, IO.Fore.LIGHTYELLOW_EX, new_host.ip, r=IO.Style.RESET_ALL))

        self.bandwidth_monitor.replace(old_host, new_host)

    def _clear_handler(self, args):
        """
        Handler for the 'clear' command-line argument
        Clears the terminal window and re-prints the banner
        """
        IO.clear()
        IO.print(get_main_banner(self.version))
        self._print_help_reminder()

    def _help_handler(self, args):
        """
        Handles 'help' command-line argument
        Prints help message including commands and usage
        """
        views.print_help()

    def _quit_handler(self, args):
        self.interrupt_handler(False)
        self.stop()

    def _get_host_id(self, host, lock=True):
        ret = None

        if lock:
            self.hosts_lock.acquire()

        for i, host_ in enumerate(self.hosts):
            if host_ == host:
                ret = i
                break
        
        if lock:
            self.hosts_lock.release()

        return ret

    def _print_help_reminder(self):
        IO.print('type {Y}help{R} or {Y}?{R} to show command information.'.format(Y=IO.Fore.LIGHTYELLOW_EX, R=IO.Style.RESET_ALL))

    def _get_hosts_by_ids(self, ids_string):
        if ids_string == 'all':
            with self.hosts_lock:
                return self.hosts.copy()

        ids = ids_string.split(',')
        hosts = set()

        with self.hosts_lock:
            for id_ in ids:
                is_mac = netutils.validate_mac_address(id_)
                is_ip = netutils.validate_ip_address(id_)
                is_id_ = id_.isdigit()

                if not is_mac and not is_ip and not is_id_:
                    IO.error('invalid identifier(s): \'{}\'.'.format(ids_string))
                    return

                if is_mac or is_ip:
                    found = False
                    for host in self.hosts:
                        if host.mac == id_.lower() or host.ip == id_:
                            found = True
                            hosts.add(host)
                            break
                    if not found:
                        IO.error('no host matching {}{}{}.'.format(IO.Fore.LIGHTYELLOW_EX, id_, IO.Style.RESET_ALL))
                        return
                else:
                    id_ = int(id_)
                    if len(self.hosts) == 0 or id_ not in range(len(self.hosts)):
                        IO.error('no host with id {}{}{}.'.format(IO.Fore.LIGHTYELLOW_EX, id_, IO.Style.RESET_ALL))
                        return
                    hosts.add(self.hosts[id_])

        return hosts

    def _parse_direction_args(self, args):
        direction = Direction.NONE

        if args.upload:
            direction |= Direction.OUTGOING
        if args.download:
            direction |= Direction.INCOMING

        return Direction.BOTH if direction == Direction.NONE else direction

    def _parse_iprange(self, range):
        try:
            if '-' in range:
                return list(netaddr.iter_iprange(*range.split('-')))
            else:
                return list(netaddr.IPNetwork(range))
        except netaddr.core.AddrFormatError:
            return

    def _parse_scan_intensity(self, value):
        if value.isdigit() and int(value) in (ScanIntensity.QUICK, ScanIntensity.NORMAL, ScanIntensity.INTENSE):
            return int(value)

    def _free_host(self, host):
        """
        Stops ARP spoofing and unlimits host
        """
        if host.spoofed:
            self.arp_spoofer.remove(host)
            self.ndp_spoofer.remove(host)

            try:
                self.limiter.unlimit(host, Direction.BOTH)
            except LimitApplyError as e:
                # caught here (rather than left to propagate) since this
                # helper also runs during rescan/shutdown cleanup, where
                # a raised exception would skip the remaining teardown
                # steps below for every other host, not just this one
                IO.error('{}{}{r} restriction removal only partially succeeded: {}.'.format(IO.Fore.LIGHTYELLOW_EX, host.ip, ', '.join(e.failed_steps), r=IO.Style.RESET_ALL))

            self.bandwidth_monitor.remove(host)
            self.host_watcher.remove(host)
