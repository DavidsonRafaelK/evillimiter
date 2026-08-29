import os
import configparser


def _default_paths():
    base = os.environ.get('XDG_CONFIG_HOME', os.path.expanduser('~/.config'))
    return [os.path.join(base, 'evillimiter', 'config.ini')]


def load_config(paths=None):
    """
    Reads optional user defaults from an ini file (the first of `paths`
    that exists; default ~/.config/evillimiter/config.ini, or the
    $XDG_CONFIG_HOME equivalent). Returns a dict of only the keys
    actually present - a missing or unreadable file returns {}, so
    every existing hardcoded default is unaffected unless a value is
    actually there.

    [general]
        interface, gateway_ip, gateway_mac, netmask, log_file - strings
        colorless - bool
    [watch]
        interval - int (seconds)
        range - string, same syntax as `watch set range` / -i CLI ranges
    """
    paths = _default_paths() if paths is None else paths
    parser = configparser.ConfigParser()

    if not parser.read(paths):
        return {}

    values = {}

    if parser.has_section('general'):
        general = parser['general']
        for key in ('interface', 'gateway_ip', 'gateway_mac', 'netmask', 'log_file'):
            if key in general:
                values[key] = general[key]
        if 'colorless' in general:
            values['colorless'] = general.getboolean('colorless')

    if parser.has_section('watch'):
        watch = parser['watch']
        if 'interval' in watch:
            values['watch_interval'] = watch.getint('interval')
        if 'range' in watch:
            values['watch_range'] = watch['range']

    return values
