from evillimiter.console.io import IO


class Host(object):
    def __init__(self, ip, mac, name):
        self.ip = ip
        self.mac = mac
        self.name = name
        self.spoofed = False
        self.limited = False
        self.blocked = False
        self.watched = False

    def __eq__(self, other):
        return self.mac == other.mac

    def __hash__(self):
        return hash(self.mac)

    def reconnected_as(self, other):
        """
        True if `other` is a fresh scan result for this same physical
        device that has since moved to a different IP - the
        "reconnect" case watch.py looks for. False for the same host
        at an unchanged IP, and for any other/unrelated device.

        MAC is the only signal trusted for identity, matching
        __eq__/__hash__ above; a device that changes MAC (e.g. a
        randomized-MAC network) is, by design, not recognized as the
        same host reconnecting - see README Restrictions.
        """
        return self.mac == other.mac and self.ip != other.ip

    def pretty_status(self):
        if self.limited:
            return '{}Limited{}'.format(IO.Fore.LIGHTRED_EX, IO.Style.RESET_ALL)
        elif self.blocked:
            return '{}Blocked{}'.format(IO.Fore.RED, IO.Style.RESET_ALL)
        else:
            return 'Free'