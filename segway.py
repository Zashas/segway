#!/usr/bin/env python2.7
#coding: utf-8

"""
segway - Testing framework for IPv6 segment routing on Linux

Usage:
    segway.py <tests> [--ns=<ns_name>] [-k] [-r] [-p]
    segway.py (-h | --help)

Options:
    -h, --help  Show help
    --ns=<ns_name>  Use specific network space name
    -k              Keep network namespace after running tests
    -r              Reuse network namespace and interfaces
    -p              Show packets of passed tests
"""


from __future__ import print_function
from scapy.all import TunTapInterface, ETH_P_ALL
from docopt import docopt
import threading, sys, time, select

from ns import create_ns, use_ns, delete_ns, add_route, add_interfaces, NetNSError
from tests import TestSuite
from structs import Event

DEFAULT_NS_NAME = "segway"

sem_sniff = threading.Semaphore(0)

class Sniffer(threading.Thread):
    """ Asynchronous packet sniffer """

    running = True
    socket = None
    handler = None

    def __init__(self, *args, **kwargs):
        from scapy.config import conf

        kwargs['target'] = self.sniff
        iface = kwargs.pop('iface')
        self.handler = kwargs.pop('handler')
        self.socket = conf.L2listen(type=ETH_P_ALL, iface=iface)

        super(self.__class__, self).__init__(*args, **kwargs)

    def sniff(self):
        sem_sniff.release()

        while self.running:
            s = select.select([self.socket], [], [], 1)[0]
            if s:
                p = s[0].recv()
                self.handler(p.getlayer(1)) # Skipping Ethernet header

    def stop_and_join(self):
        self.running = False
        super(self.__class__, self).join()


def run(test_file, reuse_ns=False, keep_ns=False, ns=DEFAULT_NS_NAME, show_succeeded=False):
    if ns == None:
        ns = DEFAULT_NS_NAME

    if not reuse_ns:
        try:
            create_ns(ns)
        except OSError:
            print("Error : couldn't create a network namespace, are you root ?", file=sys.stderr)
            sys.exit(1)
        except NetNSError,e:
            print(e, file=sys.stderr)
            sys.exit(1)

    th = None
    try:
        if not reuse_ns:
            add_interfaces(ns)
            add_route(ns, "fc00::/16")
        use_ns(ns)

        try:
            suite = TestSuite(test_file)
        except SyntaxError: #could not parse tests
            return

        th = Sniffer(handler=suite.sniffing_handler, iface="dum0")
        th.start()
        
        sem_sniff.acquire()
        tun = TunTapInterface("tun0")

        while 1:
            try:
                e = suite.get_event()
            except LookupError:
                break
            if e.type == Event.PKT:
                tun.send(e.pkt)

        suite.sem_completed.acquire()
        th.stop_and_join()

        suite.show_results(show_succeeded=show_succeeded)
        
    finally:
        if th and th.running: #Stop the sniffing thread
            th.running = False

        if not keep_ns:
            delete_ns(ns)


if __name__ == '__main__':
    arguments = docopt(__doc__)
    if arguments['--help']:
        print(__doc__)
        sys.exit(0)

    run(arguments['<tests>'],
            reuse_ns=arguments['-r'], keep_ns=arguments['-k'],
            ns=arguments['--ns'], show_succeeded=arguments['-p'])
