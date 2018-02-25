#!/usr/bin/env python2.7
#coding: utf-8

"""
segway - Testing framework for IPv6 segment routing on Linux

Usage:
    segway.py <path_to_tests> [--ns=<ns_name>] [-t <time>] [-k] [-r] [-p]
    segway.py (-h | --help)

Options:
    -h, --help  Show help
    --ns <ns_name>  Use specific network space name
    -k              Keep network namespace after running tests
    -r              Reuse network namespace and interfaces
    -p              Show packets of passed tests
    -t <time>       Maximum time length in which a forwarding/reply to a packet can be expected, in seconds. Default: 1sec
"""


from __future__ import print_function
from scapy.all import TunTapInterface, ETH_P_ALL
from docopt import docopt
import threading, sys, select, subprocess, shlex

from ns import create_ns, use_ns, delete_ns, add_route, add_interfaces, NetNSError, add_dummy_if
from tests import TestSuite
from structs import Event

DEFAULT_NS_NAME = "segway"

class Sniffer(threading.Thread):
    """ Asynchronous packet sniffer """

    running = True
    socket = None
    handler = None
    iface = None
    sem_start = threading.Semaphore(0)

    def __init__(self, *args, **kwargs):
        from scapy.config import conf

        kwargs['target'] = self.sniff
        self.iface = kwargs.pop('iface')
        self.handler = kwargs.pop('handler')
        self.socket = conf.L2listen(type=ETH_P_ALL, iface=self.iface)

        super(self.__class__, self).__init__(*args, **kwargs)

    def sniff(self):
        self.sem_start.release()

        while self.running:
            s = select.select([self.socket], [], [], 1)[0]
            if s:
                p = s[0].recv()
                p = p.getlayer(1) # Skipping Ethernet header
                p.oif = self.iface
                self.handler(p) # Skipping Ethernet header

    def stop_and_join(self):
        self.running = False
        super(self.__class__, self).join()


def sniff_on(ifname, fct):
    th = Sniffer(handler=fct, iface=ifname)
    th.start()
    th.sem_start.acquire()

    return th

def run(test_file, reuse_ns=False, keep_ns=False, ns=DEFAULT_NS_NAME, show_succeeded=False, pkt_timer=None):
    if ns == None:
        ns = DEFAULT_NS_NAME

    if pkt_timer:
        try:
            pkt_timer = float(pkt_timer)
        except ValueError:
            print("Packet timer argument \"{}\" cannot be converted to float.".format(pkt_timer))

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
            suite = TestSuite(test_file, pkt_timer)
        except SyntaxError: #could not parse tests
            return

        tun = TunTapInterface("tun0")

        sniffers = {}
        sniffers['dum0'] = sniff_on('dum0', suite.sniffing_handler)

        while 1:
            try:
                e = suite.get_event()
            except LookupError:
                break
            if e.type == Event.PKT:
                tun.send(e.pkt)
            elif e.type == Event.CMD:
                subprocess.call(shlex.split(e.cmd))
            elif e.type == Event.OIF:
                if e.oif not in sniffers:
                    add_dummy_if(ns, e.oif)
                    sniffers[e.oif] = sniff_on(e.oif, suite.sniffing_handler)
                else:
                    print("{} interface already exists.", file=sys.stderr)

        suite.sem_completed.acquire()
        for oif, th in sniffers.items():
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

    run(arguments['<path_to_tests>'],
            reuse_ns=arguments['-r'], keep_ns=arguments['-k'],
            ns=arguments['--ns'], show_succeeded=arguments['-p'], pkt_timer=arguments['-t'])
