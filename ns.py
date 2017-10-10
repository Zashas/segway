#!/usr/bin/env python2
#coding: utf-8

from pyroute2 import netns, IPDB, NetNS
import subprocess

def create_ns(name):
    if name in netns.listnetns():
        raise NetNSError('Error : a network namespace "{}" already exists. Use the --ns or -r option.'.format(name))
    ns_name = name

    netns.create(ns_name)

def add_interfaces(ns_name):
    ip = IPDB(nl=NetNS(ns_name))

    with ip.interfaces.lo as lo:
        lo.up()
        lo.add_ip('fd00::42/48')

    
    # Creating tun interface in the NS, used for injecting
    ip.create(kind='tuntap', ifname="tun0", mode="tun").commit()
    with ip.interfaces.tun0 as tun0:
        tun0.up()

    ip.release()

    add_dummy_if(ns_name, "dum0")

def add_dummy_if(ns_name, name):
    ip = IPDB(nl=NetNS(ns_name))

    # Creating dummy interface in the NS, used for default sniffing
    ip.create(kind='dummy', ifname=name).commit()
    with ip.interfaces[name] as dum:
        dum.up()

    ip.release()

def use_ns(ns_name):
    netns.setns(ns_name)
    subprocess.Popen(["sysctl", "net.ipv6.conf.all.forwarding=1"], stdout=subprocess.PIPE)
    subprocess.Popen(["sysctl", "net.ipv6.conf.tun0.forwarding=1"], stdout=subprocess.PIPE)
    subprocess.Popen(["sysctl", "net.ipv6.conf.all.seg6_enabled=1"], stdout=subprocess.PIPE)
    subprocess.Popen(["sysctl", "net.ipv6.conf.tun0.seg6_enabled=1"], stdout=subprocess.PIPE)
    
def delete_ns(ns_name):
    netns.remove(ns_name)

def add_route(ns_name, rt):
    ip = IPDB(nl=NetNS(ns_name))
    ip.routes.add(dst=rt, oif=ip.interfaces.dum0.index).commit()

class NetNSError(Exception):
    pass

if __name__ == '__main__':

    try:
        create_ns("srt")
        
        add_route("fc00::/16")
        
        use_ns() 
        print(subprocess.check_output(['ip','-6', 'route']))

    finally:
        delete_ns()

