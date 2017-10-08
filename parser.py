#!/usr/bin/env python2.7
#coding: utf-8

import tatsu

from structs import Event
from scapy.all import IPv6, IPv6ExtHdrSegmentRouting, UDP, TCP, Raw

grammar = """

start = {operation}+ $ ;

operation = '>' pkt:packet '<' answer:packet
         | '<' pkt:packet
         | 'add route'
         | 'del route'
         | '#' {/\S/|' '}+;


packet = ip:ip6h '/' srh:srh '/' trans:trans '/' payload:payload
       | ip:ip6h '/' srh:srh '/' trans:trans
       | ip:ip6h '/' srh:srh
       | ip:ip6h '/' trans:trans '/' payload:payload
       | ip:ip6h '/' trans:trans
       | ip:ip6h;


ip6h = ip6_addr '->' ip6_addr;

srh = '[' ','%{ segs_active:seg_active segs:ip6_addr }+ ']' [options:srh_options];
srh_options = '<' ','%{names:word values:number}+ '>';

trans = proto:('UDP'|'TCP') ['(' sport:number ',' dport:number ')'];

payload = /"(.*?)"/;

seg_active = /\+?/;
ip6_addr = ( /([a-f]|\d|:)+/ | '*');

word = /\w+/;
number = /\d+/;
"""
# TODO add comments


model = tatsu.compile(grammar)

def parse(string):
    ast = model.parse(string)
    
    events = []

    for op in ast:
        e = Event()
        events.append(e)

        if "pkt" in op:
            e.type = Event.PKT
            e.pkt = parse_packet(op["pkt"])

            if "answer" in op:
                e.expected_answer = parse_packet(op["answer"])

    return events

def validate_ip6(addr):
    if addr == '*':
        return None

    return addr #TODO

def parse_packet(ast):
    pkt = IPv6()
    pkt.src = validate_ip6(ast['ip'][0])
    pkt.dst = validate_ip6(ast['ip'][2])

    if ast['srh']:
        srh = IPv6ExtHdrSegmentRouting()
        segs = []
        for i,seg in enumerate(ast['srh']['segs']):
            active = ast['srh']['segs_active'][i]

            if active == '+':
                if srh.segleft:
                    raise SyntaxError("Two segments have been defined as active.")
                srh.segleft = i

            segs.append(seg)
        srh.addresses = segs

        srh.lastentry = len(ast['srh']['segs'])-1

        if ast['srh']['options']:
            for i,name in enumerate(ast['srh']['options']['names']):
                val = ast['srh']['options']['values'][i]
                if name == "sl":
                    srh.segleft = int(val)
                elif name == "le":
                    srh.lastentry = int(val)

        pkt = pkt / srh

    if ast['trans']:
        proto = ast['trans']['proto']
        if proto == "UDP":
            transport = UDP()
        elif proto == "TCP":
            transport = TCP()

        transport.sport = int(ast['trans']['sport']) # TODO if ?
        transport.dport = int(ast['trans']['dport'])

        pkt = pkt / transport

    if ast['payload']:
        payload = Raw(ast['payload'][1:-1])
        pkt = pkt / payload

    return pkt


if __name__ == '__main__':
    s1 = "fc00::2 -> fc00::1 / [+fc00::1,fd00::42] <sl 0, le 2> / UDP(4242, 4242) / \"Coucou\""
    s4 = "fc00::2 -> fc00::1 / [fc00::1,fd00::42] <sl 0, le 2>"
    s5 = "> fc00::2 -> fc00::1 / [fc00::1,+fd00::42 ]"
    s6 = "> fc00::2 -> fc00::1"
    s = """> fc00::2 -> fc00::1 / [fc00::1, +fd00::42 ]
    > fc00::2 -> fc00::1 / [fc00::1,fd00::42] <sl 0, le 1>
> fc00::2 -> fc00::1 / [+fc00::1,fd00::42] <sl 0, le 2> / UDP(4242, 4242) / \"test\"
> fc00::2 -> fc00::1 / [+fc00::1,fd00::42] <sl 1, le 1> / UDP / \"Coucou\"
> fc00::2 -> *"""
    
    parse(s)
    

