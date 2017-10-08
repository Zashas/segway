#!/usr/bin/env python2.7
#coding: utf-8

from __future__ import print_function
import tatsu, sys

from structs import Event, WILDCARD
from scapy.all import IPv6, IPv6ExtHdrSegmentRouting, UDP, TCP, Raw

SRH_FLAGS = {'P':1, 'O':2, 'A':3, 'H':4}

grammar = """
start = {operation}+ $ ;

operation = '>' pkt:packet ['<' answer:packet]
         | 'add route'
         | 'del route'
         | '#' {/\S/|' '}+;


packet = ip:ip6h ['/' srh:srh] '/' encap:packet
       | ip:ip6h '/' srh:srh '/' trans:trans '/' payload:payload
       | ip:ip6h '/' srh:srh '/' trans:trans
       | ip:ip6h '/' srh:srh
       | ip:ip6h '/' trans:trans '/' payload:payload
       | ip:ip6h '/' trans:trans
       | ip:ip6h;


ip6h = ip6_addr '->' ip6_addr;

srh = '[' ','%{ segs_active:seg_active segs:ip6_addr }+ ']' [options:srh_options];
srh_options = '<' ','%{names:word values:(number|srh_flags)}+ '>';
srh_flags = /(P|O|A|H)+/;

trans = proto:('UDP'|'TCP') ['(' sport:('*'|number) ',' dport:('*'|number) ')'];

payload = '*'
        | /"(.*?)"/;

seg_active = /\+?/;
ip6_addr = ( /([a-f]|\d|:)+/ | '*');

word = /\w+/;
number = /\d+/;
"""

model = tatsu.compile(grammar)

def parse(string):
    try:
        ast = model.parse(string)
    except tatsu.exceptions.FailedParse as e:
        print("Error when parsing the following:", file=sys.stderr)
        msg = str(e).split('\n')
        print("\n".join(msg[1:3]), file=sys.stderr)
        raise SyntaxError
    
    events = []

    for op in ast:
        e = Event()
        events.append(e)

        if "pkt" in op:
            e.type = Event.PKT
            e.pkt = parse_packet(op["pkt"])

            if op["answer"]:
                e.expected_answer = parse_packet(op["answer"], for_comparison=True)

    return events

def raise_parsing_error(msg):
    print("Parsing error: "+m, file=sys.stderr)
    raise SyntaxError

def parse_packet(ast, for_comparison=False):
    if for_comparison:
        _ = lambda x: WILDCARD if x  == '*' else x
    else:
        _ = lambda x: raise_parsing_error("a wildcard (*) cannot be used in an injected packet.") if x == '*' else x

    pkt = IPv6()
    pkt.src = _(ast['ip'][0])
    pkt.dst = _(ast['ip'][2])

    if ast['srh']:
        srh = IPv6ExtHdrSegmentRouting()
        segs = []
        for i,seg in enumerate(ast['srh']['segs']):
            active = ast['srh']['segs_active'][i]

            if active == '+':
                if srh.segleft:
                    raise_parsing_error("two segments have been defined as active.")
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
                elif name == "tag":
                    srh.tag = int(val)
                elif name == "fl":
                    for letter in val:
                        if letter == "P":
                            srh.protected = 1
                        elif letter == "O":
                            srh.oam = 1
                        elif letter == "A":
                            srh.alert = 1
                        elif letter == "H":
                            srh.hmac = 1
                else:
                    raise_parsing_error("unknown SRH option {}".format(name))

        pkt = pkt / srh

    if ast['encap']:
        return pkt / parse_packet(ast['encap'], for_comparison=for_comparison)

    if ast['trans']:
        proto = ast['trans']['proto']
        if proto == "UDP":
            transport = UDP()
        elif proto == "TCP":
            transport = TCP()

        transport.sport, transport.dport = 0,0
        if ast['trans']['sport']:
            p = _(ast['trans']['sport'])
            transport.sport = int(p) if p != WILDCARD else p

        if ast['trans']['dport']:
            p = _(ast['trans']['dport'])
            transport.dport = int(p) if p != WILDCARD else p

        pkt = pkt / transport

    if ast['payload']:
        if ast['payload'] == '*':
            pkt = pkt / Raw('') # Dirty hack, we suppose that an empty payload matches everything ..
            pkt[Raw].load = WILDCARD
        else:
            pkt = pkt / Raw(ast['payload'][1:-1])

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
    

