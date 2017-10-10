#!/usr/bin/env python2.7
#coding: utf-8

from __future__ import print_function
import tatsu, sys

from structs import Event, WILDCARD, NO_PKT
from scapy.all import IPv6, IPv6ExtHdrSegmentRouting, UDP, TCP, Raw

grammar = """
start = {operation}+ $ ;

operation = '>' pkt:packet ['<' ['(' oif:alphanum ')'] answer:('none'|packet)]
         | 'if' 'add' oif:alphanum 
         | cmd:cmd
         | '#' {/\S/|' '}+;


packet = ip:ip6h ['/' srh:srh] '/' encap:packet
       | ip:ip6h '/' srh:srh '/' trans:trans '/' payload:payload
       | ip:ip6h '/' srh:srh '/' trans:trans
       | ip:ip6h '/' srh:srh
       | ip:ip6h '/' trans:trans '/' payload:payload
       | ip:ip6h '/' trans:trans
       | ip:ip6h;


ip6h = (ip6_addr|'*') '->' (ip6_addr|'*');

srh = '[' ','%{ segs_active:seg_active segs:ip6_addr }+ ']' [options:srh_options];
srh_options = '<' ','%{names:word values:(number|srh_flags)}+ '>';
srh_flags = /(P|O|A|H)+/;

trans = proto:('UDP'|'TCP') ['(' sport:('*'|number) ',' dport:('*'|number) ')'];

payload = '*'
        | /"(.*?)"/;

cmd = /`([^`]+)`/;

seg_active = /\+?/;
ip6_addr = /([a-f]|\d|:)+/;
ip6_subnet = /([a-f]|\d|:)+\/\d{1,3}/
           | ip6_addr;

word = /\w+/;
number = /\d+/;
alphanum = /[a-zA-Z0-9_]+/;
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

        if op['pkt']:
            e.type = Event.PKT
            e.pkt = parse_packet(op["pkt"])
            e.pkt.oif = None

            if op["answer"]:
                e.expected_answer = parse_packet(op["answer"], for_comparison=True)

                if op["oif"]:
                    e.expected_answer.oif = op["oif"]
                else:
                    e.expected_answer.oif = WILDCARD
        elif op['cmd']:
            e.cmd = op['cmd'][1:-1] # stripping both `
            e.type = Event.CMD
        elif op['oif']:
            e.type = Event.OIF
            e.oif = op['oif']

    return events

def raise_parsing_error(msg):
    print("Parsing error: "+msg, file=sys.stderr) # TODO add file and line number to message
    raise SyntaxError

def parse_packet(ast, for_comparison=False):
    if for_comparison:
        _ = lambda x: WILDCARD if x  == '*' else x
    else:
        _ = lambda x: raise_parsing_error("a wildcard (*) cannot be used in an injected packet.") if x == '*' else x

    if ast == 'none':
        return NO_PKT

    pkt = IPv6()
    pkt.src = _(ast['ip'][0])
    pkt.dst = _(ast['ip'][2])

    if ast['srh']:
        srh = IPv6ExtHdrSegmentRouting()
        segs = []
        segleft_set = False
        for i,seg in enumerate(ast['srh']['segs']):
            active = ast['srh']['segs_active'][i]

            if active == '+':
                if segleft_set:
                    raise_parsing_error("two segments have been defined as active.")
                srh.segleft = i
                segleft_set = True

            segs.append(seg)
        srh.addresses = segs

        srh.lastentry = len(ast['srh']['segs'])-1

        if ast['srh']['options']:
            srh_opt = ast['srh']['options']['names']
            srh_opt_val = ast['srh']['options']['values']
            if isinstance(srh_opt, str) or isinstance(srh_opt, unicode):
                srh_opt = (srh_opt,)
                srh_opt_val = (srh_opt_val,)

            for i,name in enumerate(srh_opt):
                val = srh_opt_val[i]
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
            pkt = pkt / Raw('')
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
    

