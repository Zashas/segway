#!/usr/bin/env python2.7
#coding: utf-8

import tatsu

from tests import Packet, Event

grammar = """

start = {operation}+ $ ;

operation = '>' packet
         | '<' packet
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


model = tatsu.compile(grammar)

def parse(string):
    ast = model.parse(string)
    
    events = []

    for op in ast:
        e = Event()
        events.append(e)

        if op[0] == ">":
            e.type = Event.SEND
            e.pkt = parse_packet(op[1])
        elif op[1] == "<":
            e.type = Event.RECV
            e.pkt = parse_packet(op[1])

    return events

def validate_ip6(addr):
    if addr == '*':
        return None

    return addr #TODO

def parse_packet(ast):
    pkt = Packet()
    pkt.ip_src = validate_ip6(ast['ip'][0])
    pkt.ip_dst = validate_ip6(ast['ip'][2])

    if ast['srh']:
        pkt.ip_segs = []
        for i,seg in enumerate(ast['srh']['segs']):
            active = ast['srh']['segs_active'][i]

            if active == '+':
                if pkt.ip_segleft:
                    raise SyntaxError("Two segments have been defined as active.")
                pkt.ip_segleft = i

            pkt.ip_segs.append(seg)

        pkt.ip_lastseg = len(ast['srh']['segs'])-1

        if ast['srh']['options']:
            for i,name in enumerate(ast['srh']['options']['names']):
                val = ast['srh']['options']['values'][i]
                if name == "sl":
                    pkt.ip_segleft = val
                elif name == "le":
                    pkt.ip_lastseg = val

    if ast['trans']:
        pkt.l4_proto = ast['trans']['proto']
        pkt.sport = ast['trans']['sport']
        pkt.dport = ast['trans']['dport']

    if ast['payload']:
        pkt.payload = ast['payload'][1:-1]
    print(str(pkt))

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
    

