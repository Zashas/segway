#!/usr/bin/env python2.7
#coding: utf-8

from __future__ import print_function
import tatsu, sys

from structs import Event, WILDCARD, NO_PKT
from scapy.all import IPv6, UDP, TCP, Raw, IPv6ExtHdrSegmentRouting, \
        IPv6ExtHdrSegmentRoutingTLVPadding, IPv6ExtHdrSegmentRoutingTLVHMAC, \
        IPv6ExtHdrSegmentRoutingTLVIngressNode, IPv6ExtHdrSegmentRoutingTLVEgressNode, \
        IPv6ExtHdrSegmentRoutingTLVNSHCarrier, IPv6ExtHdrSegmentRoutingTLVOpaque

grammar = """
start = {operation}+ $ ;

operation = '>' pkt:packet ['<' ['(' oif:alphanum ')'] answer:('none'|packet)]
         | 'if' 'add' oif:alphanum 
         | cmd:cmd
         | '#' {/\S/|' '}+;


packet = ip:ip6h srhs:{'/' srh }* '/' encap:packet
       | ip:ip6h srhs:{'/' srh }+ '/' trans:trans '/' payload:payload
       | ip:ip6h srhs:{'/' srh }+ '/' trans:trans
       | ip:ip6h srhs:{'/' srh }+
       | ip:ip6h '/' trans:trans '/' payload:payload
       | ip:ip6h '/' trans:trans
       | ip:ip6h;


ip6h = (ip6_addr|'*') '->' (ip6_addr|'*');

srh = '[' ','%{ segs_active:seg_active segs:ip6_addr }+ ']' [options:srh_options] tlvs:{ '{' (srh_tlv_ingr|srh_tlv_egr|srh_tlv_hmac|srh_tlv_pad|srh_tlv_opaque|srh_tlv_nsh) '}'}*;
srh_options = '<' ','%{names:word values:(number|srh_flags)}+ '>';
srh_flags = /(P|O|A|H)+/;
srh_tlv_pad = type:'Pad' ':' size:number;
srh_tlv_ingr = type:'Ingr' ':' ip:ip6_addr;
srh_tlv_egr = type:'Egr' ':' ip:ip6_addr;
srh_tlv_hmac = type:'HMAC' ':' keyid:number ',' hmac:alphanum; 
srh_tlv_opaque = type:'Opaq' ':' data:alphanum; 
srh_tlv_nsh = type:'NSH' ':' data:alphanum; 

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

    if ast['srhs']:
        for e in ast['srhs']:
            ast_srh = e[1]

            srh = IPv6ExtHdrSegmentRouting()
            segs = []
            segleft_set = False
            for i,seg in enumerate(ast_srh['segs']):
                active = ast_srh['segs_active'][i]

                if active == '+':
                    if segleft_set:
                        raise_parsing_error("two segments have been defined as active.")
                    srh.segleft = i
                    segleft_set = True

                segs.append(seg)
            srh.addresses = segs

            srh.lastentry = len(ast_srh['segs'])-1

            if ast_srh['options']:
                srh_opt = ast_srh['options']['names']
                srh_opt_val = ast_srh['options']['values']
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

            if ast_srh['tlvs']:
                for tlv in ast_srh['tlvs']:
                    tlv = tlv[1]
                    if tlv['type'] == 'Pad':
                        pad = IPv6ExtHdrSegmentRoutingTLVPadding()
                        pad_len = int(tlv['size'])
                        if pad_len < 1 or pad_len > 7:
                            raise_parsing_error("padding TLV's length must be between 1 and 7")

                        pad.len = pad_len
                        pad.padding = b"\x00"*pad.len
                        srh.tlv_objects.append(pad)

                    elif tlv['type'] == 'HMAC':
                        hmac = IPv6ExtHdrSegmentRoutingTLVHMAC()
                        hmac.keyid = int(tlv['keyid'])
                        try:
                            hmac.hmac = tlv['hmac'].decode('hex')
                        except TypeError:
                            raise_parsing_error("specified HMAC isn't provided in a hexadecimal representation")

                        srh.tlv_objects.append(hmac)

                    elif tlv['type'] == 'Ingr':
                        ingr = IPv6ExtHdrSegmentRoutingTLVIngressNode()
                        ingr.ingress_node = tlv['ip']
                        srh.tlv_objects.append(ingr)

                    elif tlv['type'] == 'Egr':
                        egr = IPv6ExtHdrSegmentRoutingTLVEgressNode()
                        egr.egress_node = tlv['ip']
                        srh.tlv_objects.append(egr)

                    elif tlv['type'] == 'Opaq':
                        opaq = IPv6ExtHdrSegmentRoutingTLVOpaque()
                        if len(tlv['data']) != 32:
                            raise_parsing_error("container for Opaque TLV must be 128 bits long")

                        try:
                            opaq.container = tlv['data'].decode('hex')
                        except TypeError:
                            raise_parsing_error("specified Opaque TLV container isn't provided in a hexadecimal representation")
                        srh.tlv_objects.append(opaq)
                    elif tlv['type'] == 'NSH':
                        nsh = IPv6ExtHdrSegmentRoutingTLVNSHCarrier()
                        try:
                            nsh.nsh_object = tlv['data'].decode('hex')
                            nsh.len = len(nsh.nsh_object)
                        except TypeError:
                            raise_parsing_error("specified NSH carried object isn't provided in a hexadecimal representation")
                        srh.tlv_objects.append(nsh)

                    else:
                        raise_parsing_error("unknown SRH TLV {}".format(tlv['type']))


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
> fc00::2 -> fc00::1 / [+fc00::1,fd00::42] <sl 1, le 1, fl H> {Pad: 8} {HMAC: 42, c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2} / UDP / \"Coucou\"
> fc00::2 -> *"""
    
    s7 = '> fc00::2 -> fc00::1 / [+fc00::1,fd00::42] <sl 1, le 1, fl H> {Pad: 6} {HMAC: 42, c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2} / UDP / \"Coucou\"'
    s8 = '> fc00::1 -> fc00::2 / [+fc00::3,fc00::2] {Ingr: fc00::2} {Egr: fc00::3} / UDP'
    parse(s8)

    

