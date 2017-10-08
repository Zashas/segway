#coding: utf-8
from scapy.all import *

def pkt_match(expected, actual):
    """ Check if all fields described in packet `expected` match the fields of pkt `actual`' """

    fields = {
        IPv6: ('src', 'dst'),
        IPv6ExtHdrSegmentRouting: ('addresses', 'lastentry', 'segleft'),
        TCP: ('sport', 'dport'),
        UDP: ('sport', 'dport'),
        Raw: ('load',)
    }

    layer = 0
    while 1:
        sub_expected, sub_actual = expected.getlayer(layer), actual.getlayer(layer)

        if sub_expected.__class__ != sub_actual.__class__:
            return False

        if sub_actual == None: # Compared all layers
            return True

        if sub_actual.__class__ not in fields: # Unknown layer ..
            return False

        for field in fields[sub_expected.__class__]:
            # Don't care if field not set in expected packet
            if getattr(sub_expected, field) and \
                getattr(sub_expected, field) != getattr(sub_actual, field):
                    return False

        layer += 1

def pkt_str(pkt):
    _ = lambda x: x if x else "*"

    def srh_str(srh):
        segs = list(srh.addresses)
        if srh.segleft is not None and srh.segleft < len(segs):
            segs[srh.segleft] = "+"+segs[srh.segleft]

        return "[{}] <sl {}, le {}>".format(",".join(srh.addresses), srh.segleft, srh.lastentry)

    def ip_str(ip):
        return  "{} -> {}".format(_(ip.src), _(ip.dst))

    def udp_str(udp):
        if udp.sport or udp.dport:
            return "UDP({},{})".format(_(udp.sport), _(udp.dport))
        return "UDP"

    def tcp_str(tcp):
        if tcp.sport or tcp.dport:
            return "TCP({},{})".format(_(tcp.sport), _(tcp.dport))
        return "TCP"

    def payload_str(raw):
        return '"{}"'.format(raw.load)


    fcts = {
        IPv6: ip_str,
        IPv6ExtHdrSegmentRouting: srh_str,
        UDP: udp_str,
        TCP: tcp_str,
        Raw: payload_str
    }

    i = 0
    protos = []
    while 1:
        layer = pkt.getlayer(i)
        if layer == None:
            break
        elif layer.__class__ in fcts:
            protos.append(fcts[layer.__class__](layer))
        else:
            protos.append(layer.name)

        i += 1

    return " / ".join(protos)
    #"{src} -> {dst} [seg1,_seg2,seg3] <sl 1, le 2> / UDP(sport, dport) / \"payload\""

class Event:
    type = None
    completed = False
    blocking = False

    succeeded = False # Has only meaning for RECV
    timer = None

    route = None

    pkt = None
    answer = None
    expected_answer = None

    PKT = 1
    ADD_RT = 2
    DEL_RT = 3

    def __unicode__(self):
        return self.__str__()

    def __str__(self):
        if self.type == Event.PKT:
            s = "> {}".format(self.pkt)
            if self.expected_answer:
                s += "\n< {}".format(self.expected_answer)
            return s
        else:
            return "Unknown event"

    def __repr__(self):
        return self.__str__()