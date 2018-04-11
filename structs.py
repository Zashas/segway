#coding: utf-8
from scapy.all import *

class WILDCARD:
    """ Used to indicate that some fields in a scapy packet should be ignored when comparing """
    pass

class NO_PKT:
    """ Indicate that a sent packet should have no reply """
    pass

def pkt_match(expected, actual):
    """ Check if all fields described in packet `expected` match the fields of pkt `actual`' """

    if expected == NO_PKT and actual == NO_PKT:
        return True
    elif expected == NO_PKT or actual == NO_PKT:
        return False

    if expected.oif != WILDCARD and expected.oif != actual.oif:
        # This can't be added to `fields` because it's not a proper scapy field
        return False

    fields = {
        IPv6: ('src', 'dst'),
        IPv6ExtHdrSegmentRouting: ('addresses', 'lastentry', 'segleft', 'tag',
            'unused1', 'protected', 'oam', 'alert', 'hmac', 'unused2'), # Flags
        IPv6ExtHdrSegmentRoutingTLVHMAC : ('hmac', 'keyid'),
        IPv6ExtHdrSegmentRoutingTLVIngressNode : ('ingress_node',),
        IPv6ExtHdrSegmentRoutingTLVEgressNode : ('egress_node',),
        IPv6ExtHdrSegmentRoutingTLVOpaque : ('container',),
        IPv6ExtHdrSegmentRoutingTLVPadding : ('len',),
        IPv6ExtHdrSegmentRoutingTLVNSHCarrier : ('nsh_object',),
        IPv6ExtHdrSegmentRoutingTLV : ('type', 'value'),
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
            if getattr(sub_expected, field) != WILDCARD and \
                getattr(sub_expected, field) != getattr(sub_actual, field):
                    return False

        layer += 1

def pkt_str(pkt):
    if pkt == NO_PKT:
        return "none"

    _ = lambda x: x if x != WILDCARD else "*"

    def srh_str(srh):
        from collections import OrderedDict

        segs = list(srh.addresses)
        if srh.segleft and srh.segleft < len(segs):
            segs[srh.segleft] = "+"+segs[srh.segleft]

        options = OrderedDict((('sl',srh.segleft), ('le',srh.lastentry)))

        if srh.tag:
            options['tag'] = srh.tag
        flags = ""
        fl_mapping = {'oam':'O', 'hmac':'H', 'alert':'A','protected':'P'} # TODO organiser selon draft
        for key,val in fl_mapping.items():
            if getattr(srh,key) == 1:
                flags += val

        if flags != "":
            options['fl'] = flags

        tlvs = []
        for tlv in srh.tlv_objects:
            if isinstance(tlv,IPv6ExtHdrSegmentRoutingTLVHMAC):
                tlvs.append('{{HMAC: {}, {}}}'.format(tlv.hmac.encode('hex'), tlv.keyid))
            elif isinstance(tlv,IPv6ExtHdrSegmentRoutingTLVPadding):
                tlvs.append('{{Pad: {}}}'.format(tlv.len))
            elif isinstance(tlv,IPv6ExtHdrSegmentRoutingTLVIngressNode):
                tlvs.append('{{Ingr: {}}}'.format(tlv.ingress_node))
            elif isinstance(tlv,IPv6ExtHdrSegmentRoutingTLVEgressNode):
                tlvs.append('{{Egr: {}}}'.format(tlv.egress_node))
            elif isinstance(tlv,IPv6ExtHdrSegmentRoutingTLVOpaque):
                tlvs.append('{{Opaq: {}}}'.format(tlv.container.encode('hex')))
            elif isinstance(tlv,IPv6ExtHdrSegmentRoutingTLVNSHCarrier):
                tlvs.append('{{NSH: {}}}'.format(tlv.nsh_object.encode('hex')))
            else:
                tlvs.append('{{Type:{} Value:{}}}'.format(tlv.type, tlv.value.encode('hex')))


        return "[{}] <{}>{}".format(",".join(segs), ",".join(map(lambda key: "{} {}".format(key, options[key]),options)), "" if not tlvs else " "+" ".join(tlvs))

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
        if raw.load == WILDCARD:
            return "*"
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
        elif isinstance(layer, IPv6ExtHdrSegmentRoutingTLV):
            pass
        elif layer.__class__ in fcts:
            protos.append(fcts[layer.__class__](layer))
        else:
            protos.append(layer.name)

        i += 1

    iface = ""
    if pkt.oif and pkt.oif != "dum0" and pkt.oif != WILDCARD:
        iface = "({}) ".format(pkt.oif)
    return iface+" / ".join(protos)

class Event:
    type = None

    cmd = None #only used if CMD

    pkt = None # only used if PKT
    answer = None
    expected_answer = None

    oif = None # only used if OIF

    PKT = 1
    CMD = 2
    OIF = 3

    def __unicode__(self):
        return self.__str__()

    def __str__(self):
        if self.type == Event.PKT:
            s = "> {}".format(self.pkt)
            if self.expected_answer:
                s += "\n< {}".format(self.expected_answer)
            return s
        elif self.type == Event.CMD:
            return "`"+self.cmd+"`"
        elif self.type == Event.OIF:
            return "if add {}".format(self.oif)
        else:
            return "Unknown event"

    def __repr__(self):
        return self.__str__()
