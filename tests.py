#/usr/bin/env python2.7
#coding: utf-8

import threading
from scapy.all import *
from scapy.all import Packet as ScapyPacket

class Packet:
    ip_src, ip_dst, ip_segs = None, None, None
    ip_segleft, ip_lastseg = None, None
    l4_proto = None
    dport, sport = None, None
    payload = None

    _fields = ("ip_src", "ip_dst", "ip_segs", "ip_segleft", "ip_lastseg",
               "l4_proto", "dport", "sport", "payload")

    def __init__(self, *args, **kwargs):
        if len(args) > 0 and len(kwargs) > 0 or len(args) > 1:
            raise ValueError("Either pass a scapy packet or keyword arguments")

        if len(args) == 1:
            p = args[0]
            if p.haslayer(IPv6):
                self.ip_src = p[IPv6].src
                self.ip_dst = p[IPv6].dst
            if p.haslayer(IPv6ExtHdrSegmentRouting):
                self.ip_segs = p[IPv6ExtHdrSegmentRouting].addresses
                self.ip_segleft = p[IPv6ExtHdrSegmentRouting].segleft
                self.ip_lastseg = p[IPv6ExtHdrSegmentRouting].lastentry

            if p.haslayer(UDP):
                self.l4_proto = UDP # TODO keep this ? make enum
                self.dport = p[UDP].dport
                self.sport = p[UDP].sport

            if p.haslayer(Raw):
                self.payload = p[Raw].load
        else:
            for key,val in kwargs.items():
                if key in self._fields:
                    setattr(self, key, val)

    def build(self):
        """ Build a scapy packet """

        pkt = Raw("")
        if self.payload:
            pkt = Raw(self.payload)
        if self.l4_proto:
            pkt = self.l4_proto(sport=self.sport, dport=self.dport) / pkt
        if self.ip_segs:
            srh = IPv6ExtHdrSegmentRouting(addresses=self.ip_segs,
                                           segleft=self.ip_segleft, lastentry=self.ip_lastseg)
            pkt = srh / pkt

        ip = IPv6(src=self.ip_src, dst=self.ip_dst)

        return ip / pkt

    def match(self, pkt):
        """ Check if all fields described in this packet match the fields of `pkt`' """

        if isinstance(pkt, ScapyPacket):
            pkt = Packet(pkt)
        
        for f in self._fields:
            if getattr(self, f) != None and getattr(self, f) != getattr(pkt, f):
                return False

        return True


    def __str__(self):
        _ = lambda x: x if x else "*"

        ip = "{} -> {}".format(_(self.ip_src), _(self.ip_dst))
        protos = [ip]

        if self.ip_segs:
            ip_segs = self.ip_segs[:]
            if self.ip_segleft is not None and self.ip_segleft < len(ip_segs):
                ip_segs[self.ip_segleft] = "+"+ip_segs[self.ip_segleft]

            srh = "[{}] <sl {}, le {}>".format(",".join(ip_segs), self.ip_segleft, self.ip_lastseg)
            protos.append(srh)

        if self.l4_proto:
            l4 = "L4"
            if self.l4_proto == UDP:
                l4 = "UDP({}, {})".format(_(self.sport), _(self.dport))

            protos.append(l4)

            if self.payload:
                protos.append('"{}"'.format(self.payload))

        return " / ".join(protos)
        #"{src} -> {dst} [seg1,_seg2,seg3] <sl 1, le 2> / UDP(sport, dport) / \"payload\""

    def __unicode__(self):
        return self.__str__()

class Event:
    type = None
    completed = False
    blocking = False

    succeeded = False # Has only meaning for RECV
    timer = None

    pkt, route= None, None
    pkt_recv = None

    SEND = 1
    RECV = 2
    ADD_RT = 3
    DEL_RT = 4


class TestSuite:
    events = [] #Un event peut être une action
    cur_event_id = 0
    completed_events = 0
    completed = False
    firing_events = True
    sem_actions = threading.Semaphore(0) # Semaphore for available events to be fired
    sem_completed = threading.Semaphore(0) # Semaphore to wait on when asking the suite to be completed
    timer = None

    def __init__(self, f):
        pkt = Packet()
        pkt.ip_src = "fc00::2"
        pkt.ip_dst = "fd00::42"
        pkt.ip_segs = ["fc00::1", "fd00::42"]
        pkt.ip_lastseg = 2
        pkt.ip_segleft = 1
        pkt.payload = "Coucou"
        pkt.dport = 4242
        pkt.sport = 4242
        pkt.l4_proto = UDP

        pkt2 = Packet(ip_dst="fc00::2")

        e1 = Event()
        e1.type = Event.SEND
        e1.pkt = pkt

        e2 = Event()
        e2.type = Event.RECV
        e2.pkt = pkt2

        self.events = [e1, e2]
        self.sem_actions.release()

    def get_event(self):
        if not self.firing_events:
            raise LookupError("No more events to process")

        self.sem_actions.acquire()

        ret = None
        while self.firing_events:
            e = self.events[self.cur_event_id]

            if e.type in (Event.SEND, Event.ADD_RT, Event.DEL_RT):
                self.event_succeeded(self.cur_event_id)
                self.sem_actions.release()
                ret = e
            elif e.type == Event.RECV:
                e.timer = threading.Timer(1.0, lambda: self.event_failed(self.cur_event_id))
                e.timer.start()

            if self.cur_event_id+1 == len(self.events):
                self.firing_events = False
            else:
                self.cur_event_id += 1
            
            if ret:
                return ret

        raise LookupError("No more events to process")

    
    def sniffing_handler(self, pkt):
        """ Process packets from the sniffer """

        if self.completed_events == self.cur_event_id: #synchronous mode
            e = self.events[self.cur_event_id]
            if e.type == Event.RECV and not e.completed:
                e.pkt_recv = Packet(pkt)
                if e.pkt.match(pkt):
                    self.event_succeeded(self.cur_event_id)
                else:
                    self.event_failed(self.cur_event_id)
            else: # we're not expecting a packet
                print("Dropped unexpected packet : {}".format(str(Packet(pkt))))

        else: # asynchronous mode, we are expecting several packets in an undefined order
            for i in range(self.completed_events, self.cur_event_id+1):
                e = self.events[i]
                if e.type == Event.RECV and not e.completed:
                    if e.pkt.match(pkt):
                        self.event_succeeded(i)
                        e.pkt_recv = Packet(pkt)
                        return

            print("Dropped unexpected packet : {}".format(str(Packet(pkt))))

                    
    def event_succeeded(self, i):
        self.events[i].succeeded = True
        self.event_completed(i)

    def event_failed(self, i):
        self.events[i].succeeded = False
        self.event_completed(i)

    def event_completed(self, i):
        e = self.events[i]

        if e.completed:
            return

        e.completed = True
        if e.timer:
            e.timer.cancel()

        new_completed_events = 1
        if self.completed_events == i:
            for k in range(self.completed_events+1, self.cur_event_id+1):
                if self.events[k].succeeded:
                    new_completed_events += 1
                else:
                    break

        if e.blocking:
            keep_blocking = False
            for k in range(self.completed_events+1, self.completed_events+new_completed_events):
                if self.events[k].blocking:
                    keep_blocking = True
                    break

            if not keep_blocking:
                self.sem_actions.release()

        self.completed_events += new_completed_events
        if self.completed_events == len(self.events):
            self.sem_completed.release()

    def show_results(self, show_succeeded=False):
        nb_recv = 0
        nb_ok, nb_nok, nb_miss = 0, 0, 0
        for i, e in enumerate(self.events):
            if e.type == Event.RECV:
                if not e.succeeded:
                    if not e.pkt_recv:
                        print("Missing packet.")
                        print("\tExpected : {}".format(str(e.pkt)))
                        nb_miss += 1
                    else:
                        print("Incorrect packet received instead of packet #{}.".format(nb_recv+1))
                        print("\tExcepted : {}".format(str(e.pkt)))
                        print("\tReceived : {}".format(str(e.pkt_recv)))
                        nb_nok += 1
                else:
                    nb_ok += 1
                    if show_succeeded:
                        print("Packet #{} correctly received.".format(n))
                        print("\tExpected : {}".format(str(e.pkt)))
                        print("\tReceived : {}".format(str(e.pkt_recv)))

                nb_recv += 1

        print("Statistics : {ok}/{nb} OK, {nok}/{nb} incorrect, {miss}/{nb} missing".format(ok=nb_ok, nb=nb_recv, nok=nb_nok, miss=nb_miss))
