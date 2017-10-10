#/usr/bin/env python2.7
#coding: utf-8

import threading, os

from structs import pkt_match, pkt_str, Event, NO_PKT
from parser import parse

class TestSuite:
    events = [] 
    cur_event_id = 0
    sem_receiving = threading.Semaphore(1) # Semaphore to wait on a RECV
    sem_completed = threading.Semaphore(0) # Semaphore to wait on when asking the suite to be completed

    answers = [] # (Received, Event)
    timer = None
    waiting_answer = False
    pkt_timer = 1.0

    def __init__(self, path, pkt_timer=None):
        if pkt_timer:
            self.pkt_timer = pkt_timer

        f = open(path, 'r')
        tests = f.read()
        f.close()
        self.events = parse(tests)

    def get_event(self):
        self.sem_receiving.acquire()

        if self.cur_event_id >= len(self.events):
            self.sem_completed.release()
            raise LookupError("No more events to process")


        e = self.events[self.cur_event_id]
        if e.type == Event.PKT:
            if e.expected_answer: #including NO_PKT
                self.waiting_answer = True
                self.timer = threading.Timer(self.pkt_timer, self.answer_timeout)
                self.timer.start()
            else:
                self.sem_receiving.release()
        else:
            self.sem_receiving.release()

        self.cur_event_id += 1

        return e

    def answer_timeout(self):
        e = self.events[self.cur_event_id-1]
        self.answers.append((NO_PKT, e))
        self.waiting_answer = False
        self.sem_receiving.release()

    def sniffing_handler(self, pkt):
        """ Process packets from the sniffer """

        if not self.waiting_answer:
            print("Dropped unexpected packet : {}".format(pkt_str(pkt)))
            return

        self.timer.cancel()
        e = self.events[self.cur_event_id-1]
        self.answers.append((pkt, e))
        self.waiting_answer = False
        self.sem_receiving.release()

    def show_results(self, show_succeeded=False):
        nb_ok, nb_nok, nb_miss = 0, 0, 0
        written = False

        for i,ans in enumerate(self.answers):
            recv, e = ans
            if recv == NO_PKT and e.expected_answer != NO_PKT:
                print("Packet #{} missing.".format(i+1))
                print("\tSent :     {}".format(pkt_str(e.pkt)))
                print("\tExpected : {}".format(pkt_str(e.expected_answer)))
                nb_miss += 1
                written = True
            elif not pkt_match(e.expected_answer, recv):
                print("Incorrect packet received instead of packet #{}.".format(i+1))
                print("\tSent :     {}".format(pkt_str(e.pkt)))
                print("\tExpected : {}".format(pkt_str(e.expected_answer)))
                print("\tReceived : {}".format(pkt_str(recv)))
                nb_nok += 1
                written = True

            else:
                nb_ok += 1
                if show_succeeded:
                    print("Packet #{} correctly received.".format(i+1))
                    print("\tSent :     {}".format(pkt_str(e.pkt)))
                    print("\tExpected : {}".format(pkt_str(e.expected_answer)))
                    print("\tReceived : {}".format(pkt_str(recv)))
                    written = True

        if written:
            print("")
        print("Statistics : {ok}/{nb} OK, {nok} incorrect, {miss} missing".format(ok=nb_ok, nb=len(self.answers), nok=nb_nok, miss=nb_miss))
