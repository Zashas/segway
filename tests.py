#/usr/bin/env python2.7
#coding: utf-8

import threading, os

from structs import pkt_match, pkt_str, Event
from parser import parse

class TestSuite:
    events = [] 
    cur_event_id = 0
    sem_receiving = threading.Semaphore(1) # Semaphore to wait on a RECV
    sem_completed = threading.Semaphore(0) # Semaphore to wait on when asking the suite to be completed

    answers = [] # (Received, Expected)
    timer = None
    waiting_answer = False

    def __init__(self, path):
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
            if e.expected_answer:
                self.waiting_answer = True
                self.timer = threading.Timer(1.0, self.answer_timeout)
                self.timer.start()
            else:
                self.sem_receiving.release()
        else:
            self.sem_receiving.release()

        self.cur_event_id += 1

        return e

    def answer_timeout(self):
        e = self.events[self.cur_event_id-1]
        self.answers.append((None, e.expected_answer))
        self.waiting_answer = False
        self.sem_receiving.release()

    def sniffing_handler(self, pkt):
        """ Process packets from the sniffer """

        if not self.waiting_answer:
            print("Dropped unexpected packet : {}".format(pkt_str(pkt)))
            return

        self.timer.cancel()
        e = self.events[self.cur_event_id-1]
        self.answers.append((pkt, e.expected_answer))
        self.waiting_answer = False
        self.sem_receiving.release()

    def show_results(self, show_succeeded=False):
        nb_ok, nb_nok, nb_miss = 0, 0, 0
        written = False

        for i,ans in enumerate(self.answers):
            recv, expect = ans
            if recv == None:
                print("Packet #{} missing.".format(i+1))
                print("\tExpected : {}".format(pkt_str(expect)))
                nb_miss += 1
                written = True
            elif not pkt_match(expect, recv):
                print("Incorrect packet received instead of packet #{}.".format(i+1))
                print("\tExpected : {}".format(pkt_str(expect)))
                print("\tReceived : {}".format(pkt_str(recv)))
                nb_nok += 1
                written = True

            else:
                nb_ok += 1
                if show_succeeded:
                    print("Packet #{} correctly received.".format(i+1))
                    print("\tExpected : {}".format(pkt_str(expect)))
                    print("\tReceived : {}".format(pkt_str(recv)))
                    written = True

        if written:
            print("")
        print("Statistics : {ok}/{nb} OK, {nok} incorrect, {miss} missing".format(ok=nb_ok, nb=len(self.answers), nok=nb_nok, miss=nb_miss))
