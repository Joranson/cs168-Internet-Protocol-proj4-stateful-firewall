#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
       
        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        # TODO: Also do some initialization if needed.

        self.rules = []
        with open(config['rule']) as f:
            self.rules = f.readlines()
        self.rules = [rule.rstrip().split(" ") for rule in self.rules if rule[0\
]=='p' or rule[0]=='d']
        for i in self.rules:
            print i
        print "Initialization finished"


    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.

        # The handler currently passes every packet regardless of rules.
        allowed = True
        if allowed:
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
            else:
                self.iface_ext.send_ip_packet(pkt)

    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.
