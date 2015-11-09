#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import struct
import socket

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        self.debug = True
        
        self.rules = []
        with open(config['rule']) as f:
            self.rules = f.readlines()
        self.rules = [rule.rstrip().split() for rule in self.rules if rule[0:4]=='pass' or rule[0:4]=='drop']
        self.dnsRules = [elem for elem in self.rules if elem[1]=="dns" and ("*" not in elem[2] or ("*" in elem[2] and elem[2][0]=="*"))]

        for dnsRule in self.dnsRules:   # covert all domain names into lower cas:
            dnsRule[2] = dnsRule[2].lower()

        if self.debug:
            for i in self.rules:
                print i
                print "Initialization finished"
            for j in self.dnsRules:
                print "dnsRule:", j
                
        # Load the GeoIP DB
        self.geoDb = []
        with open('geoipdb.txt') as f:
            self.geoDb = f.readlines()
        self.geoDb = [(entry.rstrip()).split(' ') for entry in self.geoDb]
        self.geoHash = {}
        for entry in self.geoDb:
            self.geoHash[self.geoDb[2]] = [self.geoDb[0], self.geoDb[1]]


    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # Parse the pkt
        ## TODO: need to use socket.htons/socket.ntohs to convert endians
        pkt_info = {'ip_protocal':'', 'external_ip':'', 'external_port':''}
        pkt_info['ip_protocal'] = struct.unpack('!B', pkt[9])[0]

        ip_version =  struct.unpack('!B', pkt[0])[0] >> 4
        ip_header_len =  (struct.unpack('!B', pkt[0])[0] & 15) * 4
        # ip_header_len =  struct.unpack('!B', pkt[0])[0] & 7


        if self.debug:
            print "header version is", ip_version, "and header length is", ip_header_len
            print "the total length of packet is ", struct.unpack('!H', pkt[2:4])

        if pkt_info['ip_protocal'] == 6 or pkt_info['ip_protocal']==17:

            source_addr = self.intToDotQuad(struct.unpack('!L', pkt[12:16])[0])
            dest_addr = self.intToDotQuad(struct.unpack('!L', pkt[16:20])[0])

            source_port = struct.unpack('!H', pkt[ip_header_len:ip_header_len + 2])[0]
            dest_port = struct.unpack('!H', pkt[ip_header_len + 2:ip_header_len + 4])[0]

            if pkt_info['ip_protocal'] == 6:
                if self.debug:
                    print "TCP"
                    print "source ip address is", source_addr
                    print "destination ip address is", dest_addr
                    print "source port is", source_port
                    print "destination port is", dest_port

                if pkt_dir == PKT_DIR_INCOMING:
                    if self.debug:
                        print "incoming packet"
                    pkt_info['external_port'] = source_port
                    pkt_info['external_addr'] = source_addr
                    matchRes = self.proIpPortMatching(pkt_info)
                    if matchRes == "pass":
                        self.iface_int.send_ip_packet(pkt)
                else:
                    if self.debug:
                        print "outgoing packet"
                    pkt_info['external_port'] = dest_port
                    pkt_info['external_addr'] = dest_addr
                    matchRes = self.proIpPortMatching(pkt_info)
                    if matchRes == "pass":
                        self.iface_ext.send_ip_packet(pkt)
            else:
                if pkt_dir==PKT_DIR_OUTGOING and dest_port==53:     # treat only the udp portion of the pkt as the argument
#                    dnsQueryBool, dnsName = self.checkDnsQuery(pkt[ip_header_len:])
                    dnsQueryBool = False
                    if not dnsQueryBool:
                        if self.debug:
                            print "Normal UDP with port=53 and OUTGOING"
                    else:
                        if self.debug:
                            print "DNS query packet"
                        ## do something here
                        dns_matching_result = self.dnsMatching(dnsName)
                        if dns_matching_result=="pass":     ##TODO: check if it's the last rule
                            pass
                        elif dns_matching_result=="drop":
                            pass
                        else:
                            pass
                else:
                    if self.debug:
                        print "Normal UDP"
        elif pkt_info['ip_protocal'] == 1:
            if self.debug:
                print "ICMP"
        else:
            if self.debug:
                print "The potocal is", pkt_info['ip_protocal']


        print "-----------finished parsing-----------"

        # The handler currently passes every packet regardless of rules.
        allowed = True
        if allowed:
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
            else:
                self.iface_ext.send_ip_packet(pkt)

    def intToDotQuad(self, addr):
        dot_quad = []
        for i in range(4):
            dot_quad.append(addr % 256)
            addr = addr >> 8
        return list(reversed(dot_quad))

    def dotQuadToInt(self, quad):
        num = 0
        for i in quad:
            num += i
            num = num << 8
        num = num >> 8
        return num

    def proIpPortMatching(self, pkt_info):
        for rule in reversed(self.rules):
            if pkt_info['ip_protocal'] == rule[1]:
                if len(rule[2]) == 2:
                    # country code
                    lower, upper = self.geoHash(rule[2])
                    lowerBound = self.dotQuadToInt(lower)
                    upperBound = self.dotQuadToInt(upper)
                    ip_int_val = self.dotQaudToInt(pkt_info['external_addr'])
                    if ip_int_val <= upperBound and ip_int_val >= lowerBound:
                        if rule[3] == 'any':
                            return rule[0]
                        elif '-' in rule[3]:
                            lower, upper = rule[3].split('-')
                            lower, upper = int(lower), int(upper)
                            if pkt_info['external_port'] <= upper and pkt_info['external_port'] >= lower:
                                return rule[0]
                            else:
                                if pkt_info['external_port'] == int(rule[3]):
                                    return rule[0]
                    
                elif rule[2]  == 'any':
                    if rule[3] == 'any':
                        return rule[0]
                    elif '-' in rule[3]:
                        lower, upper = rule[3].split('-')
                        lower, upper = int(lower), int(upper)
                        if pkt_info['external_port'] <= upper and pkt_info['external_port'] >= lower:
                            return rule[0]
                        else:
                            if pkt_info['external_port'] == int(rule[3]):
                                return rule[0]
                else:
                    quad = rule[2].split('.')
                    if '/' in quad[3]:
                        # an IP prefix
                        offset = int(quad[3].split('/')[1])
                        if self.dotQuadToInt(quad) >> offset == pkt_info['external_ip'] >> offset:
                            if rule[3] == 'any':
                                return rule[0]
                            elif '-' in rule[3]:
                                lower, upper = rule[3].split('-')
                                lower, upper = int(lower), int(upper)
                                if pkt_info['external_port'] <= upper and pkt_info['external_port'] >= lower:
                                    return rule[0]
                            else:
                                if pkt_info['external_port'] == int(rule[3]):
                                    return rule[0]
                    else:
                        # a single IP address
                        if self.dotQuadToInt(quad) >> offset == pkt_info['external_ip']:
                            if rule[3] == 'any':
                                return rule[0]
                            elif '-' in rule[3]:
                                lower, upper = rule[3].split('-')
                                lower, upper = int(lower), int(upper)
                                if pkt_info['external_port'] <= upper and pkt_info['external_port'] >= lower:
                                    return rule[0]
                            else:
                                if pkt_info['external_port'] == int(rule[3]):
                                    return rule[0]

        return "pass"
                                    
    def dnsMatching(self, addr):        # make sure the dnsName are all in lower case
        addr_lst = addr.split(".")
        for j in range(1,len(self.dnsRules)):
            dnsRule = self.dnsRules[-j]
            dnsAddr_lst = dnsRule[2].split(".")
            matched = True
            if len(dnsAddr_lst)>len(addr_lst):
                break
            else:
                for i in range(1,len(dnsAddr_lst)):
                    if dnsAddr_lst[-i]=="*":
                        break
                    elif dnsAddr_lst[-i]!=addr[-i]:
                        matched = False
                        break
                if matched:
                    return dnsRule[0]
        return "no-match"    # self-defined third return value besides "pass" and "drop"

    def checkDnsQuery(self, pkt):
        udpLength = struct.unpack('!H', pkt[4:6])[0]
        dnsHeader = pkt[8:20]
        QDCOUNT = struct.unpack("!H", dnsHeader[4:6])[0]
        if QDCOUNT!=1:
            return [False, ""]
        j = 20
        dnsName = ""
        while j<udpLength:
            hex = struct.unpack("!B",pkt[udpLength+j])
            if struct.unpack("!B",pkt[udpLength+j])==0x00:
                j+=1
                break
            else:
                if (hex>=65 and hex<=90) or (hex>=97 and hex<=122) or hex==45:  # only alphabetic letters and hyphen are permitted as dns name
                    dnsName = dnsName+chr(hex)
                elif dnsName!="": # beginning of parsing, first hex number not letters/hyphens is just number of letters behind
                        dnsName = dnsName+"."       # adding dot
                j+=1
        dnsName = dnsName.lower()
        QTYPE = struct.unpack("!H", pkt[j:j+2])[0]
        QCLASS = struct.unpack("!H", pkt[j+2:j+4])
        if (QTYPE==1 or QTYPE==28) and QCLASS==1 and QDCOUNT==1:
            return True
        return [False, dnsName]







# TODO: You may want to add more classes/functions as well.

    # TODO: multiple rules are matched, use the last one

