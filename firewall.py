#!/usr/bin/env python
import re

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import struct
import socket


# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        self.debug = False

        self.ipv4ProHash = {1:'icmp', 6:'tcp', 17:'udp'}
        
        self.RawRules = []
        with open(config['rule']) as f:
            self.RawRules = f.readlines()
        self.rules = []     # store only valid rules
        for rule in self.RawRules:
            rule = rule.rstrip().split()
            rule = [r.lower() for r in rule]
            if len(rule)<3:
                continue
            if rule[0]=="deny" or rule[0]=="log":
                if rule[1]=="dns" and len(rule)==3:
                    if "*" not in rule[2] or ("*" in rule[2] and rule[2][0]=="*"):
                        rule[2] = rule[2].lower()  # covert all domain names into lower case
                        self.rules.append(rule)
                else:
                    if len(rule)!=4:
                        continue
                    self.rules.append(rule)

        if self.debug:
            for i in self.rules:
                print i
                print "Initialization finished"
                
        ## Load the GeoIP DB  --  no GeoIP for Project 4. //TODO: clean everything related to GeoIp
        self.geoDb = []
        with open('geoipdb.txt') as f:
            self.geoDb = f.readlines()

        ## create a dictionary to store {unique_id: tcp_payload} for reassembly TCP
        self.reassembly = {}
        ## create a dictionary to store {unique_id: expected_seq} for reassembly TCP
        self.expected_seq = {}
        ## CRLF, which is "\r\n\r\n"
        self.crlf = (struct.pack("!B",13)+struct.pack("!B",10))*2
        ##
        self.parsedHeader = {}
        # temporary http_request_info backup
        self.http_request_info = {}

    def create_ip_deny_packet_header(self, source_addr, dest_addr, ip_protocol, total_length):
        if self.debug:
            print "constructing ip header"
        ip_version_ihl = (4 << 4) + 5
        ip_tos = 0
        ip_total_len = total_length
        ip_iden = 0
        ip_flags_frag_offset = 0
        ip_ttl_proto = (1 << 8) + ip_protocol
        ip_checksum = 0
        
        new_pkt = struct.pack('!B', ip_version_ihl) + struct.pack('!B', ip_tos) + struct.pack('!H', ip_total_len) + struct.pack('!H', ip_iden) + struct.pack('!H', ip_flags_frag_offset)+struct.pack('!H', ip_ttl_proto)+struct.pack('!H', ip_checksum)+source_addr+dest_addr

        if self.debug:
            print "ip version", struct.unpack('!B', new_pkt[0])[0] >> 4
            print "ip header length", (struct.unpack('!B', new_pkt[0])[0] & 15) * 4
            print "the total length of packet is ", struct.unpack('!H', new_pkt[2:4])
        # Compute checksum
        all_sum = 0
        print "length of pkt is", len(new_pkt)
        for i in range(10):
            all_sum += struct.unpack('!H', new_pkt[2*i:2*i+2])[0]
        all_sum -= struct.unpack('!H', new_pkt[10:12])[0]
        while all_sum > (2**16 - 1):
            all_sum = all_sum % (2**16) + (all_sum >> 16)
        computed_checksum = all_sum ^ (2**16 - 1)
        
        new_pkt = new_pkt[:10] + struct.pack('!H', computed_checksum) + new_pkt[12:]
        return new_pkt

    def create_dns_deny_packet(self, source_addr, dest_addr, source_port, dest_port, ip_pkt, ip_header_len):
        pkt = ip_pkt[ip_header_len:]
        if self.debug:
            print "constructing IP header for DNS deny packet"
        old_dnsHeader = pkt[8:20]
        old_AA = struct.unpack('!H', old_dnsHeader[2:4])[0] & (((2**5-1)<<11)+(2**10-1))
        old_RD_and_RA = struct.unpack('!H', old_dnsHeader[2:4])[0] & (((2**7-1)<<9)+(2**7-1))
        dns_header_QR_to_RCODE = struct.pack("!H",(1<<15) + old_AA + old_RD_and_RA)
            #     For DNS header:
            # a) copy ID as is
            # b) QR = 1, Opcode = 0, AA = as is, TC = 0, RD = as is, RA = as is, RCODE = 0
            # c) QDCount = as is (1)
            # d) ANCOUNT = 1
            # e) NSCOUNT, ARCOUNT = 0
        new_dnsHeader = old_dnsHeader[:2] + dns_header_QR_to_RCODE + old_dnsHeader[4:6] + struct.pack("!H", 1) + struct.pack("!H", 0) + struct.pack("!H", 0)
        old_udpLength = struct.unpack('!H', pkt[4:6])[0]
        j = self.getQName(pkt, old_udpLength)[1]
        new_dnsQuestion = pkt[20:j+4]
        answer_name = pkt[20:j]
        answer_type = struct.pack("!H", 1)
        answer_class = struct.pack("!H", 1)
        answer_ttl = struct.pack("!L", 1)
        answer_RDlength = struct.pack("!H", 4)
        answer_RData = struct.pack("!B", 169)+struct.pack("!B", 229)+struct.pack("!B", 49)+struct.pack("!B", 130)
        new_dnsAnswer = answer_name+answer_type+answer_class+answer_ttl+answer_RDlength+answer_RData

        udp_length = j+4+(j-20)+2*7 ## TODO: compute this later
        udp_checksum = 0
        new_udp_header = source_port+dest_port+struct.pack("!H", udp_length)+struct.pack("!H", udp_checksum)
        ip_header = self.create_ip_deny_packet_header(source_addr, dest_addr, 17, ip_header_len+udp_length)
        return ip_header+new_udp_header+new_dnsHeader+new_dnsQuestion+new_dnsAnswer


    def create_tcp_deny_packet(self, source_addr, dest_addr, source_port, dest_port, ack_no):
        ip_header = self.create_ip_deny_packet_header(source_addr, dest_addr, 6, 40)

        if self.debug:
            print "constructing tcp header"

        ip_proto = 6
        tcp_header_len = 20
        tcp_seq_no = 0
        tcp_offset_res_flags = (5 << 12) + 20
        tcp_window = 0
        tcp_checksum = 0
        tcp_urgent_pointer = 0
        
        tcp_header = source_port + dest_port + struct.pack('!L', tcp_seq_no) + ack_no + struct.pack('!H', tcp_offset_res_flags) + struct.pack('!H', tcp_window) + struct.pack('!H', tcp_checksum) + struct.pack('!H', tcp_urgent_pointer)
        psuedo_tcp_header = source_addr + dest_addr + struct.pack('!H', ip_proto) + struct.pack('!H', tcp_header_len) + tcp_header

        if self.debug:
            print "tcp header length", len(tcp_header)
            print "tcp flag is", struct.unpack('!H', psuedo_tcp_header[24:26])[0] & 15
            print "tcp source port is", struct.unpack('!H', psuedo_tcp_header[12:14])[0]
            print "tcp destination port is", struct.unpack('!H', psuedo_tcp_header[14:16])[0]
        
        # compute tcp checksum
        all_sum = 0
        for i in range(15):
            all_sum += struct.unpack('!H', psuedo_tcp_header[2*i:2*i+2])[0]
        all_sum -= struct.unpack('!H', psuedo_tcp_header[28:30])[0]
        print "checksum subtracted:", struct.unpack('!H', psuedo_tcp_header[28:30])[0]
        while all_sum > (2**16 - 1):
            all_sum = all_sum % (2**16) + (all_sum >> 16)
        computed_checksum = all_sum ^ (2**16 - 1)
        tcp_header = tcp_header[:16] + struct.pack('!H', computed_checksum) + tcp_header[18:];

        return ip_header + tcp_header

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
            print "the total length of packet is", struct.unpack('!H', pkt[2:4])[0]
            print "checksum is", struct.unpack('!H', pkt[10:12])[0]
            
        source_addr_str = pkt[12:16]
        source_addr = self.intToDotQuad(struct.unpack('!L', source_addr_str)[0])
        dest_addr_str = pkt[16:20]
        dest_addr = self.intToDotQuad(struct.unpack('!L', dest_addr_str)[0])

        if pkt_info['ip_protocal'] == 6 or pkt_info['ip_protocal']==17:

            source_port_str = pkt[ip_header_len:ip_header_len + 2]
            source_port = struct.unpack('!H', source_port_str)[0]
            dest_port_str = pkt[ip_header_len + 2:ip_header_len + 4]
            dest_port = struct.unpack('!H', dest_port_str)[0]

            if pkt_info['ip_protocal'] == 6:
                if self.debug:
                    print "-------------------------TCP"
                    print "source ip address is", source_addr
                    print "destination ip address is", dest_addr
                    print "source port is", source_port
                    print "destination port is", dest_port
                if pkt_dir == PKT_DIR_INCOMING:
                    if self.debug:
                        print "incoming packet"
                    pkt_info['external_port'] = source_port
                    pkt_info['external_ip'] = source_addr
                    matchRes = self.proIpPortMatching(pkt_info)     # check TCP deny
                    if self.debug:
                        print "+++++++++++++++++++incoming packet rule matching result says,", matchRes
                    if matchRes == "pass":
                        if pkt_info['external_port']==80:    ## handle logging here if external port is 80
                            tcp_header_len = (struct.unpack("!B", pkt[ip_header_len+12])[0]>>4) *4  ## tcp header size in Byte
                            ip_total_len = struct.unpack("!H", pkt[2:4])[0]
                            # if ip_total_len>ip_header_len+tcp_header_len:  ## there is payload related to TCP connection, which means there is http texts inside
                            tcp_payload_len = ip_total_len-ip_header_len-tcp_header_len
                            tcp_payload = pkt[ip_header_len+tcp_header_len:]
                            seq_num = struct.unpack("!L",pkt[ip_header_len+4:ip_header_len+8])[0]
                            expected_next_seq_num = seq_num+tcp_payload_len
                            unique_id = (self.dotQuadToInt(source_addr), self.dotQuadToInt(dest_addr), source_port, dest_port)
                            if unique_id not in self.expected_seq or (unique_id in self.expected_seq and seq_num<=self.expected_seq[unique_id]): # pass pkt
                                self.iface_int.send_ip_packet(pkt)
                                if unique_id not in self.expected_seq:
                                    isSynSet = (struct.unpack("!B", pkt[ip_header_len+13:ip_header_len+14])[0]>>1)&1
                                    if isSynSet:
                                        self.expected_seq[unique_id] = seq_num+1  # special case for handshake, only allow once
                                elif unique_id in self.expected_seq and seq_num==self.expected_seq[unique_id]: # actual reassembling
                                    self.expected_seq[unique_id] = expected_next_seq_num
                                    if unique_id not in self.parsedHeader or self.parsedHeader[unique_id]==False:
                                        if unique_id in self.reassembly:
                                            self.reassembly[unique_id]+=tcp_payload
                                        else:
                                            self.reassembly[unique_id]=tcp_payload
                                    if self.crlf in self.reassembly[unique_id]:
                                        print "##############INGOING################", self.reassembly[unique_id]
                                        retrieveInfo = self.retrieveInfo(self.reassembly[unique_id], False, pkt_info['external_ip'])  # this is an INCOMING pkt--> response msg
                                        print "---------------> retrieved info: ", retrieveInfo
                                        reverse_unique_id = (unique_id[1],unique_id[0], unique_id[3], unique_id[2])
                                        self.parsedHeader[unique_id] = True     ## stop adding http body data into self.reassembly
                                        self.parsedHeader[reverse_unique_id] = False    ## now okay to receive http request header
                                        http_request_info = self.http_request_info[reverse_unique_id]
                                        if self.hostMatching(http_request_info):  # host/ip matches log rule
                                            self.log(http_request_info, retrieveInfo)
                                        self.reassembly[unique_id] = ""   # reset to empty string for next http header
                            else:
                                pass                # drop forward out-of-order http packet
                        else:  ## normal tcp packet, just send
                            self.iface_int.send_ip_packet(pkt)
                    elif matchRes == "deny":
                        if self.debug:
                            print "deny this packet"
                        ack_num = struct.unpack('!L', pkt[ip_header_len + 4:ip_header_len + 8])[0] + 1
                        return_pkt = self.create_tcp_deny_packet(dest_addr_str, source_addr_str, dest_port_str, source_port_str, struct.pack('!L', ack_num))
                        self.iface_ext.send_ip_packet(return_pkt)
                else:
                    if self.debug:
                        print "outgoing packet"
                    pkt_info['external_port'] = dest_port
                    pkt_info['external_ip'] = dest_addr
                    matchRes = self.proIpPortMatching(pkt_info)
                    if self.debug:
                        print "+++++++++++++++++++outgoing packet rule matching result says,", matchRes
                    if matchRes == "pass":
                        if pkt_info['external_port']==80:    ## handle logging here if external port is 80
                            tcp_header_len = (struct.unpack("!B", pkt[ip_header_len+12])[0]>>4) *4  ## tcp header size in Byte
                            ip_total_len = struct.unpack("!H", pkt[2:4])[0]
                            # if ip_total_len>ip_header_len+tcp_header_len:  ## there is payload related to TCP connection, which means there is http texts inside
                            tcp_payload_len = ip_total_len-ip_header_len-tcp_header_len
                            tcp_payload = pkt[ip_header_len+tcp_header_len:]
                            seq_num = struct.unpack("!L",pkt[ip_header_len+4:ip_header_len+8])[0]
                            expected_next_seq_num = seq_num+tcp_payload_len
                            unique_id = (self.dotQuadToInt(source_addr), self.dotQuadToInt(dest_addr), source_port, dest_port)
                            if unique_id not in self.expected_seq or (unique_id in self.expected_seq and seq_num<=self.expected_seq[unique_id]): # pass pkt
                                self.iface_ext.send_ip_packet(pkt)
                                if unique_id not in self.expected_seq:
                                    isSynSet = (struct.unpack("!B", pkt[ip_header_len+13:ip_header_len+14])[0]>>1)&1
                                    if isSynSet:
                                        self.expected_seq[unique_id] = seq_num+1  # special case for handshake, only allow once
                                elif unique_id in self.expected_seq and seq_num==self.expected_seq[unique_id]: # actual reassembling
                                    self.expected_seq[unique_id] = expected_next_seq_num
                                    if unique_id not in self.parsedHeader or self.parsedHeader[unique_id]==False:
                                        if unique_id in self.reassembly:
                                            self.reassembly[unique_id]+=tcp_payload
                                        else:
                                            self.reassembly[unique_id]=tcp_payload
                                    if self.crlf in self.reassembly[unique_id]:
                                        print "----------------------OUTGOING------------------------", self.reassembly[unique_id]
                                        retrieveInfo = self.retrieveInfo(self.reassembly[unique_id], True, pkt_info['external_ip'])  # this is an OUTGOING pkt--> request msg
                                        print "---------------> retrieved info: ", retrieveInfo
                                        reverse_unique_id = (unique_id[1],unique_id[0], unique_id[3], unique_id[2])
                                        self.parsedHeader[unique_id] = True     ## stop adding http body data into self.reassembly
                                        self.parsedHeader[reverse_unique_id] = False    ## now okay to receive http response header
                                        self.http_request_info[unique_id] = retrieveInfo
                                        self.reassembly[unique_id] = ""   # reset to empty string for next http header
                            else:
                                pass                # drop forward out-of-order http packet
                        else:               ## normal tcp packet, just send
                            self.iface_ext.send_ip_packet(pkt)
                    elif matchRes == "deny":
                        if self.debug:
                            print "deny this packet"
                        ack_num = struct.unpack('!L', pkt[ip_header_len + 4:ip_header_len + 8])[0] + 1
                        return_pkt = self.create_tcp_deny_packet(dest_addr_str, source_addr_str, dest_port_str, source_port_str, struct.pack('!L', ack_num))
                        self.iface_int.send_ip_packet(return_pkt)
            else:
                if self.debug:
                    print "-----------------------------UDP"
                    print "source ip address is", source_addr
                    print "destination ip address is", dest_addr
                    print "source port is", source_port
                    print "destination port is", dest_port
                if pkt_dir==PKT_DIR_OUTGOING and dest_port==53:     # treat only the udp portion of the pkt as the argument
                    dnsQueryBool, sendDnsResponseBool, dnsName = self.checkDnsQuery(pkt[ip_header_len:])
                    pkt_info['external_port'] = dest_port
                    pkt_info['external_ip'] = dest_addr
                    if not dnsQueryBool:
                        if self.debug:
                            print "Normal UDP with port=53 and OUTGOING"
                        matchRes = self.proIpPortMatching(pkt_info)
                        if self.debug:
                            print "+++++++++++++++++++outgoing packet rule matching result says,", matchRes
                        if matchRes == "pass":
                            self.iface_ext.send_ip_packet(pkt)
                    else:
                        if self.debug:
                            print "DNS query packet"
                        ## do something here
                        dns_matching_result = self.dnsMatching(dnsName, pkt_info)
                        if dns_matching_result=="pass" or dns_matching_result=="no-match":
                            self.iface_ext.send_ip_packet(pkt)
                        else:   # dns_matching_result=="drop":
                            if self.debug:
                                print "DROPPING DNS QUERY MATCHED"
                            if sendDnsResponseBool:
                                response = self.create_dns_deny_packet(dest_addr_str, source_addr_str, dest_port_str, source_port_str, pkt, ip_header_len)
                                self.iface_int.send_ip_packet(response)

                else:
                    if self.debug:
                        print "Normal UDP"

                    if pkt_dir == PKT_DIR_INCOMING:
                        if self.debug:
                            print "incoming packet"
                        pkt_info['external_port'] = source_port
                        pkt_info['external_ip'] = source_addr
                        matchRes = self.proIpPortMatching(pkt_info)
                        if self.debug:
                            print "+++++++++++++++++++incoming packet rule matching result says,", matchRes
                        if matchRes == "pass":
                            self.iface_int.send_ip_packet(pkt)
                    else:
                        if self.debug:
                            print "outgoing packet"
                        pkt_info['external_port'] = dest_port
                        pkt_info['external_ip'] = dest_addr
                        matchRes = self.proIpPortMatching(pkt_info)
                        if self.debug:
                            print "+++++++++++++++++++outgoing packet rule matching result says,", matchRes
                        if matchRes == "pass":
                            self.iface_ext.send_ip_packet(pkt)

        elif pkt_info['ip_protocal'] == 1:
            icmp_type = struct.unpack('!B', pkt[ip_header_len])[0]
            if self.debug:
                print "icmp_type is", icmp_type
            pkt_info['external_port'] = icmp_type
            if pkt_dir == PKT_DIR_INCOMING:
                if self.debug:
                    print "incoming packet"
                pkt_info['external_ip'] = source_addr
                matchRes = self.proIpPortMatching(pkt_info)
                if self.debug:
                    print "+++++++++++++++++++incoming packet rule matching result says,", matchRes
                if matchRes == "pass":
                    self.iface_int.send_ip_packet(pkt)
            else:
                if self.debug:
                    print "outgoing packet"
                pkt_info['external_ip'] = dest_addr
                matchRes = self.proIpPortMatching(pkt_info)
                if self.debug:
                    print "+++++++++++++++++++outgoing packet rule matching result says,", matchRes
                if matchRes == "pass":
                    self.iface_ext.send_ip_packet(pkt)
        else:
            if self.debug:
                print "The potocal is", pkt_info['ip_protocal']
            if pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)
            else:
                self.iface_int.send_ip_packet(pkt)

    def intToDotQuad(self, addr):
        dot_quad = []
        for i in range(4):
            dot_quad.append(addr % 256)
            addr = addr >> 8
        return list(reversed(dot_quad))

    def dotQuadToInt(self, quad):
        num = 0
        for i in quad:
            num += int(i)
            num = num << 8
        num = num >> 8
        return num

    def isInCountry(self, ip, ctry):
        if len(self.geoDb) == 0:
            return None
        for i in ip:
            if i < 0 or i > 255:
                return None
        res = self.findCtry(ip, 0, len(self.geoDb)-1)
        if res == None:
            return False
        if res.lower() == ctry.lower():
            if self.debug:
                print "country found:", res.lower()
            return True
        return False

    def findCtry(self, ip, start, end):
        if self.debug:
            print "start:", start, "and end:", end
        if start>end:
            return None
        if start == end:
            mid = self.geoDb[start]
            lower, upper = mid[0].split('.'), mid[1].split('.')
            ipIntVal = self.dotQuadToInt(ip)
            if ipIntVal >= self.dotQuadToInt(lower) and ipIntVal <= self.dotQuadToInt(upper):
                return mid[2]
            return None
        mid = self.geoDb[(start+end)/2]
        lower, upper = mid[0].split('.'), mid[1].split('.')
        ipIntVal = self.dotQuadToInt(ip)
        if ipIntVal < self.dotQuadToInt(lower):
            return self.findCtry(ip, start, (start+end)/2-1)
        elif ipIntVal > self.dotQuadToInt(upper):
            if self.debug:
                print "ipIntVal is greater than upper:", start, "and", end
            return self.findCtry(ip, (start+end)/2+1, end)
        return mid[2]


    def proIpPortMatching(self, pkt_info):
        if self.debug:
            print "entered proTpPortMatching"
            print pkt_info
        for rule in reversed(self.rules):
            rule = [r.lower() for r in rule]
            if self.debug:
                print "rule is", rule
            if self.ipv4ProHash[pkt_info['ip_protocal']] == rule[1]:
                if self.debug:
                    print "pkt's ipv4 protocal:", rule[1]
                if len(rule[2]) == 2:
                    # country code
                    if self.debug:
                        print "isInCountry: \n", self.isInCountry(pkt_info['external_ip'], rule[2])
                    if self.isInCountry(pkt_info['external_ip'], rule[2]):
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
                    if self.debug:
                        print "rule says that external ip can be anything"
                    if rule[3] == 'any':
                        return rule[0]
                    elif '-' in rule[3]:
                        lower, upper = rule[3].split('-')
                        lower, upper = int(lower), int(upper)
                        if pkt_info['external_port'] <= upper and pkt_info['external_port'] >= lower:
                            return rule[0]
                    else:
                        if self.debug:
                            print "rule says that external port should be", rule[3]
                        if pkt_info['external_port'] == int(rule[3]):
                            return rule[0]
                else:
                    quad = rule[2].split('.')
                    if '/' in quad[3]:
                        # an IP prefix
                        last_quad, offset = quad[3].split('/')
                        last_quad = int(last_quad)
                        offset = int(offset)
                        base_quad = quad[:3]
                        base_quad.append(last_quad)
                        if self.dotQuadToInt(base_quad) >> (32 - offset) == self.dotQuadToInt(pkt_info['external_ip']) >> (32 - offset):
                            if self.debug:
                                print "range matched:", quad
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
                        if self.dotQuadToInt(quad) == self.dotQuadToInt(pkt_info['external_ip']):
                            if self.debug:
                                print "single ip matched:", quad
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
                                    
    def dnsMatching(self, addr, pkt_info):        # make sure the dnsName are all in lower case
        addr_lst = addr.split(".")
        for j in range(1,len(self.rules)+1):
            rule = self.rules[-j]
            if rule[1]=="dns":
                dnsRule = rule
                dnsAddr_lst = dnsRule[2].split(".")
                matched = True
                if len(dnsAddr_lst)>len(addr_lst):
                    continue
                else:
                    for i in range(1,len(dnsAddr_lst)+1):
                        if dnsAddr_lst[-i]=="*":
                            break
                        elif dnsAddr_lst[-i]!=addr_lst[-i]:
                            matched = False
                            break
                    if matched:
                        return dnsRule[0]
            else:
                if rule[1]=="udp":
                    if len(rule[2]) == 2:
                        # country code
                        if self.debug:
                            print "isInCountry:", self.isInCountry(pkt_info['external_ip'], rule[2])
                        if self.isInCountry(pkt_info['external_ip'], rule[2]):
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
                        if self.debug:
                            print "rule says that external ip can be anything"
                        if rule[3] == 'any':
                            return rule[0]
                        elif '-' in rule[3]:
                            lower, upper = rule[3].split('-')
                            lower, upper = int(lower), int(upper)
                            if pkt_info['external_port'] <= upper and pkt_info['external_port'] >= lower:
                                return rule[0]
                        else:
                            if self.debug:
                                print "rule says that external port should be", rule[3]
                            if pkt_info['external_port'] == int(rule[3]):
                                return rule[0]
                    else:
                        quad = rule[2].split('.')
                        if '/' in quad[3]:
                            # an IP prefix
                            last_quad, offset = quad[3].split('/')
                            last_quad = int(last_quad)
                            offset = int(offset)
                            base_quad = quad[:3]
                            base_quad.append(last_quad)
                            if self.dotQuadToInt(base_quad) >> (32 - offset) == self.dotQuadToInt(pkt_info['external_ip']) >> (32 - offset):
                                if self.debug:
                                    print "range matched:", quad
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
                            if self.dotQuadToInt(quad) == self.dotQuadToInt(pkt_info['external_ip']):
                                if self.debug:
                                    print "single ip matched:", quad
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

        return "no-match"    # self-defined third return value besides "pass" and "drop"

    def checkDnsQuery(self, pkt): # return [isDnsQuery, sendDnsResponse, dnsName]
        """
        :rtype: a tuple of (isDnsQuery, isDeny, dnsName)
        """
        udpLength = struct.unpack('!H', pkt[4:6])[0]
        dnsHeader = pkt[8:20]
        QDCOUNT = struct.unpack("!H", dnsHeader[4:6])[0]
        if QDCOUNT!=1:
            return False, False, ""
        if self.debug:
            print "PKT: ", pkt, " length: ", len(pkt)
        dnsName, j = self.getQName(pkt, udpLength)
        QTYPE = struct.unpack("!H", pkt[j:j+2])[0]
        QCLASS = struct.unpack("!H", pkt[j+2:j+4])[0]
        if QCLASS!=1:
            return False, False, ""
        if QTYPE==1:
            return True, True, dnsName
        elif QTYPE==28:
            return True, False, dnsName
        else:
            return False, False, dnsName

    def getQName(self, pkt, udpLength):
        """
        :rtype: a tuple of (dnsName, Byte-index of the end of QName)
        """
        dnsName = ""
        j = 20
        while j<udpLength:
            hex = struct.unpack("!B",pkt[j])[0]
            if hex==0x00:
                j+=1
                break
            else:
                if (hex>=65 and hex<=90) or (hex>=97 and hex<=122) or (hex>=48 and hex<=57) or hex==45:  # only alphabetic letters, digits and hyphen are permitted as dns name
                    dnsName = dnsName+chr(hex)
                elif dnsName!="": # beginning of parsing, first hex number not letters/hyphens is just number of letters behind
                    dnsName = dnsName+"."       # adding dot
                j+=1
        return dnsName.lower(), j

    def hostMatching(self, retrieveInfo):
        return True
        # if type(retrieveInfo["host"])==str: ## actual hostname matching, can use domainMatching(domainName)
        #     hostname = retrieveInfo["host"]
        #     addr_lst = hostname.split(".")
        #     for j in range(1,len(self.rules)+1):
        #         rule = self.rules[-j]
        #         if rule[0]=="log":
        #             logRule = rule
        #             logAddr_lst = logRule[2].split(".")
        #             matched = True
        #             if len(logAddr_lst)>len(addr_lst):
        #                 continue
        #             else:
        #                 for i in range(1,len(logRule)+1):
        #                     if logAddr_lst[-i]=="*":
        #                         break
        #                     elif logRule[-i]!=addr_lst[-i]:
        #                         matched = False
        #                         break
        #                 if matched:
        #                     return True
        #     return False
        # else:                               ## IPv4 matching, TODO: remeber to convert IPv4 dot quad into integer first inside retrieveInfo
        #     ipv4_int = retrieveInfo["host"]
        #     for j in range(1,len(self.rules)+1):
        #         rule = self.rules[-j]
        #         if rule[0]=="log":
        #             isIPv4 = True
        #             logAddr_lst = rule[2].split(".")
        #             for i in logAddr_lst:
        #                 if not i.isdigit():
        #                     isIPv4 = False
        #                     break
        #             if rule[0]=="log" and isIPv4:
        #                 rule_int = self.dotQuadToInt(rule[2])
        #                 if ipv4_int!=rule_int:
        #                     continue
        #                 else:
        #                     return True
        #     return False

    def retrieveInfo(self, payload, is_request_http, external_ip): ## TODO: implement this
        """
        argument: is_request_http is a boolean that is true if the info to be extracted is an http request payload
        :rtype: a dictionary specifying host_name, method, path, version, status_code, object_size
        steps:
        1) locate the crlf inside the payload
        2) from crlf, go backwards to parse information
        Be careful about the cases that some of the fields do not exist, need default value (content-length) or alternative (IPv4)
        """
        http_string = payload.split(self.crlf)[0]
        result_dict = {}
        http_string = http_string.lower()
        if is_request_http:
            request_info_lst = http_string.split('\r\n');
            # first info is always method, path, version
            result_dict["method"], result_dict["path"], result_dict["version"] = request_info_lst[0].split()
            for i in range(1, len(request_info_lst)):
                info_elem = request_info_lst[i].split()
                if info_elem[0]=="host:":
                    result_dict["host"] = info_elem[1]
                    break
            if "host" not in result_dict:
                # convert dot quad lst into string
                result_dict["host"] = ".".join([str(_) for _ in external_ip])
        else:
            response_info_lst = http_string.split('\r\n');
            # first info is always version, status_code, description
            result_dict["status_cod"] = response_info_lst[0].split()[1]
            for i in range(1, len(response_info_lst)):
                info_elem = response_info_lst[i].split()
                if info_elem[0]=="content-length:":
                    result_dict["object-size"] = info_elem[1]
                    break
            if "object-size" not in result_dict:
                # default object-size to -1 if no content-length exists
                result_dict["object-size"] = "-1"
        return result_dict

    def log(self, requestInfo, responseInfo):
        # info is a dictionary with all logging info pairs
#         f = open('http.log', 'a')
#
#         write_str = info["host"]+" "+info["method"]+" "+info["path"]+" "+info["version"]+" "+info["status_code"]+" "+info["object_s\
# ize"]+"\n"
#         print "string to write", write_str
#         f.write(write_str)
        pass
#
#     def log(self, request_info, response_info):
#         # info is a dictionary with all logging info pairs
#         f = open('http.log', 'a')
#
#         write_str = request_info["host"]+" "+request_info["method"]+" "+request_info["path"]+" "+request_info["version"]+" "+response_info["status_code"]+" "+response_info["object_size"]+"\n"
#         print "string to write", write_str
#         f.write(write_str)
# >>>>>>> d9f47d6465d8c23a373258bfe0a71837c8d3506e







