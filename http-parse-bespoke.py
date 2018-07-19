#!/usr/bin/python
#
#Bertrone Matteo - Polytechnic of Turin
#November 2015
#
#eBPF application that parses HTTP packets
#and extracts (and prints on screen) the URL contained in the GET/POST request.
#
#eBPF program http_filter is used as SOCKET_FILTER attached to eth0 interface.
#only packet of type ip and tcp containing HTTP GET/POST are returned to userspace, others dropped
#
#python script uses bcc BPF Compiler Collection by iovisor (https://github.com/iovisor/bcc)
#and prints on stdout the first line of the HTTP GET/POST request containing the url

from __future__ import print_function
from bcc import BPF
from ctypes import *
from struct import *
from sys import argv
from urlparse import urlparse, parse_qs

import sys
import socket
import os
import struct
import binascii
import time

CLEANUP_N_PACKETS  = 50       #run cleanup every CLEANUP_N_PACKETS packets received
MAX_URL_STRING_LEN = 8192     #max url string len (usually 8K)
MAX_AGE_SECONDS    = 121       #max age entry in bpf_sessions map (formerly 30s, but I bumped it up to TCP default timeout)

#convert a bin string into a string of hex char
#helper function to print raw packet in hex
def toHex(s):
    lst = []
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0'+hv
        lst.append(hv)

    return reduce(lambda x,y:x+y, lst)

def getUntilCRLF(str):
    """text section ends on CRLF
    """
    return str.split("\r\n", 1)[0]

def isReply(text_section):
    """HTTP requests begin with URI. replies begin with HTTP version
    """
    return text_section[:5] == "HTTP/"

def getService(text_section):
    """URI ends is followed by HTTP version (space-delimited)
    """
    path = text_section.split(" HTTP", 1)[0]
    parsed = urlparse(path)
    query_str = parsed.query
    query_params = parse_qs(query_str)
    if ('s' in query_params):
      return query_params['s'][-1]
    eprint('HTTP request captured, but no service in URI. attributing data to _unspecified.')
    return '_unspecified'

#print str until CR+LF
def printUntilCRLF(str):
    for k in range (0,len(str)-1):
      if (str[k] == '\n'):
        if (str[k-1] == '\r'):
          eprint("")
          return
      eprint("%c" % (str[k]), end = "")
    eprint("")
    return

def addBytesInboundToService(bytes, service):
    current_bytes = bytes_inbound_to_service[service] if service in bytes_inbound_to_service else 0
    new_bytes = current_bytes + bytes
    bytes_inbound_to_service[service] = new_bytes
    eprint("+%d bytes inbound to service '%s' = %d" % (bytes, service, new_bytes))
    printTotalServiceCounts()

def addBytesOutboundFromService(bytes, service):
    current_bytes = bytes_outbound_from_service[service] if service in bytes_outbound_from_service else 0
    new_bytes = current_bytes + bytes
    bytes_outbound_from_service[service] = new_bytes
    eprint("+%d bytes outbound from service '%s' = %d" % (bytes, service, new_bytes))
    printTotalServiceCounts()

def printTotalServiceCounts():
    eprint("----")
    eprint("inbound bytes:")
    printTotalServiceCountsFor(bytes_inbound_to_service)
    eprint("-")
    eprint("outbound bytes:")
    printTotalServiceCountsFor(bytes_outbound_from_service)
    eprint("----")

def printTotalServiceCountsFor(dict):
    for key, value in dict.items():
      eprint("%s -> %d" % (key, value))


def printBytesAndService(bytes, str):
    # print("%d" % bytes, end = "")
    request_line = str.split("\r\n", 1)[0]
    path = request_line.split(" HTTP", 1)[0]
    parsed = urlparse(path)
    query_str = parsed.query
    query_params = parse_qs(query_str)
    if ('s' in query_params):
      service = query_params['s'][-1]
      if service in bytes_sent_by_service:
        bytes_sent_by_service[service] += bytes
      else:
        bytes_sent_by_service[service] = bytes
      eprint("+%d bytes service '%s' = %d" % (bytes, service, bytes_sent_by_service[service]))
    else:
      eprint("%d bytes no service" % (bytes))
    eprint("")
    return

#cleanup function
def cleanup():
    #get current time in seconds
    current_time = int(time.time())
    #looking for leaf having:
    #timestap  == 0        --> update with current timestamp
    #AGE > MAX_AGE_SECONDS --> delete item
    for key,leaf in bpf_sessions.items():
      try:
        current_leaf = bpf_sessions[key]
        #set timestamp if timestamp == 0
        if (current_leaf.timestamp == 0):
          bpf_sessions[key] = bpf_sessions.Leaf(current_time)
        else:
          #delete older entries
          if (current_time - current_leaf.timestamp > MAX_AGE_SECONDS):
            del bpf_sessions[key]
      except:
        eprint("cleanup exception.")
    return

#args
def usage():
    eprint("USAGE: %s [-i <if_name>]" % argv[0])
    eprint("")
    eprint("Try '%s -h' for more options." % argv[0])
    exit()

#help
def help():
    eprint("USAGE: %s [-i <if_name>]" % argv[0])
    eprint("")
    eprint("optional arguments:")
    eprint("   -h                       print this help")
    eprint("   -i if_name               select interface if_name. Default is eth0")
    eprint("")
    eprint("examples:")
    eprint("    http-parse              # bind socket to eth0")
    eprint("    http-parse -i wlan0     # bind socket to wlan0")
    exit()

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

#arguments
interface="eth0"

if len(argv) == 2:
  if str(argv[1]) == '-h':
    help()
  else:
    usage()

if len(argv) == 3:
  if str(argv[1]) == '-i':
    interface = argv[2]
  else:
    usage()

if len(argv) > 3:
  usage()

print ("binding socket to '%s'" % interface)

# initialize BPF - load source code from http-parse-complete.c
bpf = BPF(src_file = "http-parse-complete.c",debug = 0)

#load eBPF program http_filter of type SOCKET_FILTER into the kernel eBPF vm
#more info about eBPF program types
#http://man7.org/linux/man-pages/man2/bpf.2.html
function_http_filter = bpf.load_func("http_filter", BPF.SOCKET_FILTER)

#create raw socket, bind it to interface
#attach bpf program to socket created
BPF.attach_raw_socket(function_http_filter, interface)

#get file descriptor of the socket previously created inside BPF.attach_raw_socket
socket_fd = function_http_filter.sock

#create python socket object, from the file descriptor
sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
#set it as blocking socket
sock.setblocking(True)

#get pointer to bpf map of type hash
bpf_sessions = bpf.get_table("sessions")

#packets counter
packet_count = 0

#dictionary containing association <key(ipsrc,ipdst,portsrc,portdst),payload_string>
#if url is not entirely contained in only one packet, save the firt part of it in this local dict
#when I find \r\n in a next pkt, append and print all the url
local_dictionary = {}
bytes_sent_dic = {}
bytes_inbound_to_service = {}
bytes_outbound_from_service = {}
requested_service = {}

while 1:
  #retrieve raw packet from socket
  packet_str = os.read(socket_fd,4096) #set packet length to max packet length on the interface
  packet_count += 1

  #DEBUG - print raw packet in hex format
  #packet_hex = toHex(packet_str)
  #print ("%s" % packet_hex)

  #convert packet into bytearray
  packet_bytearray = bytearray(packet_str)

  #ethernet header length
  ETH_HLEN = 14

  #IP HEADER
  #https://tools.ietf.org/html/rfc791
  # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  # |Version|  IHL  |Type of Service|          Total Length         |
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #
  #IHL : Internet Header Length is the length of the internet header
  #value to multiply * 4 byte
  #e.g. IHL = 5 ; IP Header Length = 5 * 4 byte = 20 byte
  #
  #Total length: This 16-bit field defines the entire packet size,
  #including header and data, in bytes.

  #calculate packet total length
  total_length = packet_bytearray[ETH_HLEN + 2]               #load MSB
  total_length = total_length << 8                            #shift MSB
  total_length = total_length + packet_bytearray[ETH_HLEN+3]  #add LSB

  #calculate ip header length
  ip_header_length = packet_bytearray[ETH_HLEN]               #load Byte
  ip_header_length = ip_header_length & 0x0F                  #mask bits 0..3
  ip_header_length = ip_header_length << 2                    #shift to obtain length

  #retrieve ip source/dest
  ip_src_str = packet_str[ETH_HLEN+12:ETH_HLEN+16]                #ip source offset 12..15
  ip_dst_str = packet_str[ETH_HLEN+16:ETH_HLEN+20]                #ip dest   offset 16..19

  ip_src = int(toHex(ip_src_str),16)
  ip_dst = int(toHex(ip_dst_str),16)

  #TCP HEADER
  #https://www.rfc-editor.org/rfc/rfc793.txt
  #  12              13              14              15
  #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  # |  Data |           |U|A|P|R|S|F|                               |
  # | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
  # |       |           |G|K|H|T|N|N|                               |
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #
  #Data Offset: This indicates where the data begins.
  #The TCP header is an integral number of 32 bits long.
  #value to multiply * 4 byte
  #e.g. DataOffset = 5 ; TCP Header Length = 5 * 4 byte = 20 byte

  #calculate tcp header length
  tcp_header_length = packet_bytearray[ETH_HLEN + ip_header_length + 12]  #load Byte
  tcp_header_length = tcp_header_length & 0xF0                            #mask bit 4..7
  tcp_header_length = tcp_header_length >> 2                              #SHR 4 ; SHL 2 -> SHR 2

  #retrieve port source/dest
  port_src_str = packet_str[ETH_HLEN+ip_header_length:ETH_HLEN+ip_header_length+2]
  port_dst_str = packet_str[ETH_HLEN+ip_header_length+2:ETH_HLEN+ip_header_length+4]

  port_src = int(toHex(port_src_str),16)
  port_dst = int(toHex(port_dst_str),16)

  #calculate payload offset
  payload_offset = ETH_HLEN + ip_header_length + tcp_header_length

  #payload_string contains only packet payload
  payload_string = packet_str[(payload_offset):(len(packet_bytearray))]
  bytes_sent = total_length

  #CR + LF (substring to find)
  crlf = "\r\n"

  #current_Key contains ip source/dest and port source/map
  #useful for direct bpf_sessions map access
  current_Key = bpf_sessions.Key(ip_src,ip_dst,port_src,port_dst)
  partner_Key = bpf_sessions.Key(ip_dst,ip_src,port_dst,port_src)

  #looking for HTTP GET/POST request
  if ((payload_string[:3] == "GET") or (payload_string[:4] == "POST")   or (payload_string[:4] == "HTTP")  \
  or ( payload_string[:3] == "PUT") or (payload_string[:6] == "DELETE") or (payload_string[:4] == "HEAD") ):
    #match: HTTP GET/POST packet found (i.e. it's a request)
    if (crlf in payload_string):
      eprint("\n\n")
      text_section = getUntilCRLF(payload_string)
      if (isReply(text_section)):
        eprint("reply: %s" % (text_section))
        partner_key_hex = binascii.hexlify(partner_Key)
        if (partner_key_hex in requested_service):
          service = requested_service[partner_key_hex]
        else:
          eprint('HTTP reply captured, but no corresponding HTTP request known. attributing data to _unknown.')
          service = '_unknown'
        # for outbound requests only: we count bytes of each fragmented packet
        # along the way. so we need only count this latest packet's bytes
        addBytesOutboundFromService(bytes_sent, service)
        try:
          del requested_service[partner_key_hex]
        except:
          eprint("error during delete from requested_service map ")
      else:
        eprint("request: %s" % (text_section))
        service = getService(text_section)
        requested_service[binascii.hexlify(current_Key)] = service
        addBytesInboundToService(bytes_sent, service)

      #url entirely contained in first packet -> print it all
      # printUntilCRLF(payload_string)
      # printBytesAndService(bytes_sent, payload_string)

      #delete current_Key from bpf_sessions, url already printed. current session not useful anymore
      try:
        del bpf_sessions[current_Key]
      except:
        eprint("error during delete from bpf map ")
    else:
      #url NOT entirely contained in first packet
      #not found \r\n in payload.
      #save current part of the payload_string in dictionary <key(ips,ipd,ports,portd),payload_string>
      local_dictionary[binascii.hexlify(current_Key)] = payload_string
      bytes_sent_dic[binascii.hexlify(current_Key)] = bytes_sent
  else:
    #NO match: HTTP GET/POST  NOT found

    #check if the packet belong to a session saved in bpf_sessions
    if (current_Key in bpf_sessions):
      #check id the packet belong to a session saved in local_dictionary
      #(local_dictionary mantains HTTP GET/POST url not printed yet because splitted in N packets)
      if (binascii.hexlify(current_Key) in local_dictionary):
        #first part of the HTTP GET/POST url is already present in local dictionary (prev_payload_string)
        prev_payload_string = local_dictionary[binascii.hexlify(current_Key)]
        prev_bytes_sent = bytes_sent_dic[binascii.hexlify(current_Key)]
        #looking for CR+LF in current packet.
        if (crlf in payload_string):
          #last packet. containing last part of HTTP GET/POST url splitted in N packets.
          #append current payload
          prev_payload_string += payload_string
          prev_bytes_sent += bytes_sent

          eprint("\n\n")
          text_section = getUntilCRLF(prev_payload_string)
          if (isReply(text_section)):
            eprint("reply: %s" % (text_section))
            partner_key_hex = binascii.hexlify(partner_Key)
            if (partner_key_hex in requested_service):
              service = requested_service[partner_key_hex]
            else:
              eprint('HTTP reply captured, but no corresponding HTTP request known. attributing data to _unknown.')
              service = '_unknown'
            # for outbound requests only: we count bytes of each fragmented packet
            # along the way. so we need only count this latest packet's bytes
            addBytesOutboundFromService(bytes_sent, service)
            try:
              del requested_service[partner_key_hex]
            except:
              eprint("error during delete from requested_service map ")
          else:
            eprint("request: %s" % (text_section))
            service = getService(text_section)
            requested_service[binascii.hexlify(current_Key)] = service
            addBytesInboundToService(prev_bytes_sent, service)
          
          #print HTTP GET/POST url
          # printUntilCRLF(prev_payload_string)
          # printBytesAndService(prev_bytes_sent, prev_payload_string)

          #clean bpf_sessions & local_dictionary
          try:
            del bpf_sessions[current_Key]
            del local_dictionary[binascii.hexlify(current_Key)]
            del bytes_sent_dic[binascii.hexlify(current_Key)]
          except:
            eprint("error deleting from map or dictionary")
        else:
          #NOT last packet. containing part of HTTP GET/POST url splitted in N packets.
          #append current payload
          prev_payload_string += payload_string
          prev_bytes_sent += bytes_sent

          if (isReply(prev_payload_string)):
            eprint("partial reply")
            partner_key_hex = binascii.hexlify(partner_Key)
            if (partner_key_hex in requested_service):
              service = requested_service[partner_key_hex]
            else:
              eprint('partial HTTP reply captured, but no corresponding HTTP request known. attributing data to _unknown.')
              service = '_unknown'
            addBytesOutboundFromService(bytes_sent, service)
          

          #check if not size exceeding (usually HTTP GET/POST url < 8K )
          if (len(prev_payload_string) > MAX_URL_STRING_LEN):
            eprint("url too long")
            try:
              del bpf_sessions[current_Key]
              del local_dictionary[binascii.hexlify(current_Key)]
              del bytes_sent_dic[binascii.hexlify(current_Key)]
            except:
              eprint("error deleting from map or dict")
          #update dictionary
          local_dictionary[binascii.hexlify(current_Key)] = prev_payload_string
          bytes_sent_dic[binascii.hexlify(current_Key)] = prev_bytes_sent
      else:
        #first part of the HTTP GET/POST url is NOT present in local dictionary
        #bpf_sessions contains invalid entry -> delete it
        try:
          del bpf_sessions[current_Key]
        except:
          eprint("error del bpf_session")

  #check if dirty entry are present in bpf_sessions
  if (((packet_count) % CLEANUP_N_PACKETS) == 0):
    cleanup()
