#!/usr/bin/python
# pip install http-parser
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
bpf = BPF(src_file = "http-parse-seq.c",debug = 0)

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
sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP) # formerly IPPROTO_IP
#set it as blocking socket
sock.setblocking(True)

#get pointer to bpf map of type hash
bpf_sessions = bpf.get_table("sessions")

print ("ready")

# bpf.trace_print()

while 1:
  #retrieve raw packet from socket
  packet_str = os.read(socket_fd,65536) #set packet length to max packet length on the interface. formerly 4096. consider 65536

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

  tcp_header_offset = ETH_HLEN+ip_header_length

  #calculate tcp header length
  tcp_header_length = packet_bytearray[tcp_header_offset + 12]  #load Byte
  tcp_header_length = tcp_header_length & 0xF0                            #mask bit 4..7
  tcp_header_length = tcp_header_length >> 2                              #SHR 4 ; SHL 2 -> SHR 2

  #retrieve port source/dest
  port_src_str = packet_str[tcp_header_offset:tcp_header_offset+2]
  port_dst_str = packet_str[tcp_header_offset+2:tcp_header_offset+4]

  port_src = int(toHex(port_src_str),16)
  port_dst = int(toHex(port_dst_str),16)

  seq_num_str = packet_str[tcp_header_offset+4:tcp_header_offset+8]
  seq_num = int(toHex(seq_num_str),16)

  print(seq_num)