#!/usr/bin/python

# invoke with:
# sudo ./http-minimal.py -i docker0

from bcc import BPF
from sys import argv

import socket
import os

def toHex(s):
    lst = []
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0'+hv
        lst.append(hv)

    return reduce(lambda x,y:x+y, lst)

interface = argv[2]
print ("binding socket to '%s'" % interface)

bpf = BPF(text = \
r'''
#include <bcc/proto.h>

#define IP_TCP  6

int http_filter(struct __sk_buff *skb) {

  u8 *cursor = 0;

  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  //filter IP packets (ethernet type = 0x0800)
  if (!(ethernet->type == 0x0800)) {
    goto DROP;
  }

  struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
  //filter TCP packets (ip next protocol = 0x06)
  if (ip->nextp != IP_TCP) {
    goto DROP;
  }

  u32  ip_header_length = 0;

  //calculate ip header length
  //value to multiply * 4
  //e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 byte = 20 byte
  ip_header_length = ip->hlen << 2;    //SHL 2 -> *4 multiply

  //check ip header length against minimum
  if (ip_header_length < sizeof(*ip)) {
    goto DROP;
  }

  //shift cursor forward for dynamic ip header size
  void *_ = cursor_advance(cursor, (ip_header_length-sizeof(*ip)));

  struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

  bpf_trace_printk("%u\n", tcp->seq_num);
  return -1;

  //drop the packet returning 0
  DROP:
  return 0;
}
''')

function_http_filter = bpf.load_func("http_filter", BPF.SOCKET_FILTER)

BPF.attach_raw_socket(function_http_filter, interface)

socket_fd = function_http_filter.sock

sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP) # formerly IPPROTO_IP
sock.setblocking(True)

ETH_HLEN = 14

print ("ready")

while 1:
  #retrieve raw packet from socket
  packet_str = os.read(socket_fd,65536) #set packet length to max packet length on the interface. formerly 4096.

  #calculate ip header length
  ip_header_length = bytearray(packet_str)[ETH_HLEN]               #load Byte
  ip_header_length = ip_header_length & 0x0F                  #mask bits 0..3
  ip_header_length = ip_header_length << 2                    #shift to obtain length

  tcp_header_offset = ETH_HLEN+ip_header_length

  seq_num_str = packet_str[tcp_header_offset+4:tcp_header_offset+8]
  seq_num = int(toHex(seq_num_str),16)

  print(seq_num)