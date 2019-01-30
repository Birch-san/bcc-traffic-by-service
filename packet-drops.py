#!/usr/bin/python
#
# urandomread  Example of instrumenting a kernel tracepoint.
#              For Linux, uses BCC, BPF. Embedded C.
#
# REQUIRES: Linux 4.7+ (BPF_PROG_TYPE_TRACEPOINT support).
#
# Test by running this, then in another shell, run:
#     dd if=/dev/urandom of=/dev/null bs=1k count=5
#
# Copyright 2016 Orange.
# Licensed under the Apache License, Version 2.0 (the "License")
from __future__ import print_function
from bcc import BPF
from time import sleep

# load BPF program
b = BPF(text="""
struct key_t {
    u64 location;
};

BPF_HASH(drops, struct key_t);

TRACEPOINT_PROBE(skb, kfree_skb) {
    u64 zero = 0, *count;
    struct key_t key = {};

    // args is from /sys/kernel/debug/tracing/events/skb/kfree_skb/format
    key.location = (u64)args->location;
    count = drops.lookup_or_init(&key, &zero);
    (*count)++;
    return 0;
};
""")

# header
print("Tracing... Ctrl-C to end.")

# format output
try:
    sleep(99999999)
except KeyboardInterrupt:
    pass

print("\n%-16s %-26s %8s" % ("ADDR", "FUNC", "COUNT"))
drops = b.get_table("drops")
print(drops.items()[0][1].value)
for k, v in sorted(drops.items(), key=lambda elem: elem[1].value):
    print("%-16x %-26s %8d" % (k.location, b.ksym(k.location), v.value))
