# bcc-traffic-by-service
Linux eBPF BCC script to count the amount of HTTP traffic for which each API endpoint is responsible


suo su -
echo 1 > /sys/kernel/debug/tracing/tracing_on
cat /sys/kernel/debug/tracing/trace_pipe

sudo bpftrace -l '*skb*' | more
sudo su -
cat /sys/kernel/debug/tracing/events/skb/kfree_skb/format