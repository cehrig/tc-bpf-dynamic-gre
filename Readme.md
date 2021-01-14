This is a lab setup for using a GRE endpoint with dynamically changing IP addresses. The sending side will install a BPF program
- via tc (tc_egress) for changing destination address and checksum 
- via XDP (xdp_ingress) for changing source address and checksum

# GRE setup on sender's side
```
// setup GRE endpoint with dummy remote
ip link add name gre-home type gre remote 1.2.4.8
ip addr add 10.0.10.0/31 dev gre-home
ip link set dev gre-home up
```
# Egress (tc)
relevant steps to install egress filter
## kernel object
`clang -g -O2 -target bpf -o tc_egress_kern.o -c tc_egress_kern.c`

## user-space
`gcc -lbpf -o tc_egress_user ./tc_egress_user.c`

## setup qdisc via iproute2
```
tc qdisc add dev enp0s31f6 clsact
tc filter add dev enp0s31f6 egress bpf da obj tc_egress_kern.o sec egress
```
## configure BPF map
`./tc_egress_user 1.2.4.8 <dynamic GRE endpoint>`

## cleanup
```
tc filter del dev <egress interface> egress
tc qdisc del dev <egress interface> clsact
```

# Ingress (XDP)
Ingress packets will have source IP set to the endpoint's dynamic IP. We have to map that to our dummy IP address.
## kernel object
`clang -g -O2 -target bpf -o xdp_ingress_kern.o -c xdp_ingress_kern.c`

## user-space
`gcc -lbpf -o xdp_ingress_user xdp_ingress_user.c`

## install in XDP via custom loader
We are using a custom loader here to re-use the map setup via tc

`./xdp_ingress_user <ingress interface>`

## cleanup
`ip link set dev <ingress interface> xdp off`

# Test
A ping from the remote side should show something like this
```
13:52:15.472965 IP (tos 0x0, ttl 58, id 49534, offset 0, flags [DF], proto GRE (47), length 108)
    1.2.4.8 > [senders public IP]: GREv0, Flags [none], length 88
        IP (tos 0x0, ttl 64, id 24639, offset 0, flags [DF], proto ICMP (1), length 84)
    10.0.10.1 > 10.0.10.0: ICMP echo request, id 11247, seq 1972, length 64
13:52:15.473058 IP (tos 0x0, ttl 64, id 46835, offset 0, flags [DF], proto GRE (47), length 108)
    [senders public IP] > [dynamic GRE endpoint IP]: GREv0, Flags [none], length 88
        IP (tos 0x0, ttl 64, id 60136, offset 0, flags [none], proto ICMP (1), length 84)
    10.0.10.0 > 10.0.10.1: ICMP echo reply, id 11247, seq 1972, length 64
```
