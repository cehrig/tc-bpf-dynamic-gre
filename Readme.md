This is a lab setup for using a GRE endpoint with dynamically changing IP addresses. The sending side will install a BPF programm via tc that is responsible for changing daddr and checksum. destination is read from a BPF map. 

# GRE setup on sender's side
```
// setup GRE endpoint with dummy remote
ip link add name gre-home type gre remote 1.2.4.8
ip addr add 10.0.10.0/31 dev gre-home
ip link set dev gre-home up
```
# egress
relevant steps to run BPF program 
## kernel object
`clang -g -O2 -target bpf -o tc_egress_kern.o -c tc_egress_kern.c`

## user-space
`gcc -lbpf -o tc_egress_user ./tc_egress_user.c`

## setup qdisc
```
tc qdisc add dev enp0s31f6 clsact
tc filter add dev enp0s31f6 egress bpf da obj tc_egress_kern.o sec egress
tc filter del dev <egress interface> egress
tc qdisc del dev <egress interface> clsact
```
## configure BPF map
`./tc_egress_user 1.2.4.8 <dynamic GRE endpoint>`

# ingress
WIP