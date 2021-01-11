#include <arpa/inet.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <iproute2/bpf_elf.h>
#include <bpf/bpf_helpers.h>

#define MAX_ITER 32
#define PKT_LEN (__u16)((__u16)(data_end-data)-sizeof(struct ethhdr))

int _egress_gre(struct iphdr *, struct __sk_buff *, __u16);
__u32 _ingress_old_addr();

struct bpf_elf_map SEC("maps") gre_dst = {
        .type = BPF_MAP_TYPE_ARRAY,
        .id = 1,
        .size_key = sizeof(__u32),
        .size_value = sizeof(__u32),
        .max_elem = 2,
        .pinning = PIN_GLOBAL_NS,
};

SEC("egress")
int _egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth_hdr = data;
    struct iphdr *ip_hdr = data+sizeof(struct ethhdr);

    if (data + ETH_HLEN + sizeof(struct iphdr) > data_end) {
        return TC_ACT_OK;
    }

    // not handling ipv6 at the moment
    if (eth_hdr->h_proto == ntohs(ETH_P_IPV6)
    // only process GRE packets
    || ip_hdr->protocol != IPPROTO_GRE
    // only process packets with configured destination address
    || ip_hdr->daddr != _ingress_old_addr()) {
        return TC_ACT_OK;
    }

    return _egress_gre(ip_hdr, skb, PKT_LEN);
}

SEC("ingress_old_addr")
__u32 _ingress_old_addr()
{
    __u32 old_dst_key = 0;
    __u32 old_dst = 0;

    __u32 *value = bpf_map_lookup_elem(&gre_dst, &old_dst_key);
    if (value != NULL && *value > 0) {
        old_dst = *value;
    }

    return old_dst;
}

SEC("egress_gre")
int _egress_gre(struct iphdr *data, struct __sk_buff * skb, __u16 len)
{
    __u32 ret;
    __u32 dst_key = 1;
    __u32 old_dst;

    // read dest IP from map elem #1 and change destination addr
    __u32 *value = bpf_map_lookup_elem(&gre_dst, &dst_key);

    if (value != NULL && *value > 0) {
        ret = bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr), &old_dst, 4);
        if (ret < 0) {
            return TC_ACT_OK;
        }

        bpf_l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check), old_dst, *value, 4);
        bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr), value, sizeof(*value), 0);
    }

    return TC_ACT_OK;
}