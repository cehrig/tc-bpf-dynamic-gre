#include <arpa/inet.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

int xdp_ingress_gre_prog(void *);
__u32 xdp_ingress_new_addr_prog();

struct bpf_map_def gre_dst SEC("maps") = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(__u32),
        .value_size = sizeof(__u32),
        .max_entries = 2,
};

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth_hdr = data;
    struct iphdr *ip_hdr = data+sizeof(struct ethhdr);

    if (data + ETH_HLEN + sizeof(struct iphdr) > data_end) {
        return XDP_PASS;
    }

    // not handling ipv6 at the moment
    if (eth_hdr->h_proto == ntohs(ETH_P_IPV6)
        // only process GRE packets
        || ip_hdr->protocol != IPPROTO_GRE
        // only process packets with configured destination address
        || ip_hdr->saddr != xdp_ingress_new_addr_prog()) {
        return XDP_PASS;
    }

    return xdp_ingress_gre_prog(ip_hdr);
}

__u32 xdp_ingress_new_addr_prog()
{
    __u32 new_src_key = 1;
    __u32 new_src = 0;

    __u32 *value = bpf_map_lookup_elem(&gre_dst, &new_src_key);
    if (value && *value > 0) {
        new_src = *value;
    }

    return new_src;
}

__u16 checksum(__u16 *data, __u32 len) {
    __u32 sum = 0;

    while (len > 1) {
        sum += *data;
        data++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(__u8 *)data;
    }

    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

int xdp_ingress_gre_prog(void *data)
{
    __u32 src_key = 0;

    // read dest IP from map elem #1 and change source addr
    __u32 *value = bpf_map_lookup_elem(&gre_dst, &src_key);
    __u32 *ip_src = (__u32*)data+3;
    __u16 *ip_csum = (__u16*)data+5;

    if (value && *value > 0) {
        __u8 *_ip_src = (__u8*)ip_src;
        __u8 *_value = (__u8*)value;

        _ip_src[0] = _value[0];
        _ip_src[1] = _value[1];
        _ip_src[2] = _value[2];
        _ip_src[3] = _value[3];

        *ip_csum = 0;
        *ip_csum = checksum((__u16 *)data, sizeof(struct iphdr));
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";