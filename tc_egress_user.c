#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <error.h>

#define PINNED_FILE "/sys/fs/bpf/tc/globals/gre_dst"

int main(int argc, char **argv)
{
    int array_fd, ret;
    int ip_old_key = 0, ip_new_key = 1;
    unsigned int ip_old, ip_new;

    if (argc != 3) {
        error(-1, errno, "run with [old dst IP] [new dst IP]");
    }

    if ((ip_old = inet_addr(argv[1])) == INADDR_NONE) {
        error(-1, errno, "inet_addr(%s)", argv[1]);
    }

    if ((ip_new = inet_addr(argv[2])) == INADDR_NONE) {
        error(-1, errno, "inet_addr(%s)", argv[2]);
    }

    array_fd = bpf_obj_get(PINNED_FILE);
    if (array_fd < 0) {
        error(-1, errno, "bpf_obj_get(%s)", PINNED_FILE);
    }

    printf("old dst: %u new dst: %u\n", ip_old, ip_new);

    ret = bpf_map_update_elem(array_fd, &ip_old_key, (void *)&ip_old, 0);
    if (ret) {
        error(-1, errno, "bpf_map_update_elem(%d)", ip_old);
    }

    ret = bpf_map_update_elem(array_fd, &ip_new_key, (void *)&ip_new, 0);
    if (ret) {
        error(-1, errno, "bpf_map_update_elem(%d)", ip_new);
    }

    return 1;
}