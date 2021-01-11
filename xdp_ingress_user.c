#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <sys/resource.h>
#include <errno.h>
#include <error.h>

#define PINNED_FILE "/sys/fs/bpf/tc/globals/gre_dst"

int main(int argc, char **argv) {
    struct xdp_link_info xdp_info;
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_map *map;
    int prog_fd, map_fd, pin_fd;
    int ifindex;

    if (argc != 2) {
        error(-1, errno, "run with [iface name]");
    }

    if (!(ifindex = if_nametoindex(argv[1]))) {
        error(-1, errno, "if_nametoindex(%s)", argv[1]);
    }

    int xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

    bpf_get_link_xdp_info(ifindex, &xdp_info, 1, 0);
    bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

    struct bpf_object_open_attr attr = {
            .prog_type = BPF_PROG_TYPE_XDP,
            .file = "xdp_ingress_kern.o",
    };

    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        error(-1, errno, "setrlimit(RLIMIT_MEMLOCK)");
    }

    obj = bpf_object__open_xattr(&attr);
    //obj = bpf_object__open_file("xdp_ingress_kern.o", NULL);
    if (libbpf_get_error(obj)) {
        error(1, errno, "bpf_object__open_xattr");
    }

    map = bpf_object__find_map_by_name(obj, "gre_dst");
    if (libbpf_get_error(map)) {
        error(1, errno, "bpf_object__find_map_by_name(%s)", "gre_dst");
    }

    if ((pin_fd = bpf_obj_get(PINNED_FILE)) < 0) {
        error(1, errno, "bpf_obj_get(%s)", PINNED_FILE);
    }

    if(bpf_map__reuse_fd(map, pin_fd)) {
        error(1, errno, "bpf_map__reuse_fd(%d)", pin_fd);
    }

    int err = bpf_object__load(obj);
    if (err) {
        error(1, errno, "bpf_object__load, %s", strerror(errno));
    }

    prog = bpf_object__find_program_by_title(obj, "xdp");
    if (!prog) {
        error(1, errno, "bpf_object__find_program_by_title");
    }

    prog_fd = bpf_program__fd(prog);
    if (!prog_fd) {
        error(1, errno, "bpf_program__fd");
    }

    if (bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags) < 0) {
        error(1, errno, "bpf_set_link_xdp_fd(%s)", attr.file);
    }

    return 1;
}