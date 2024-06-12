#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>

#define PATH_MAX 4096
#define DROP_PORT_MAP_PATH "/sys/fs/bpf/drop_port_map"
#define DEFAULT_DROP_PORT 4040

static int bump_memlock_rlimit(void) {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    return setrlimit(RLIMIT_MEMLOCK, &r);
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    int prog_fd, map_fd;
    char filename[PATH_MAX];
    char *prog_name = "xdp_drop_tcp_port";
    int err;

    if (argc < 2) {
        printf("Usage: %s <port>\n", argv[0]);
        return 1;
    }

    int port = atoi(argv[1]);

    bump_memlock_rlimit();

    snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

    prog_fd = bpf_program__fd(bpf_object__find_program_by_title(obj, prog_name));
    if (prog_fd < 0) {
        fprintf(stderr, "ERROR: finding a program in the object file failed\n");
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "drop_port_map");
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: finding a map in the object file failed\n");
        return 1;
    }

    __u32 key = 0;
    __u32 value = port;
    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
        fprintf(stderr, "ERROR: updating map\n");
        return 1;
    }

    printf("Successfully updated the drop port to %d\n", port);

    return 0;
}
