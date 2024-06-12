#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define DEFAULT_PORT 4040
#define PROCESS_NAME "myprocess"

struct bpf_map_def SEC("maps") allowed_port_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

SEC("cgroup_skb/egress")
int filter_packets(struct __sk_buff *skb) {
    __u32 pid;
    __u64 id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    
    struct task_struct *task;
    char comm[16];
    
    task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel_str(&comm, sizeof(comm), task->comm);

    if (__builtin_memcmp(comm, PROCESS_NAME, sizeof(PROCESS_NAME) - 1) != 0) {
        return 1; // Allow packets from other processes
    }

    __u32 *allowed_port;
    __u32 key = 0;
    allowed_port = bpf_map_lookup_elem(&allowed_port_map, &key);
    if (!allowed_port) {
        return 1;
    }

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return 1;

    if (eth->h_proto != htons(ETH_P_IP)) return 1;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return 1;

    if (ip->protocol != IPPROTO_TCP) return 1;

    struct tcphdr *tcp = (struct tcphdr *)((__u8 *)ip + (ip->ihl * 4));
    if ((void *)(tcp + 1) > data_end) return 1;

    if (tcp->dest != htons(*allowed_port)) {
        return 0; // Drop the packet
    }

    return 1; // Allow the packet
}

char _license[] SEC("license") = "GPL";
