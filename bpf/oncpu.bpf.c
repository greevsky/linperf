// SPDX-License-Identifier: GPL-2.0
/* on-CPU 采样。由 perf_event 触发，把内核栈和用户栈记进 stack map。 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct stack_key {
	__u32 pid;
	__s32 kern_stack;
	__s32 user_stack;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, 127 * sizeof(__u64));
	__uint(max_entries, 16384);
} stacks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct stack_key);
	__type(value, __u64);
} stack_counts SEC(".maps");

SEC("perf_event")
int oncpu(struct bpf_perf_event_data *ctx)
{
	struct stack_key key = {};
	__u64 one = 1;
	__u64 id = bpf_get_current_pid_tgid();
	__u64 *val;

	key.pid = id >> 32;
	bpf_get_current_comm(&key.comm, sizeof(key.comm));
	key.kern_stack = bpf_get_stackid(ctx, &stacks, 0);
	key.user_stack = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK);

	val = bpf_map_lookup_elem(&stack_counts, &key);
	if (val)
		__sync_fetch_and_add(val, 1);
	else
		bpf_map_update_elem(&stack_counts, &key, &one, BPF_NOEXIST);
	return 0;
}
