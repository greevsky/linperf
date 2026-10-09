// SPDX-License-Identifier: GPL-2.0
/* 版权所有 © 2026 lei <mr.greevsky@gmail.com>
 * https://github.com/greevsky/linperf
 * 内核加载要求这段字节码按 GPL 发布。 */
/* on-CPU 采样。perf_event 触发，把内核栈和用户栈记进 stack map。不依赖 vmlinux.h。 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct stack_key {
	__u32 pid;
	__s32 kern_stack;
	__s32 user_stack;
	char comm[16];
};

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

struct bpf_map_def SEC("maps") stacks = {
	.type = BPF_MAP_TYPE_STACK_TRACE,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64) * 32,
	.max_entries = 4096,
};

struct bpf_map_def SEC("maps") counts = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct stack_key),
	.value_size = sizeof(__u64),
	.max_entries = 4096,
};

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

	val = bpf_map_lookup_elem(&counts, &key);
	if (val)
		__sync_fetch_and_add(val, 1);
	else
		bpf_map_update_elem(&counts, &key, &one, BPF_NOEXIST);
	return 0;
}
