// SPDX-License-Identifier: GPL-2.0
/* off-CPU：任务离开 CPU 时记下内核栈，再次被调度时累计睡眠时间。 */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct fold_key {
	char comm[16];
	__u32 nr;
	__u64 ips[16];
};

struct start_state {
	__u64 ts;
	struct fold_key key;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct start_state);
} inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct fold_key);
	__type(value, __u64);
} off_ns SEC(".maps");

static __always_inline void add_off(struct fold_key *key, __u64 delta)
{
	__u64 *val = bpf_map_lookup_elem(&off_ns, key);
	if (val)
		__sync_fetch_and_add(val, delta);
	else
		bpf_map_update_elem(&off_ns, key, &delta, BPF_NOEXIST);
}

SEC("tp_btf/sched_switch")
int BPF_PROG(offcpu, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	__u32 prev_pid = BPF_CORE_READ(prev, pid);
	__u32 next_pid = BPF_CORE_READ(next, pid);
	__u64 now = bpf_ktime_get_ns();
	struct start_state *state;
	struct start_state fresh = {};

	(void)preempt;
	state = bpf_map_lookup_elem(&inflight, &next_pid);
	if (state) {
		__u64 delta = now - state->ts;
		if (delta > 1000)
			add_off(&state->key, delta);
		bpf_map_delete_elem(&inflight, &next_pid);
	}

	fresh.ts = now;
	BPF_CORE_READ_STR_INTO(&fresh.key.comm, prev, comm);
	fresh.key.nr = 0;
	if (bpf_get_task_stack(prev, fresh.key.ips, sizeof(fresh.key.ips), 0) > 0)
		fresh.key.nr = sizeof(fresh.key.ips) / sizeof(fresh.key.ips[0]);
	bpf_map_update_elem(&inflight, &prev_pid, &fresh, BPF_ANY);
	return 0;
}
