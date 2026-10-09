// SPDX-License-Identifier: GPL-2.0
/* 版权所有 © 2026 lei <mr.greevsky@gmail.com>
 * https://github.com/greevsky/linperf
 * 内核加载要求这段字节码按 GPL 发布。 */
/* off-CPU：sched_switch 原始 tracepoint，不使用 CO-RE。 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct sched_switch_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	char prev_comm[16];
	int prev_pid;
	int prev_prio;
	long prev_state;
	char next_comm[16];
	int next_pid;
	int next_prio;
};

struct fold_key {
	char comm[16];
	__u32 pid;
	__u32 nr;
	__u64 ips[16];
};

struct start_state {
	__u64 ts;
	struct fold_key key;
};

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

struct bpf_map_def SEC("maps") inflight = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct start_state),
	.max_entries = 10240,
};

struct bpf_map_def SEC("maps") off_ns = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct fold_key),
	.value_size = sizeof(__u64),
	.max_entries = 8192,
};

/* key 0：0 表示不过滤，否则只记录这个线程组。 */
struct bpf_map_def SEC("maps") target = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
};

static __always_inline int wanted(__u32 pid)
{
	__u32 key = 0;
	__u32 *cfg = bpf_map_lookup_elem(&target, &key);
	if (!cfg || *cfg == 0)
		return 1;
	return pid == *cfg;
}

static __always_inline void add_off(struct fold_key *key, __u64 delta)
{
	__u64 *val = bpf_map_lookup_elem(&off_ns, key);
	if (val)
		__sync_fetch_and_add(val, delta);
	else
		bpf_map_update_elem(&off_ns, key, &delta, BPF_NOEXIST);
}

SEC("tracepoint/sched/sched_switch")
int offcpu(struct sched_switch_args *ctx)
{
	__u32 prev_pid = (__u32)ctx->prev_pid;
	__u32 next_pid = (__u32)ctx->next_pid;
	__u64 now = bpf_ktime_get_ns();
	__u64 current_id = bpf_get_current_pid_tgid();
	__u32 tgid = current_id >> 32;
	struct start_state *state;
	struct start_state fresh = {};
	long got;

	state = bpf_map_lookup_elem(&inflight, &next_pid);
	if (state) {
		__u64 delta = now - state->ts;
		if (delta > 1000)
			add_off(&state->key, delta);
		bpf_map_delete_elem(&inflight, &next_pid);
	}

	if (!wanted(tgid) || prev_pid == 0)
		return 0;
	fresh.ts = now;
	__builtin_memcpy(fresh.key.comm, ctx->prev_comm, sizeof(fresh.key.comm));
	fresh.key.pid = prev_pid;
	got = bpf_get_stack(ctx, fresh.key.ips, sizeof(fresh.key.ips), 0);
	if (got > 0)
		fresh.key.nr = (__u32)(got / (long)sizeof(fresh.key.ips[0]));
	bpf_map_update_elem(&inflight, &prev_pid, &fresh, BPF_ANY);
	return 0;
}
