use crate::analyze::Finding;
use crate::procs::{self, ProcExtra, ProcRate};

#[derive(Debug, Clone)]
pub struct Action {
    pub actors: Vec<ProcRate>,
    pub suggestion: String,
}

pub fn action(finding: &Finding, procs: &[ProcRate]) -> Action {
    let actors = rank(finding.id.as_str(), procs);
    let suggestion = match finding.id.as_str() {
        "io.saturated" | "cpu.iowait" => io_advice(&actors),
        "cpu.saturated" | "cgroup.cpu_throttle" => cpu_advice(finding.id.as_str(), &actors),
        "memory.pressure" | "memory.swap" | "cgroup.memory_high" => mem_advice(finding.id.as_str(), &actors),
        "cpu.steal" => "steal 是宿主机抽走的时间。客人机里改代码或加线程都补不回。向宿主机要独占核，或降低超分。".into(),
        "net.drops" => "丢包记在网卡上。先加大网卡队列并核对 softnet backlog，再把超时的服务和这个时间段对齐。这次没有拆到每个进程的连接。".into(),
        "host.healthy" => "这一窗口没有越过阈值。卡顿如果已经过去，这次对不上；下次卡顿还在时再跑 snapshot 或 watch。".into(),
        _ => finding.next_step.clone(),
    };
    Action { actors, suggestion }
}

pub fn for_process(proc: &ProcRate, extra: Option<&ProcExtra>) -> String {
    let mut parts = Vec::new();
    if proc.state == "D" {
        let wchan = if proc.wchan.is_empty() {
            "未知等待点".into()
        } else {
            proc.wchan.clone()
        };
        parts.push(format!(
            "状态是不可中断睡眠，停在 {wchan}。这是在等磁盘或锁，加 CPU 没有用。先降这个进程的读写：日志改异步、合并 fsync，或把日志和数据分到不同磁盘。"
        ));
    }
    if proc.cpu_ratio >= 0.9 {
        parts.push(format!(
            "CPU 约 {}，线程 {}。先确认线程池是不是把核打满；能加副本就水平扩展。函数级热点要等 eBPF 栈采样编进二进制。",
            procs::cpu_percent(proc.cpu_ratio),
            proc.threads
        ));
    }
    if proc.write_bps + proc.read_bps >= 5_000_000.0 {
        parts.push(format!(
            "读 {}，写 {}。写多就查日志和刷盘周期；读多就查是否缺少缓存或在反复扫盘。",
            procs::human_bps(proc.read_bps),
            procs::human_bps(proc.write_bps)
        ));
    }
    if proc.vmswap_kb > 0 {
        parts.push(format!(
            "已有 {} 换出。先停住这个进程的新增分配，再考虑加内存。",
            procs::human_kb(proc.vmswap_kb)
        ));
    }
    if let Some(extra) = extra {
        if let (Some(fd), Some(limit)) = (extra.fd_count, extra.nofile_soft) {
            if limit > 0 && fd as u64 * 100 / limit >= 80 {
                parts.push(format!(
                    "文件描述符 {fd}，软限制 {limit}。先查连接或文件是否泄漏，再考虑提高 nofile。"
                ));
            }
        }
        if extra.stack.is_none() && proc.state == "D" {
            parts.push("内核栈读不到。用 root 或 CAP_SYS_PTRACE 再看 /proc/<pid>/stack，才能从 wchan 走到具体函数。".into());
        }
    }
    if parts.is_empty() {
        parts.push(format!(
            "{} 这一窗口没有单项打满。CPU {}，RSS {}，读 {}，写 {}。若业务仍慢，对照整机结论看是不是别的进程或宿主机。",
            proc.comm,
            procs::cpu_percent(proc.cpu_ratio),
            procs::human_kb(proc.rss_kb),
            procs::human_bps(proc.read_bps),
            procs::human_bps(proc.write_bps),
        ));
    }
    parts.join(" ")
}

fn rank(id: &str, procs: &[ProcRate]) -> Vec<ProcRate> {
    let mut rows = procs.to_vec();
    rows.sort_by(|a, b| {
        rank_key(id, b)
            .partial_cmp(&rank_key(id, a))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    rows.truncate(3);
    rows.retain(|proc| rank_key(id, proc) > 0.0);
    rows
}

fn rank_key(id: &str, proc: &ProcRate) -> f64 {
    match id {
        "io.saturated" | "cpu.iowait" => {
            let bytes = proc.write_bps + proc.read_bps;
            if proc.state != "D" && bytes < 1_000_000.0 {
                return 0.0;
            }
            let waiting = if proc.state == "D" { 1.0 } else { 0.0 };
            bytes / 1_000_000.0 + waiting
        }
        "cpu.saturated" | "cgroup.cpu_throttle" => {
            if proc.cpu_ratio < 0.15 {
                0.0
            } else {
                proc.cpu_ratio
            }
        }
        "memory.pressure" | "memory.swap" | "cgroup.memory_high" => {
            if proc.rss_kb < 10_240 && proc.vmswap_kb == 0 {
                0.0
            } else {
                proc.rss_kb as f64 / 1024.0 + proc.vmswap_kb as f64 / 1024.0
            }
        }
        _ => 0.0,
    }
}

fn io_advice(actors: &[ProcRate]) -> String {
    let Some(top) = actors.first() else {
        return "磁盘已经饱和，但用户进程读写不突出。先看内核回写和文件系统日志。函数级路径要等 off-CPU 采样可用。".into();
    };
    format!(
        "优先处理 {} (pid {})：读 {}，写 {}，状态 {}{}。把这个进程的日志改成异步或批量刷盘，日志和数据分盘；它若在 cgroup 里，用 io.max 限制写带宽，避免拖垮整机。不要为这种等待去加 CPU。",
        top.comm,
        top.pid,
        procs::human_bps(top.read_bps),
        procs::human_bps(top.write_bps),
        procs::state_label(&top.state),
        wchan_phrase(&top.wchan),
    )
}

fn cpu_advice(id: &str, actors: &[ProcRate]) -> String {
    let quota = if id == "cgroup.cpu_throttle" {
        "当前 cgroup 还被 cpu.max 限流。配额是上限，热点优化也过不了这个线；先确认配额是否故意，再决定提高 cpu.max 或把进程移出去。"
    } else {
        "整机 CPU 已经饱和。"
    };
    let Some(top) = actors.first() else {
        return format!("{quota} 没有单个用户进程占满。可能是很多进程分摊，或开销在内核线程。");
    };
    format!(
        "{quota} 最明显的是 {} (pid {})，约 {}，{} 个线程。线程数符合预期就水平加副本；单线程打满时加核帮助有限。函数级热点这次还采不了栈。",
        top.comm,
        top.pid,
        procs::cpu_percent(top.cpu_ratio),
        top.threads
    )
}

fn mem_advice(id: &str, actors: &[ProcRate]) -> String {
    let lead = match id {
        "memory.swap" => "已经在换页。",
        "cgroup.memory_high" => "cgroup 内存贴近上限，回收会先于 OOM 出现。",
        _ => "可用内存偏低。",
    };
    let Some(top) = actors.first() else {
        return format!("{lead} 没有单个进程的 RSS 特别突出，先看页缓存和内核回收。");
    };
    let swap = if top.vmswap_kb > 0 {
        format!("，其中换出 {}", procs::human_kb(top.vmswap_kb))
    } else {
        String::new()
    };
    format!(
        "{lead} {} (pid {}) RSS {}{swap}。先确认是缓存还是泄漏；给它的 cgroup 设 memory.high，避免一个进程把整机推进换页。持续上涨时先停住新增分配，再考虑加内存。",
        top.comm, top.pid, procs::human_kb(top.rss_kb)
    )
}

fn wchan_phrase(wchan: &str) -> String {
    if wchan.is_empty() {
        String::new()
    } else {
        format!("，停在 {wchan}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::{analyze, Severity};
    use crate::demo;
    use crate::rate::between;

    fn fio() -> ProcRate {
        ProcRate {
            pid: 4242,
            comm: "fio".into(),
            cmdline: "fio --name=write --rw=write".into(),
            state: "D".into(),
            ppid: 1,
            uid: 0,
            cpu_ratio: 0.2,
            rss_kb: 200_000,
            vmsize_kb: 400_000,
            vmswap_kb: 0,
            threads: 2,
            read_bps: 1_000_000.0,
            write_bps: 80_000_000.0,
            vol_ctxt_per_sec: 10.0,
            nonvol_ctxt_per_sec: 1.0,
            wchan: "io_schedule".into(),
        }
    }

    #[test]
    fn disk_finding_names_the_writer() {
        let samples = demo::timeline();
        let rates = between(&samples[2], &samples[3]).unwrap();
        let findings = analyze(&rates);
        let io = findings.iter().find(|item| item.id == "io.saturated").unwrap();
        assert_eq!(io.severity, Severity::Critical);
        let action = action(io, &[fio()]);
        assert_eq!(action.actors[0].pid, 4242);
        assert!(action.suggestion.contains("fio"));
        assert!(action.suggestion.contains("不要为这种等待去加 CPU"));
    }
}
