use std::thread;
use std::time::Duration;

use crate::advise;
use crate::analyze;
use crate::collect;
use crate::compat::{self, HostCaps};
use crate::demo;
use crate::error::{Error, Result};
use crate::model::HostSample;
use crate::procs::{self, ProcRate};
use crate::rate::{self, Rates};
use crate::report::{self, Snapshot};

pub fn check_text() -> Result<String> {
    Ok(compat::format_check(&compat::detect()?))
}

pub fn snapshot(interval_secs: u64, demo: bool) -> Result<Snapshot> {
    if demo {
        return demo_snapshot();
    }
    let host = compat::detect()?;
    if !host.plan().counters {
        return Err(Error::NotLinux);
    }
    let first = collect::capture_live()?;
    let first_procs = procs::capture();
    thread::sleep(Duration::from_secs(interval_secs.max(1)));
    let second = collect::capture_live()?;
    let second_procs = procs::capture();
    let mut snapshot = finish(host, false, first, second)?;
    snapshot.processes = procs::diff(&first_procs, &second_procs, 25);
    Ok(snapshot)
}

fn demo_snapshot() -> Result<Snapshot> {
    let mut samples = demo::timeline();
    let curr = samples.pop().expect("demo timeline");
    let prev = samples.pop().expect("demo timeline");
    let mut snapshot = finish(demo_host(), true, prev, curr)?;
    snapshot.processes = demo::demo_processes(true);
    Ok(snapshot)
}

fn finish(host: HostCaps, demo: bool, prev: HostSample, curr: HostSample) -> Result<Snapshot> {
    let rates = rate::between(&prev, &curr)?;
    let findings = analyze::analyze(&rates);
    Ok(Snapshot {
        version: 3,
        host,
        demo,
        rates,
        findings,
        processes: Vec::new(),
        samples: vec![prev, curr],
    })
}

pub fn demo_frame(index: usize) -> Result<(Rates, Vec<analyze::Finding>, Vec<ProcRate>, usize)> {
    let samples = demo::timeline();
    let last = samples.len() - 1;
    let index = index.clamp(1, last);
    let rates = rate::between(&samples[index - 1], &samples[index])?;
    let findings = analyze::analyze(&rates);
    let processes = demo::demo_processes(index == last);
    Ok((rates, findings, processes, index))
}

pub fn demo_len() -> usize {
    demo::timeline().len()
}

fn demo_host() -> HostCaps {
    HostCaps {
        os: "临机演示".into(),
        kernel: "demo".into(),
        arch: std::env::consts::ARCH.into(),
        procfs: true,
        psi: true,
        distro_id: "demo".into(),
        cgroup_v2: true,
        cgroup_layout: "v2".into(),
        in_container: false,
        cgroup_path: "/".into(),
        virt: "none".into(),
        perf_event_paranoid: None,
        btf: false,
        cap_bpf: false,
        cap_perfmon: false,
        cap_sys_admin: false,
        ebpf_linked: false,
    }
}

pub fn format_snapshot_text(snapshot: &Snapshot) -> String {
    report::format_text(snapshot)
}

pub fn process_table(interval_secs: u64, query: &str) -> Result<Vec<ProcRate>> {
    let first = procs::capture();
    thread::sleep(Duration::from_secs(interval_secs.max(1)));
    let second = procs::capture();
    let self_pid = std::process::id() as i32;
    let rows = if query.trim().is_empty() {
        let mut rows = procs::diff(&first, &second, 21);
        rows.retain(|proc| proc.pid != self_pid);
        rows.truncate(20);
        rows
    } else {
        let mut rows = procs::diff_for_query(&first, &second, query);
        rows.retain(|proc| proc.pid != self_pid);
        rows
    };
    Ok(rows)
}

pub fn inspect_text(interval_secs: u64, pid: i32) -> Result<String> {
    if !procs::proc_exists(pid) {
        return Err(Error::Message(format!("没有 pid {pid}")));
    }
    let host = compat::detect()?;
    let first_host = collect::capture_live().ok();
    let first_procs = procs::capture();
    thread::sleep(Duration::from_secs(interval_secs.max(1)));
    let second_host = collect::capture_live().ok();
    let second_procs = procs::capture();
    let proc = procs::diff_pid(&first_procs, &second_procs, pid).ok_or_else(|| {
        Error::Message(format!("pid {pid} 在采样期间退出，或两次读到的命令名不一致"))
    })?;
    let extra = procs::extra(pid);
    let mut lines = Vec::new();
    lines.push(format!(
        "{}  进程 {}  pid {}    {} {}",
        crate::identity::PRODUCT,
        proc.comm, proc.pid, host.os, host.kernel
    ));
    lines.push(format!(
        "身份    用户 {}  父进程 {}  状态 {}",
        extra.user,
        proc.ppid,
        procs::state_label(&proc.state)
    ));
    lines.push(format!("命令    {}", procs::display_cmd(&proc, 120)));
    if !extra.cgroup.is_empty() {
        lines.push(format!("cgroup  {}", extra.cgroup));
    }
    if let (Some(host_a), Some(host_b)) = (first_host, second_host) {
        if let Ok(rates) = rate::between(&host_a, &host_b) {
            let findings = analyze::analyze(&rates);
            if let Some(finding) = findings.first() {
                lines.push(format!(
                    "整机    [{}] {}",
                    finding.severity.label(),
                    finding.title
                ));
            }
        }
    } else {
        lines.push(format!("整机    {} 上的计数这次没有采到", host.os));
    }
    lines.push(String::new());
    lines.push(format!(
        "CPU     {}   线程 {}   自愿切换 {:.0}/s   非自愿 {:.0}/s",
        procs::cpu_percent(proc.cpu_ratio),
        proc.threads,
        proc.vol_ctxt_per_sec,
        proc.nonvol_ctxt_per_sec
    ));
    lines.push(format!(
        "内存    RSS {}   虚拟 {}   换出 {}",
        procs::human_kb(proc.rss_kb),
        procs::human_kb(proc.vmsize_kb),
        procs::human_kb(proc.vmswap_kb)
    ));
    lines.push(format!(
        "磁盘    读 {}   写 {}",
        procs::human_bps(proc.read_bps),
        procs::human_bps(proc.write_bps)
    ));
    let wchan = if proc.wchan.is_empty() {
        "没有"
    } else {
        proc.wchan.as_str()
    };
    lines.push(format!("等待    {wchan}"));
    match (extra.fd_count, extra.nofile_soft) {
        (Some(fd), Some(limit)) => lines.push(format!("描述符  {fd} / 软限制 {limit}")),
        (Some(fd), None) => lines.push(format!("描述符  {fd}")),
        _ => lines.push("描述符  读不到 /proc/<pid>/fd".into()),
    }
    if let Some(stack) = &extra.stack {
        lines.push(String::new());
        lines.push("内核栈".into());
        lines.push(stack.clone());
    }
    lines.push(String::new());
    lines.push(format!("建议    {}", advise::for_process(&proc, Some(&extra))));
    crate::identity::sign(&mut lines);
    Ok(lines.join("\n"))
}
