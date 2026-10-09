use serde::Serialize;

use crate::analyze::Finding;
use crate::compat::HostCaps;
use crate::model::HostSample;
use crate::procs::ProcRate;
use crate::rate::Rates;

#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub version: u32,
    pub host: HostCaps,
    pub demo: bool,
    pub rates: Rates,
    pub findings: Vec<Finding>,
    pub processes: Vec<ProcRate>,
    pub samples: Vec<HostSample>,
}

pub fn format_text(snapshot: &Snapshot) -> String {
    let rates = &snapshot.rates;
    let mut lines = Vec::new();
    lines.push(format!(
        "linperf  定位{}",
        if snapshot.demo { "（演示数据）" } else { "" }
    ));
    if let Some(finding) = snapshot.findings.first() {
        lines.push(format!(
            "瓶颈    [{}] {} ({})",
            finding.severity.label(),
            finding.title,
            finding.id
        ));
        lines.push(format!("        {}", finding.summary));
        for evidence in &finding.evidence {
            lines.push(format!(
                "        {} = {} {}  {}",
                evidence.metric,
                format_value(evidence.value),
                evidence.unit,
                evidence.note
            ));
        }
        lines.push(format!("        下一步: {}", finding.next_step));
        let action = crate::advise::action(finding, &snapshot.processes);
        if !action.actors.is_empty() {
            lines.push("        相关进程".into());
            for proc in &action.actors {
                lines.push(format!(
                    "        {} pid {}  CPU {}  RSS {}  读 {}  写 {}  {}",
                    proc.comm,
                    proc.pid,
                    crate::procs::cpu_percent(proc.cpu_ratio),
                    crate::procs::human_kb(proc.rss_kb),
                    crate::procs::human_bps(proc.read_bps),
                    crate::procs::human_bps(proc.write_bps),
                    crate::procs::state_label(&proc.state),
                ));
            }
        }
        lines.push(format!("        建议: {}", action.suggestion));
    }
    lines.push(String::new());
    lines.push(format!(
        "现场    {}  {}  间隔 {:.1}s",
        snapshot.host.os, snapshot.host.kernel, rates.interval_secs
    ));
    lines.push(format!(
        "CPU     busy {}  user {}  system {}  iowait {}  steal {}  idle {}",
        pct(rates.cpu.busy_ratio),
        pct(rates.cpu.user_ratio),
        pct(rates.cpu.system_ratio),
        pct(rates.cpu.iowait_ratio),
        pct(rates.cpu.steal_ratio),
        pct(rates.cpu.idle_ratio),
    ));
    let estimated = if rates.mem_available_estimated {
        "  近似"
    } else {
        ""
    };
    lines.push(format!(
        "内存    available {} ({:.1} GiB / {:.1} GiB){estimated}",
        pct(rates.mem_available_ratio),
        kb_gib(rates.mem_available_kb),
        kb_gib(rates.mem_total_kb),
    ));
    lines.push(format!(
        "负载    {:.2} {:.2} {:.2}  / {} CPU",
        rates.load1, rates.load5, rates.load15, rates.cpu.ncpu
    ));
    if let Some(disk) = rates.disks.iter().max_by(|a, b| {
        a.util
            .partial_cmp(&b.util)
            .unwrap_or(std::cmp::Ordering::Equal)
    }) {
        lines.push(format!(
            "磁盘    {} util {}  await {:.1} ms  read {:.0} iops  write {:.0} iops",
            disk.name,
            pct(disk.util.min(1.0)),
            disk.await_ms,
            disk.read_iops,
            disk.write_iops
        ));
    }
    if let Some(psi) = rates.psi_io {
        lines.push(format!(
            "PSI io  some10 {:.1}%  full10 {:.1}%",
            psi.some_avg10, psi.full_avg10
        ));
    }
    if snapshot.findings.len() > 1 {
        lines.push(String::new());
        lines.push("其余结论".into());
        for finding in snapshot.findings.iter().skip(1) {
            lines.push(format!(
                "- [{}] {} ({})",
                finding.severity.label(),
                finding.title,
                finding.id
            ));
            lines.push(format!("  {}", finding.summary));
            lines.push(format!("  下一步: {}", finding.next_step));
        }
    }
    lines.join("\n")
}

fn pct(ratio: f64) -> String {
    format!("{:.1}%", ratio * 100.0)
}

fn kb_gib(kb: u64) -> f64 {
    kb as f64 / 1024.0 / 1024.0
}

fn format_value(value: f64) -> String {
    if value.abs() >= 100.0 {
        format!("{value:.0}")
    } else {
        format!("{value:.3}")
    }
}
