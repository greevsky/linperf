use serde::Serialize;

use crate::rate::Rates;

const CPU_BUSY: f64 = 0.90;
const CPU_BUSY_WITH_LOAD: f64 = 0.80;
const CPU_IOWAIT: f64 = 0.20;
const CPU_STEAL: f64 = 0.10;
const MEM_AVAILABLE: f64 = 0.10;
const PSI_SOME: f64 = 20.0;
const PSI_FULL: f64 = 10.0;
const SWAP_PAGES_PER_SEC: f64 = 50.0;
const DISK_UTIL: f64 = 0.90;
const DISK_AWAIT_MS: f64 = 50.0;
const DISK_UTIL_WITH_AWAIT: f64 = 0.50;
const NET_ERR_PER_SEC: f64 = 1.0;
const CGROUP_THROTTLE: f64 = 0.05;
const CGROUP_MEMORY: f64 = 0.90;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    #[allow(dead_code)]
    Watch,
    Warning,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "信息",
            Severity::Watch => "观察",
            Severity::Warning => "警告",
            Severity::Critical => "严重",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Watch => 1,
            Severity::Warning => 2,
            Severity::Critical => 3,
        }
    }
}

/// 同一严重程度里，先放把时间吃掉的资源，再放它引起的等待。
fn focus_rank(id: &str) -> u8 {
    match id {
        "cpu.iowait" | "memory.swap" => 1,
        _ => 0,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    pub metric: String,
    pub value: f64,
    pub unit: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub summary: String,
    pub evidence: Vec<Evidence>,
    pub next_step: String,
}

pub fn analyze(rates: &Rates) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Some(finding) = cpu_saturated(rates) {
        findings.push(finding);
    }
    if let Some(finding) = cpu_iowait(rates) {
        findings.push(finding);
    }
    if let Some(finding) = cpu_steal(rates) {
        findings.push(finding);
    }
    if let Some(finding) = memory_pressure(rates) {
        findings.push(finding);
    }
    if let Some(finding) = memory_swap(rates) {
        findings.push(finding);
    }
    if let Some(finding) = io_saturated(rates) {
        findings.push(finding);
    }
    if let Some(finding) = net_drops(rates) {
        findings.push(finding);
    }
    if let Some(finding) = cgroup_cpu(rates) {
        findings.push(finding);
    }
    if let Some(finding) = cgroup_memory(rates) {
        findings.push(finding);
    }
    findings.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then_with(|| focus_rank(&a.id).cmp(&focus_rank(&b.id)))
            .then_with(|| a.id.cmp(&b.id))
    });
    if findings.is_empty() {
        findings.push(Finding {
            id: "host.healthy".into(),
            severity: Severity::Info,
            title: "未发现明显瓶颈".into(),
            summary: "这一窗口里的 CPU、内存、磁盘、网络和 cgroup 都没有越过内置阈值。".into(),
            evidence: vec![Evidence {
                metric: "cpu.busy_ratio".into(),
                value: rates.cpu.busy_ratio,
                unit: "ratio".into(),
                note: "非 idle、非 iowait 的时间占比".into(),
            }],
            next_step: "如果体感仍然慢，把采样间隔拉长，或打开 profile 看 on-CPU / off-CPU。".into(),
        });
    }
    findings
}

fn cpu_saturated(rates: &Rates) -> Option<Finding> {
    let load_pressure = rates.load1 >= rates.cpu.ncpu as f64 && rates.cpu.busy_ratio >= CPU_BUSY_WITH_LOAD;
    if rates.cpu.busy_ratio < CPU_BUSY && !load_pressure {
        return None;
    }
    let severity = if rates.cpu.busy_ratio >= 0.97 || rates.load1 >= rates.cpu.ncpu as f64 * 2.0 {
        Severity::Critical
    } else {
        Severity::Warning
    };
    Some(Finding {
        id: "cpu.saturated".into(),
        severity,
        title: "CPU 饱和".into(),
        summary: "可运行任务把 CPU 占满，或者负载已经高于 CPU 数。".into(),
        evidence: vec![
            metric("cpu.busy_ratio", rates.cpu.busy_ratio, "ratio", "user+system+irq+steal"),
            metric("load.1", rates.load1, "tasks", "1 分钟平均负载"),
            metric("cpu.count", rates.cpu.ncpu as f64, "cpus", "逻辑 CPU 数"),
        ],
        next_step: "用 profile oncpu 看是哪些调用栈在消耗 CPU。先确认没有被 cgroup 限流。".into(),
    })
}

fn cpu_iowait(rates: &Rates) -> Option<Finding> {
    if rates.cpu.iowait_ratio < CPU_IOWAIT {
        return None;
    }
    let severity = if rates.cpu.iowait_ratio >= 0.50 {
        Severity::Critical
    } else {
        Severity::Warning
    };
    Some(Finding {
        id: "cpu.iowait".into(),
        severity,
        title: "CPU 大量处在 IO 等待".into(),
        summary: "iowait 升高通常说明任务在等磁盘或下层存储，CPU 本身不一定算力不足。".into(),
        evidence: vec![
            metric("cpu.iowait_ratio", rates.cpu.iowait_ratio, "ratio", "iowait 占全部 CPU 时间"),
            metric("cpu.busy_ratio", rates.cpu.busy_ratio, "ratio", "对照：真正干活的比例"),
        ],
        next_step: "对照 io.saturated 的磁盘 util 和 await。下一步用 profile offcpu 看谁堵在 IO 路径。".into(),
    })
}

fn cpu_steal(rates: &Rates) -> Option<Finding> {
    if rates.cpu.steal_ratio < CPU_STEAL {
        return None;
    }
    Some(Finding {
        id: "cpu.steal".into(),
        severity: if rates.cpu.steal_ratio >= 0.25 {
            Severity::Critical
        } else {
            Severity::Warning
        },
        title: "虚拟机 CPU 被宿主机抽走".into(),
        summary: "steal 来自宿主机或其他虚拟机，客人机里的优化解决不了这部分时间。".into(),
        evidence: vec![metric(
            "cpu.steal_ratio",
            rates.cpu.steal_ratio,
            "ratio",
            "被 hypervisor 占用的比例",
        )],
        next_step: "到宿主机看超分和 CPU 竞争。客人机里只记录，不要把它当成应用热点。".into(),
    })
}

fn memory_pressure(rates: &Rates) -> Option<Finding> {
    let psi = rates.psi_memory;
    let psi_hot = psi.is_some_and(|item| item.some_avg10 >= PSI_SOME || item.full_avg10 >= PSI_FULL);
    if rates.mem_available_ratio >= MEM_AVAILABLE && !psi_hot {
        return None;
    }
    let severity = if rates.mem_available_ratio < 0.05 || psi.is_some_and(|item| item.full_avg10 >= 20.0)
    {
        Severity::Critical
    } else {
        Severity::Warning
    };
    let available_note = if rates.mem_available_estimated {
        "旧内核没有 MemAvailable，用 MemFree+Buffers+Cached 近似"
    } else {
        "MemAvailable / MemTotal"
    };
    let mut evidence = vec![
        metric(
            "mem.available_ratio",
            rates.mem_available_ratio,
            "ratio",
            available_note,
        ),
        metric(
            "mem.available_kb",
            rates.mem_available_kb as f64,
            "kB",
            "仍可立即使用的内存",
        ),
    ];
    if let Some(item) = psi {
        evidence.push(metric(
            "psi.memory.some.avg10",
            item.some_avg10,
            "percent",
            "有任务在等内存的时间占比",
        ));
    }
    Some(Finding {
        id: "memory.pressure".into(),
        severity,
        title: "内存压力".into(),
        summary: "可用内存偏低，或者 PSI 显示已经有任务因为内存停顿。".into(),
        evidence,
        next_step: "看是页缓存回收还是匿名页不足。若同时有 memory.swap，优先找增长最快的进程或 cgroup。".into(),
    })
}

fn memory_swap(rates: &Rates) -> Option<Finding> {
    let pages = rates.swap_in_per_sec + rates.swap_out_per_sec;
    if pages < SWAP_PAGES_PER_SEC {
        return None;
    }
    Some(Finding {
        id: "memory.swap".into(),
        severity: if pages >= 500.0 {
            Severity::Critical
        } else {
            Severity::Warning
        },
        title: "发生换页".into(),
        summary: "采样窗口里有 swap in/out，内存访问会带着磁盘延迟。".into(),
        evidence: vec![
            metric("vm.pswpin_per_sec", rates.swap_in_per_sec, "pages/s", "换入"),
            metric("vm.pswpout_per_sec", rates.swap_out_per_sec, "pages/s", "换出"),
        ],
        next_step: "确认 swappiness 和具体 cgroup 的 memory.max。换页持续时，先停住新增分配。".into(),
    })
}

fn io_saturated(rates: &Rates) -> Option<Finding> {
    let hot = rates.disks.iter().max_by(|a, b| {
        a.util
            .partial_cmp(&b.util)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let disk_hot = hot.is_some_and(|disk| {
        disk.util >= DISK_UTIL || (disk.util >= DISK_UTIL_WITH_AWAIT && disk.await_ms >= DISK_AWAIT_MS)
    });
    let psi_hot = rates
        .psi_io
        .is_some_and(|item| item.some_avg10 >= PSI_SOME || item.full_avg10 >= PSI_FULL);
    if !disk_hot && !psi_hot {
        return None;
    }
    let mut evidence = Vec::new();
    if let Some(disk) = hot.filter(|_| disk_hot) {
        evidence.push(metric(
            format!("disk.util.{}", disk.name),
            disk.util,
            "ratio",
            "io_ticks / 采样时间，多队列设备可以大于 1",
        ));
        evidence.push(metric(
            format!("disk.await_ms.{}", disk.name),
            disk.await_ms,
            "ms",
            "平均每次读写耗时",
        ));
    }
    if let Some(item) = rates.psi_io {
        evidence.push(metric(
            "psi.io.some.avg10",
            item.some_avg10,
            "percent",
            "有任务在等 IO",
        ));
        evidence.push(metric(
            "psi.io.full.avg10",
            item.full_avg10,
            "percent",
            "所有可运行任务都在等 IO",
        ));
    }
    let severe = hot.is_some_and(|disk| disk.util >= 0.95 || disk.await_ms >= 100.0)
        || rates.psi_io.is_some_and(|item| item.full_avg10 >= 20.0);
    Some(Finding {
        id: "io.saturated".into(),
        severity: if severe {
            Severity::Critical
        } else {
            Severity::Warning
        },
        title: "磁盘饱和".into(),
        summary: "块设备利用率或等待时间过高，或者 IO PSI 已经出现停顿。".into(),
        evidence,
        next_step: "先分清是写放大、读放大还是日志刷盘。profile offcpu 可以看调用栈停在哪个 IO 路径。".into(),
    })
}

fn net_drops(rates: &Rates) -> Option<Finding> {
    let mut hot: Vec<_> = rates
        .nets
        .iter()
        .filter(|net| net.errs_per_sec >= NET_ERR_PER_SEC)
        .collect();
    if hot.is_empty() {
        return None;
    }
    hot.sort_by(|a, b| {
        b.errs_per_sec
            .partial_cmp(&a.errs_per_sec)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let evidence = hot
        .iter()
        .take(3)
        .map(|net| {
            metric(
                format!("net.errs_per_sec.{}", net.name),
                net.errs_per_sec,
                "packets/s",
                "rx/tx 的 error 与 drop 之和",
            )
        })
        .collect();
    let worst = hot[0].errs_per_sec;
    Some(Finding {
        id: "net.drops".into(),
        severity: if worst >= 100.0 {
            Severity::Critical
        } else {
            Severity::Warning
        },
        title: "网卡错误或丢包".into(),
        summary: "采样窗口里有网卡计数在增加。这还不能区分本机队列、驱动和链路。".into(),
        evidence,
        next_step: "对照 softnet stat 和网卡驱动计数。应用超时要和这段时间对齐后再下结论。".into(),
    })
}

fn cgroup_cpu(rates: &Rates) -> Option<Finding> {
    let cg = rates.cgroup.as_ref()?;
    if cg.throttle_ratio < CGROUP_THROTTLE {
        return None;
    }
    Some(Finding {
        id: "cgroup.cpu_throttle".into(),
        severity: if cg.throttle_ratio >= 0.20 {
            Severity::Critical
        } else {
            Severity::Warning
        },
        title: "cgroup CPU 被限流".into(),
        summary: format!("cgroup {} 在这个窗口里有一部分时间跑在 cpu.max 之外。", cg.path),
        evidence: vec![
            metric("cgroup.cpu.throttle_ratio", cg.throttle_ratio, "ratio", "throttled_usec / 窗口"),
            metric(
                "cgroup.cpu.nr_throttled_per_sec",
                cg.nr_throttled_per_sec,
                "events/s",
                "被限流的次数",
            ),
        ],
        next_step: "先看 cpu.max 是不是预期配额。配额本身不够时，优化热点也不能提高上限。".into(),
    })
}

fn cgroup_memory(rates: &Rates) -> Option<Finding> {
    let cg = rates.cgroup.as_ref()?;
    let ratio = cg.memory_ratio?;
    if ratio < CGROUP_MEMORY {
        return None;
    }
    Some(Finding {
        id: "cgroup.memory_high".into(),
        severity: if ratio >= 0.98 {
            Severity::Critical
        } else {
            Severity::Warning
        },
        title: "cgroup 内存接近上限".into(),
        summary: format!("cgroup {} 的 memory.current 已经贴近 memory.max。", cg.path),
        evidence: vec![
            metric("cgroup.memory.ratio", ratio, "ratio", "current / max"),
            metric(
                "cgroup.memory.current",
                cg.memory_current as f64,
                "bytes",
                "当前用量",
            ),
        ],
        next_step: "确认上限是保护措施还是容量不足。接近上限后会开始回收，延迟会先于 OOM 出现。".into(),
    })
}

fn metric(name: impl Into<String>, value: f64, unit: &str, note: &str) -> Evidence {
    Evidence {
        metric: name.into(),
        value,
        unit: unit.into(),
        note: note.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo;
    use crate::rate::between;

    #[test]
    fn disk_demo_points_at_io_and_iowait() {
        let samples = demo::timeline();
        let rates = between(&samples[2], &samples[3]).unwrap();
        let findings = analyze(&rates);
        let ids: Vec<_> = findings.iter().map(|item| item.id.as_str()).collect();
        assert!(ids.contains(&"io.saturated"), "{ids:?}");
        assert!(ids.contains(&"cpu.iowait"), "{ids:?}");
        assert_eq!(findings[0].id, "io.saturated");
        assert!(findings.iter().any(|item| item.severity == Severity::Critical));
        assert!(findings
            .iter()
            .flat_map(|item| &item.evidence)
            .any(|item| item.metric.starts_with("disk.util.")));
    }

    #[test]
    fn quiet_host_stays_healthy() {
        let samples = demo::timeline();
        let rates = between(&samples[0], &samples[1]).unwrap();
        let findings = analyze(&rates);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "host.healthy");
    }
}
