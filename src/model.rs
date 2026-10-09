use serde::Serialize;

/// `/proc/stat` 里的 CPU 累计滴答。guest 时间已经含在 user/nice 里，这里不再单列。
#[derive(Debug, Clone, Serialize)]
pub struct CpuCounters {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
    pub ncpu: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemInfo {
    pub total_kb: u64,
    pub available_kb: u64,
    /// 内核没有 `MemAvailable`（大约 3.14 之前）时，用 MemFree + Buffers + Cached 近似。
    pub available_estimated: bool,
    pub swap_total_kb: u64,
    pub swap_free_kb: u64,
    pub dirty_kb: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct VmCounters {
    pub pswpin: u64,
    pub pswpout: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Default)]
pub struct Pressure {
    pub some_avg10: f64,
    pub some_avg60: f64,
    pub full_avg10: f64,
    pub full_avg60: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskCounters {
    pub name: String,
    pub reads: u64,
    pub read_ms: u64,
    pub writes: u64,
    pub write_ms: u64,
    pub in_flight: u64,
    pub io_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetCounters {
    pub name: String,
    pub rx_bytes: u64,
    pub rx_errs: u64,
    pub rx_drop: u64,
    pub tx_bytes: u64,
    pub tx_errs: u64,
    pub tx_drop: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CgroupCounters {
    pub path: String,
    pub throttled_usec: u64,
    pub nr_throttled: u64,
    pub memory_current: u64,
    pub memory_max: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoadAvg {
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostSample {
    pub mono_ms: u64,
    pub wall_ms: i64,
    pub kernel: String,
    pub cpu: CpuCounters,
    pub mem: MemInfo,
    pub vm: VmCounters,
    pub load: LoadAvg,
    pub psi_cpu: Option<Pressure>,
    pub psi_memory: Option<Pressure>,
    pub psi_io: Option<Pressure>,
    pub disks: Vec<DiskCounters>,
    pub nets: Vec<NetCounters>,
    pub cgroup: Option<CgroupCounters>,
}
