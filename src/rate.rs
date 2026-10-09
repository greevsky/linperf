use serde::Serialize;

use crate::error::{Error, Result};
use crate::model::{CgroupCounters, DiskCounters, HostSample, NetCounters, Pressure};

#[derive(Debug, Clone, Serialize)]
pub struct CpuRates {
    pub busy_ratio: f64,
    pub user_ratio: f64,
    pub system_ratio: f64,
    pub iowait_ratio: f64,
    pub irq_ratio: f64,
    pub steal_ratio: f64,
    pub idle_ratio: f64,
    pub ncpu: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskRates {
    pub name: String,
    pub util: f64,
    pub await_ms: f64,
    pub read_iops: f64,
    pub write_iops: f64,
    pub in_flight: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetRates {
    pub name: String,
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
    pub errs_per_sec: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CgroupRates {
    pub path: String,
    pub throttle_ratio: f64,
    pub nr_throttled_per_sec: f64,
    pub memory_current: u64,
    pub memory_max: Option<u64>,
    pub memory_ratio: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Rates {
    pub interval_secs: f64,
    pub cpu: CpuRates,
    pub mem_available_ratio: f64,
    pub mem_available_estimated: bool,
    pub mem_total_kb: u64,
    pub mem_available_kb: u64,
    pub dirty_kb: u64,
    pub swap_in_per_sec: f64,
    pub swap_out_per_sec: f64,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    pub psi_cpu: Option<Pressure>,
    pub psi_memory: Option<Pressure>,
    pub psi_io: Option<Pressure>,
    pub disks: Vec<DiskRates>,
    pub nets: Vec<NetRates>,
    pub cgroup: Option<CgroupRates>,
}

pub fn between(prev: &HostSample, curr: &HostSample) -> Result<Rates> {
    if curr.mono_ms <= prev.mono_ms {
        return Err(Error::NeedTwoSamples);
    }
    let interval_ms = (curr.mono_ms - prev.mono_ms) as f64;
    let interval_secs = interval_ms / 1000.0;
    let cpu = cpu_rates(&prev.cpu, &curr.cpu);
    let mem_total = curr.mem.total_kb.max(1);
    Ok(Rates {
        interval_secs,
        cpu,
        mem_available_ratio: curr.mem.available_kb as f64 / mem_total as f64,
        mem_available_estimated: curr.mem.available_estimated,
        mem_total_kb: curr.mem.total_kb,
        mem_available_kb: curr.mem.available_kb,
        dirty_kb: curr.mem.dirty_kb,
        swap_in_per_sec: per_sec(prev.vm.pswpin, curr.vm.pswpin, interval_secs),
        swap_out_per_sec: per_sec(prev.vm.pswpout, curr.vm.pswpout, interval_secs),
        load1: curr.load.load1,
        load5: curr.load.load5,
        load15: curr.load.load15,
        psi_cpu: curr.psi_cpu,
        psi_memory: curr.psi_memory,
        psi_io: curr.psi_io,
        disks: disk_rates(&prev.disks, &curr.disks, interval_ms),
        nets: net_rates(&prev.nets, &curr.nets, interval_secs),
        cgroup: cgroup_rates(prev.cgroup.as_ref(), curr.cgroup.as_ref(), interval_secs),
    })
}

fn cpu_rates(prev: &crate::model::CpuCounters, curr: &crate::model::CpuCounters) -> CpuRates {
    let user = delta(prev.user, curr.user);
    let nice = delta(prev.nice, curr.nice);
    let system = delta(prev.system, curr.system);
    let idle = delta(prev.idle, curr.idle);
    let iowait = delta(prev.iowait, curr.iowait);
    let irq = delta(prev.irq, curr.irq);
    let softirq = delta(prev.softirq, curr.softirq);
    let steal = delta(prev.steal, curr.steal);
    let total = user + nice + system + idle + iowait + irq + softirq + steal;
    let ratio = |part: u64| {
        if total == 0 {
            0.0
        } else {
            part as f64 / total as f64
        }
    };
    let busy = user + nice + system + irq + softirq + steal;
    CpuRates {
        busy_ratio: ratio(busy),
        user_ratio: ratio(user + nice),
        system_ratio: ratio(system),
        iowait_ratio: ratio(iowait),
        irq_ratio: ratio(irq + softirq),
        steal_ratio: ratio(steal),
        idle_ratio: ratio(idle),
        ncpu: curr.ncpu.max(1),
    }
}

fn disk_rates(prev: &[DiskCounters], curr: &[DiskCounters], interval_ms: f64) -> Vec<DiskRates> {
    curr.iter()
        .filter_map(|disk| {
            let old = prev.iter().find(|item| item.name == disk.name)?;
            let reads = delta(old.reads, disk.reads);
            let writes = delta(old.writes, disk.writes);
            let ops = reads + writes;
            let op_ms = delta(old.read_ms, disk.read_ms) + delta(old.write_ms, disk.write_ms);
            let await_ms = if ops == 0 {
                0.0
            } else {
                op_ms as f64 / ops as f64
            };
            let util = if interval_ms <= 0.0 {
                0.0
            } else {
                delta(old.io_ms, disk.io_ms) as f64 / interval_ms
            };
            let secs = interval_ms / 1000.0;
            Some(DiskRates {
                name: disk.name.clone(),
                util,
                await_ms,
                read_iops: reads as f64 / secs,
                write_iops: writes as f64 / secs,
                in_flight: disk.in_flight,
            })
        })
        .collect()
}

fn net_rates(prev: &[NetCounters], curr: &[NetCounters], interval_secs: f64) -> Vec<NetRates> {
    curr.iter()
        .filter_map(|net| {
            let old = prev.iter().find(|item| item.name == net.name)?;
            let errs = delta(old.rx_errs, net.rx_errs)
                + delta(old.rx_drop, net.rx_drop)
                + delta(old.tx_errs, net.tx_errs)
                + delta(old.tx_drop, net.tx_drop);
            Some(NetRates {
                name: net.name.clone(),
                rx_bytes_per_sec: per_sec(old.rx_bytes, net.rx_bytes, interval_secs),
                tx_bytes_per_sec: per_sec(old.tx_bytes, net.tx_bytes, interval_secs),
                errs_per_sec: errs as f64 / interval_secs,
            })
        })
        .collect()
}

fn cgroup_rates(
    prev: Option<&CgroupCounters>,
    curr: Option<&CgroupCounters>,
    interval_secs: f64,
) -> Option<CgroupRates> {
    let curr = curr?;
    let prev = prev.filter(|item| item.path == curr.path);
    let throttled = prev
        .map(|item| delta(item.throttled_usec, curr.throttled_usec))
        .unwrap_or(0);
    let nr = prev
        .map(|item| delta(item.nr_throttled, curr.nr_throttled))
        .unwrap_or(0);
    let interval_usec = interval_secs * 1_000_000.0;
    let memory_ratio = curr
        .memory_max
        .filter(|max| *max > 0)
        .map(|max| curr.memory_current as f64 / max as f64);
    Some(CgroupRates {
        path: curr.path.clone(),
        throttle_ratio: if interval_usec <= 0.0 {
            0.0
        } else {
            throttled as f64 / interval_usec
        },
        nr_throttled_per_sec: nr as f64 / interval_secs,
        memory_current: curr.memory_current,
        memory_max: curr.memory_max,
        memory_ratio,
    })
}

fn delta(prev: u64, curr: u64) -> u64 {
    curr.saturating_sub(prev)
}

fn per_sec(prev: u64, curr: u64, interval_secs: f64) -> f64 {
    if interval_secs <= 0.0 {
        0.0
    } else {
        delta(prev, curr) as f64 / interval_secs
    }
}
