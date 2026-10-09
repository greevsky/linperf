use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};
use crate::model::HostSample;
use crate::parse;

pub fn capture_live() -> Result<HostSample> {
    #[cfg(target_os = "linux")]
    {
        capture_linux()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Error::NotLinux)
    }
}

#[cfg(target_os = "linux")]
fn capture_linux() -> Result<HostSample> {
    let stat = fs::read_to_string("/proc/stat")?;
    let meminfo = fs::read_to_string("/proc/meminfo")?;
    let vmstat = fs::read_to_string("/proc/vmstat").unwrap_or_default();
    let loadavg = fs::read_to_string("/proc/loadavg")?;
    let diskstats = fs::read_to_string("/proc/diskstats").unwrap_or_default();
    let netdev = fs::read_to_string("/proc/net/dev").unwrap_or_default();
    let softnet = fs::read_to_string("/proc/net/softnet_stat").unwrap_or_default();
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|text| text.trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let cgroup_text = fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    let cgroup_path = parse::parse_cgroup_path(&cgroup_text).unwrap_or_else(|| "/".into());
    Ok(HostSample {
        mono_ms: uptime_ms()?,
        wall_ms: wall_ms(),
        kernel,
        cpu: parse::parse_proc_stat(&stat)?,
        mem: parse::parse_meminfo(&meminfo)?,
        vm: parse::parse_vmstat(&vmstat),
        load: parse::parse_loadavg(&loadavg)?,
        psi_cpu: read_pressure("/proc/pressure/cpu"),
        psi_memory: read_pressure("/proc/pressure/memory"),
        psi_io: read_pressure("/proc/pressure/io"),
        disks: parse::parse_diskstats(&diskstats),
        nets: parse::parse_netdev(&netdev),
        softnet: parse::parse_softnet(&softnet),
        cgroup: read_cgroup(&cgroup_text, &cgroup_path),
    })
}

#[cfg(target_os = "linux")]
fn read_pressure(path: &str) -> Option<crate::model::Pressure> {
    fs::read_to_string(path)
        .ok()
        .map(|text| parse::parse_pressure(&text))
}

#[cfg(target_os = "linux")]
fn read_cgroup(text: &str, path: &str) -> Option<crate::model::CgroupCounters> {
    if let Some(root) = crate::compat::v2_mount() {
        let dir = format!("{root}{path}");
        let cpu_stat = fs::read_to_string(format!("{dir}/cpu.stat")).ok();
        let useful = cpu_stat
            .as_deref()
            .is_some_and(|body| body.contains("usage_usec") || body.contains("throttled_usec"));
        if useful {
            let memory_current = fs::read_to_string(format!("{dir}/memory.current")).ok();
            let memory_max = fs::read_to_string(format!("{dir}/memory.max")).ok();
            if let Some(cgroup) = parse::assemble_cgroup(
                path,
                cpu_stat.as_deref(),
                memory_current.as_deref(),
                memory_max.as_deref(),
            ) {
                return Some(cgroup);
            }
        }
    }
    let cpu_rel = parse::cgroup_controller_path(text, "cpu").unwrap_or_else(|| path.to_string());
    let mem_rel = parse::cgroup_controller_path(text, "memory").unwrap_or_else(|| path.to_string());
    let cpu_stat = ["cpu,cpuacct", "cpu", "cpuacct"].iter().find_map(|mount| {
        fs::read_to_string(format!("/sys/fs/cgroup/{mount}{cpu_rel}/cpu.stat")).ok()
    });
    let memory_current = fs::read_to_string(format!(
        "/sys/fs/cgroup/memory{mem_rel}/memory.usage_in_bytes"
    ))
    .ok();
    let memory_max = fs::read_to_string(format!(
        "/sys/fs/cgroup/memory{mem_rel}/memory.limit_in_bytes"
    ))
    .ok();
    parse::assemble_cgroup(
        path,
        cpu_stat.as_deref(),
        memory_current.as_deref(),
        memory_max.as_deref(),
    )
}

#[cfg(target_os = "linux")]
fn uptime_ms() -> Result<u64> {
    let text = fs::read_to_string("/proc/uptime")?;
    let secs: f64 = text
        .split_whitespace()
        .next()
        .ok_or_else(|| Error::Parse("uptime 为空".into()))?
        .parse()
        .map_err(|_| Error::Parse("uptime 不是数字".into()))?;
    Ok((secs * 1000.0) as u64)
}

fn wall_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
