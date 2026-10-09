use crate::error::{Error, Result};
use crate::model::{
    CgroupCounters, CpuCounters, DiskCounters, LoadAvg, MemInfo, NetCounters, Pressure, VmCounters,
};

pub fn parse_proc_stat(text: &str) -> Result<CpuCounters> {
    let mut agg = None;
    let mut ncpu = 0u32;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let name = parts.next().unwrap_or("");
        if name == "cpu" {
            agg = Some(read_cpu_fields(&mut parts));
        } else if name.len() > 3
            && name.starts_with("cpu")
            && name[3..].chars().all(|c| c.is_ascii_digit())
        {
            ncpu += 1;
        }
    }
    let mut cpu = agg.ok_or_else(|| Error::Parse("缺少 cpu 汇总行".into()))?;
    cpu.ncpu = ncpu.max(1);
    Ok(cpu)
}

fn read_cpu_fields<'a>(parts: &mut impl Iterator<Item = &'a str>) -> CpuCounters {
    let mut nums = [0u64; 8];
    for slot in &mut nums {
        *slot = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    }
    CpuCounters {
        user: nums[0],
        nice: nums[1],
        system: nums[2],
        idle: nums[3],
        iowait: nums[4],
        irq: nums[5],
        softirq: nums[6],
        steal: nums[7],
        ncpu: 1,
    }
}

pub fn parse_meminfo(text: &str) -> Result<MemInfo> {
    let mut total = None;
    let mut available = None;
    let mut free = None;
    let mut buffers = None;
    let mut cached = None;
    let mut swap_total = None;
    let mut swap_free = None;
    let mut dirty = None;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let key = parts.next().unwrap_or("").trim_end_matches(':');
        let value = parts.next().and_then(|v| v.parse().ok());
        match key {
            "MemTotal" => total = value,
            "MemAvailable" => available = value,
            "MemFree" => free = value,
            "Buffers" => buffers = value,
            "Cached" => cached = value,
            "SwapTotal" => swap_total = value,
            "SwapFree" => swap_free = value,
            "Dirty" => dirty = value,
            _ => {}
        }
    }
    let (available_kb, available_estimated) = if let Some(value) = available {
        (value, false)
    } else {
        (
            free.unwrap_or(0) + buffers.unwrap_or(0) + cached.unwrap_or(0),
            true,
        )
    };
    Ok(MemInfo {
        total_kb: total.ok_or_else(|| Error::Parse("缺少 MemTotal".into()))?,
        available_kb,
        available_estimated,
        swap_total_kb: swap_total.unwrap_or(0),
        swap_free_kb: swap_free.unwrap_or(0),
        dirty_kb: dirty.unwrap_or(0),
    })
}

pub fn parse_vmstat(text: &str) -> VmCounters {
    let mut vm = VmCounters {
        pswpin: 0,
        pswpout: 0,
    };
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let key = parts.next().unwrap_or("");
        let value = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        match key {
            "pswpin" => vm.pswpin = value,
            "pswpout" => vm.pswpout = value,
            _ => {}
        }
    }
    vm
}

pub fn parse_loadavg(text: &str) -> Result<LoadAvg> {
    let mut parts = text.split_whitespace();
    let load1 = parts
        .next()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| Error::Parse("loadavg 缺少 load1".into()))?;
    let load5 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(load1);
    let load15 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(load5);
    Ok(LoadAvg {
        load1,
        load5,
        load15,
    })
}

pub fn parse_pressure(text: &str) -> Pressure {
    let mut pressure = Pressure::default();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let kind = parts.next().unwrap_or("");
        let mut avg10 = 0.0;
        let mut avg60 = 0.0;
        for item in parts {
            if let Some(value) = item.strip_prefix("avg10=") {
                avg10 = value.parse().unwrap_or(0.0);
            } else if let Some(value) = item.strip_prefix("avg60=") {
                avg60 = value.parse().unwrap_or(0.0);
            }
        }
        match kind {
            "some" => {
                pressure.some_avg10 = avg10;
                pressure.some_avg60 = avg60;
            }
            "full" => {
                pressure.full_avg10 = avg10;
                pressure.full_avg60 = avg60;
            }
            _ => {}
        }
    }
    pressure
}

pub fn parse_diskstats(text: &str) -> Vec<DiskCounters> {
    let mut disks = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 14 {
            continue;
        }
        let name = parts[2];
        if !interesting_disk(name) {
            continue;
        }
        disks.push(DiskCounters {
            name: name.to_string(),
            reads: parts[3].parse().unwrap_or(0),
            read_ms: parts[6].parse().unwrap_or(0),
            writes: parts[7].parse().unwrap_or(0),
            write_ms: parts[10].parse().unwrap_or(0),
            in_flight: parts[11].parse().unwrap_or(0),
            io_ms: parts[12].parse().unwrap_or(0),
        });
    }
    disks
}

fn interesting_disk(name: &str) -> bool {
    const SKIP: &[&str] = &["loop", "ram", "fd", "sr", "zram"];
    !SKIP.iter().any(|prefix| name.starts_with(prefix))
}

pub fn parse_netdev(text: &str) -> Vec<NetCounters> {
    let mut nets = Vec::new();
    for line in text.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() || name == "lo" {
            continue;
        }
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() < 16 {
            continue;
        }
        nets.push(NetCounters {
            name: name.to_string(),
            rx_bytes: parts[0].parse().unwrap_or(0),
            rx_errs: parts[2].parse().unwrap_or(0),
            rx_drop: parts[3].parse().unwrap_or(0),
            rx_fifo: parts[4].parse().unwrap_or(0),
            rx_frame: parts[5].parse().unwrap_or(0),
            tx_bytes: parts[8].parse().unwrap_or(0),
            tx_errs: parts[10].parse().unwrap_or(0),
            tx_drop: parts[11].parse().unwrap_or(0),
            tx_fifo: parts[12].parse().unwrap_or(0),
            tx_colls: parts[13].parse().unwrap_or(0),
            tx_carrier: parts[14].parse().unwrap_or(0),
        });
    }
    nets
}

pub fn parse_softnet(text: &str) -> crate::model::SoftnetCounters {
    let mut total = crate::model::SoftnetCounters::default();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let hex = |index: usize| {
            parts
                .get(index)
                .and_then(|value| u64::from_str_radix(value, 16).ok())
                .unwrap_or(0)
        };
        total.dropped += hex(1);
        total.squeezed += hex(2);
        if parts.len() > 6 {
            total.flow_limit += hex(6);
        }
    }
    total
}

pub fn parse_cpu_stat(text: &str) -> (u64, u64) {
    let mut throttled_usec = 0u64;
    let mut throttled_ns: Option<u64> = None;
    let mut saw_usec = false;
    let mut nr_throttled = 0u64;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        match parts.next().unwrap_or("") {
            "throttled_usec" => {
                saw_usec = true;
                throttled_usec = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
            }
            "throttled_time" => {
                throttled_ns = parts.next().and_then(|v| v.parse().ok());
            }
            "nr_throttled" => nr_throttled = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            _ => {}
        }
    }
    if !saw_usec {
        if let Some(ns) = throttled_ns {
            throttled_usec = ns / 1000;
        }
    }
    (throttled_usec, nr_throttled)
}

pub fn parse_memory_max(text: &str) -> Option<u64> {
    let token = text.split_whitespace().next().unwrap_or("");
    if token.is_empty() || token == "max" {
        return None;
    }
    let value: u64 = token.parse().ok()?;
    // v1 不限额时 memory.limit_in_bytes 是一个接近 2^63 的数。
    if value >= 1 << 62 {
        None
    } else {
        Some(value)
    }
}

struct CgroupEntry {
    v2: bool,
    path: String,
}

fn cgroup_entries(text: &str) -> Vec<CgroupEntry> {
    let mut entries = Vec::new();
    for line in text.lines() {
        if let Some(path) = line.strip_prefix("0::") {
            entries.push(CgroupEntry {
                v2: true,
                path: if path.is_empty() {
                    "/".into()
                } else {
                    path.to_string()
                },
            });
            continue;
        }
        let mut parts = line.splitn(3, ':');
        let Some(id) = parts.next() else { continue };
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Some(_ctrls) = parts.next() else { continue };
        let Some(path) = parts.next() else { continue };
        entries.push(CgroupEntry {
            v2: false,
            path: if path.is_empty() {
                "/".into()
            } else {
                path.to_string()
            },
        });
    }
    entries
}

pub fn parse_cgroup_path(text: &str) -> Option<String> {
    let entries = cgroup_entries(text);
    if entries.is_empty() {
        return None;
    }
    if let Some(entry) = entries.iter().find(|entry| container_path(&entry.path)) {
        return Some(entry.path.clone());
    }
    if let Some(entry) = entries.iter().find(|entry| entry.v2) {
        return Some(entry.path.clone());
    }
    entries.into_iter().map(|entry| entry.path).max_by_key(|path| path.len())
}

pub fn cgroup_controller_path(text: &str, controller: &str) -> Option<String> {
    for line in text.lines() {
        let mut parts = line.splitn(3, ':');
        let id = parts.next()?;
        if id == "0" || !id.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let ctrls = parts.next()?;
        let path = parts.next()?;
        if ctrls.split(',').any(|item| item == controller) {
            return Some(if path.is_empty() {
                "/".into()
            } else {
                path.to_string()
            });
        }
    }
    None
}

fn container_path(path: &str) -> bool {
    ["docker", "kubepods", "containerd", "libpod", "/lxc/", "crio-", "podman"]
        .iter()
        .any(|marker| path.contains(marker))
}

pub fn assemble_cgroup(
    path: &str,
    cpu_stat: Option<&str>,
    memory_current: Option<&str>,
    memory_max: Option<&str>,
) -> Option<CgroupCounters> {
    if cpu_stat.is_none() && memory_current.is_none() {
        return None;
    }
    let (throttled_usec, nr_throttled) = cpu_stat.map(parse_cpu_stat).unwrap_or((0, 0));
    let memory_current = memory_current
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0);
    Some(CgroupCounters {
        path: path.to_string(),
        throttled_usec,
        nr_throttled,
        memory_current,
        memory_max: memory_max.and_then(parse_memory_max),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cpu_and_counts_processors() {
        let text = "\
cpu  100 10 50 800 20 5 5 10 0 0
cpu0 40 5 20 400 10 2 2 5 0 0
cpu1 60 5 30 400 10 3 3 5 0 0
intr 1
";
        let cpu = parse_proc_stat(text).unwrap();
        assert_eq!(cpu.user, 100);
        assert_eq!(cpu.iowait, 20);
        assert_eq!(cpu.ncpu, 2);
    }

    #[test]
    fn parses_disk_net_and_pressure() {
        let disks = parse_diskstats(
            "   8 0 sda 10 0 100 20 5 0 50 30 0 40 80 0 0 0 0\n   7 0 loop0 1 0 1 1 0 0 0 0 0 1 1 0\n",
        );
        assert_eq!(disks.len(), 1);
        assert_eq!(disks[0].name, "sda");
        assert_eq!(disks[0].io_ms, 40);

        let nets = parse_netdev(
            "Inter-|   Receive\n face |bytes\n  lo: 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0\n  eth0: 100 1 2 3 7 8 0 0 200 1 4 5 9 6 11 0\n",
        );
        assert_eq!(nets.len(), 1);
        assert_eq!(nets[0].rx_errs, 2);
        assert_eq!(nets[0].rx_fifo, 7);
        assert_eq!(nets[0].rx_frame, 8);
        assert_eq!(nets[0].tx_drop, 5);
        assert_eq!(nets[0].tx_fifo, 9);
        assert_eq!(nets[0].tx_colls, 6);
        assert_eq!(nets[0].tx_carrier, 11);
        let softnet = parse_softnet("0000000a 00000002 00000003 00000000 00000000 00000000 00000004\n");
        assert_eq!(softnet.dropped, 2);
        assert_eq!(softnet.squeezed, 3);
        assert_eq!(softnet.flow_limit, 4);

        let pressure = parse_pressure("some avg10=1.50 avg60=0.20 avg300=0.00 total=9\nfull avg10=0.40 avg60=0.10 avg300=0.00 total=3\n");
        assert!((pressure.some_avg10 - 1.5).abs() < 0.001);
        assert!((pressure.full_avg10 - 0.4).abs() < 0.001);
    }

    #[test]
    fn old_meminfo_estimates_available() {
        let estimated = parse_meminfo(
            "MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 50 kB\nCached: 200 kB\n",
        )
        .unwrap();
        assert!(estimated.available_estimated);
        assert_eq!(estimated.available_kb, 350);

        let exact = parse_meminfo("MemTotal: 1000 kB\nMemAvailable: 0 kB\nMemFree: 100 kB\n").unwrap();
        assert!(!exact.available_estimated);
        assert_eq!(exact.available_kb, 0);
    }

    #[test]
    fn parses_cgroup_limits() {
        assert_eq!(
            parse_cgroup_path("0::/user.slice/app\n"),
            Some("/user.slice/app".into())
        );
        assert_eq!(
            parse_cgroup_path("5:memory:/docker/abc\n4:cpu,cpuacct:/docker/abc\n"),
            Some("/docker/abc".into())
        );
        assert_eq!(
            parse_cgroup_path("0::/\n4:cpu,cpuacct:/docker/abc\n"),
            Some("/docker/abc".into())
        );
        assert_eq!(
            cgroup_controller_path("4:cpu,cpuacct:/user.slice\n5:memory:/user.slice\n", "cpu"),
            Some("/user.slice".into())
        );
        assert_eq!(parse_memory_max("max\n"), None);
        assert_eq!(parse_memory_max("1048576\n"), Some(1_048_576));
        assert_eq!(parse_memory_max("9223372036854771712\n"), None);
        let v1 = parse_cpu_stat("nr_periods 1\nnr_throttled 2\nthrottled_time 5000000\n");
        assert_eq!(v1, (5000, 2));
        let cg = assemble_cgroup(
            "/app",
            Some("usage_usec 10\nnr_throttled 2\nthrottled_usec 5000\n"),
            Some("900\n"),
            Some("1000\n"),
        )
        .unwrap();
        assert_eq!(cg.throttled_usec, 5000);
        assert_eq!(cg.memory_max, Some(1000));
    }
}
