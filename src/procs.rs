use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::Serialize;

const USER_HZ: f64 = 100.0;

#[derive(Debug, Clone)]
pub struct ProcPoint {
    pub pid: i32,
    pub comm: String,
    pub cmdline: String,
    pub state: String,
    pub ppid: i32,
    pub uid: u32,
    pub utime: u64,
    pub stime: u64,
    pub rss_kb: u64,
    pub vmsize_kb: u64,
    pub vmswap_kb: u64,
    pub threads: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub vol_ctxt: u64,
    pub nonvol_ctxt: u64,
    pub wchan: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcRate {
    pub pid: i32,
    pub comm: String,
    pub cmdline: String,
    pub state: String,
    pub ppid: i32,
    pub uid: u32,
    pub cpu_ratio: f64,
    pub rss_kb: u64,
    pub vmsize_kb: u64,
    pub vmswap_kb: u64,
    pub threads: u64,
    pub read_bps: f64,
    pub write_bps: f64,
    pub vol_ctxt_per_sec: f64,
    pub nonvol_ctxt_per_sec: f64,
    pub wchan: String,
}

#[derive(Debug, Clone)]
pub struct ProcShot {
    pub mono_ms: u64,
    pub procs: Vec<ProcPoint>,
}

#[derive(Debug, Clone)]
pub struct ProcExtra {
    pub user: String,
    pub cgroup: String,
    pub fd_count: Option<usize>,
    pub nofile_soft: Option<u64>,
    pub stack: Option<String>,
}

pub fn capture() -> ProcShot {
    ProcShot {
        mono_ms: uptime_ms(),
        procs: list_procs(),
    }
}

pub fn diff_all(prev: &ProcShot, curr: &ProcShot) -> Vec<ProcRate> {
    build(prev, curr, 0, false)
}

pub fn systemd_unit(cgroup_path: &str) -> Option<String> {
    cgroup_path
        .split(['/', '\n'])
        .filter(|part| part.ends_with(".service"))
        .next_back()
        .map(|part| part.to_string())
}

pub fn diff(prev: &ProcShot, curr: &ProcShot, limit: usize) -> Vec<ProcRate> {
    build(prev, curr, limit, true)
}

pub fn diff_for_query(prev: &ProcShot, curr: &ProcShot, query: &str) -> Vec<ProcRate> {
    let mut rates = build(prev, curr, 0, false);
    rates.retain(|proc| matches(proc, query));
    if rates.len() > 50 {
        rates.truncate(50);
    }
    rates
}

fn build(prev: &ProcShot, curr: &ProcShot, limit: usize, interesting_only: bool) -> Vec<ProcRate> {
    let interval_secs = curr.mono_ms.saturating_sub(prev.mono_ms) as f64 / 1000.0;
    if interval_secs <= 0.0 {
        return Vec::new();
    }
    let prev_map: HashMap<i32, &ProcPoint> = prev.procs.iter().map(|item| (item.pid, item)).collect();
    let mut rates: Vec<ProcRate> = curr
        .procs
        .iter()
        .filter_map(|item| {
            let old = prev_map.get(&item.pid)?;
            if old.comm != item.comm {
                return None;
            }
            let rate = rate_of(old, item, interval_secs);
            let live = !interesting_only
                || !rate.cmdline.is_empty()
                || rate.cpu_ratio > 0.02
                || rate.read_bps + rate.write_bps > 100_000.0
                || rate.state == "D"
                || rate.vmswap_kb > 0;
            live.then_some(rate)
        })
        .collect();
    rates.sort_by(|a, b| {
        score(b)
            .partial_cmp(&score(a))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    if limit > 0 && rates.len() > limit {
        rates.truncate(limit);
    }
    rates
}

pub fn diff_pid(prev: &ProcShot, curr: &ProcShot, pid: i32) -> Option<ProcRate> {
    let interval_secs = curr.mono_ms.saturating_sub(prev.mono_ms) as f64 / 1000.0;
    if interval_secs <= 0.0 {
        return None;
    }
    let old = prev.procs.iter().find(|item| item.pid == pid)?;
    let new = curr.procs.iter().find(|item| item.pid == pid)?;
    if old.comm != new.comm {
        return None;
    }
    Some(rate_of(old, new, interval_secs))
}

pub fn rate_of(prev: &ProcPoint, curr: &ProcPoint, interval_secs: f64) -> ProcRate {
    let ticks = delta(prev.utime, curr.utime) + delta(prev.stime, curr.stime);
    ProcRate {
        pid: curr.pid,
        comm: curr.comm.clone(),
        cmdline: curr.cmdline.clone(),
        state: curr.state.clone(),
        ppid: curr.ppid,
        uid: curr.uid,
        cpu_ratio: ticks as f64 / (interval_secs * USER_HZ),
        rss_kb: curr.rss_kb,
        vmsize_kb: curr.vmsize_kb,
        vmswap_kb: curr.vmswap_kb,
        threads: curr.threads,
        read_bps: per_sec(prev.read_bytes, curr.read_bytes, interval_secs),
        write_bps: per_sec(prev.write_bytes, curr.write_bytes, interval_secs),
        vol_ctxt_per_sec: per_sec(prev.vol_ctxt, curr.vol_ctxt, interval_secs),
        nonvol_ctxt_per_sec: per_sec(prev.nonvol_ctxt, curr.nonvol_ctxt, interval_secs),
        wchan: curr.wchan.clone(),
    }
}

pub fn matches(proc: &ProcRate, query: &str) -> bool {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return true;
    }
    if query.chars().all(|ch| ch.is_ascii_digit()) && proc.pid.to_string() == query {
        return true;
    }
    let hay = format!("{} {}", proc.comm, proc.cmdline).to_lowercase();
    query.split_whitespace().all(|part| hay.contains(part))
}

pub fn extra(pid: i32) -> ProcExtra {
    let user = user_name(uid_of(pid).unwrap_or(u32::MAX));
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()
        .and_then(|text| crate::parse::parse_cgroup_path(&text))
        .unwrap_or_default();
    let fd_count = fs::read_dir(format!("/proc/{pid}/fd")).ok().map(|dir| dir.count());
    let nofile_soft = fs::read_to_string(format!("/proc/{pid}/limits"))
        .ok()
        .as_deref()
        .and_then(parse_nofile_soft);
    let stack = fs::read_to_string(format!("/proc/{pid}/stack")).ok().map(|text| {
        text.lines()
            .take(8)
            .collect::<Vec<_>>()
            .join("\n")
    }).filter(|text| !text.trim().is_empty());
    ProcExtra {
        user,
        cgroup,
        fd_count,
        nofile_soft,
        stack,
    }
}

pub fn user_name(uid: u32) -> String {
    passwd_users().get(&uid).cloned().unwrap_or_else(|| uid.to_string())
}

pub fn parse_stat(text: &str) -> Option<(i32, String, Vec<String>)> {
    let text = text.trim();
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    if close < open {
        return None;
    }
    let pid = text[..open].trim().parse().ok()?;
    let comm = text[open + 1..close].to_string();
    let fields = text[close + 1..]
        .split_whitespace()
        .map(|item| item.to_string())
        .collect::<Vec<_>>();
    if fields.len() < 22 {
        return None;
    }
    Some((pid, comm, fields))
}

pub fn parse_cmdline(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.split('\0')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn parse_status_kv(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        map.insert(key.trim().to_string(), value.trim().to_string());
    }
    map
}

pub fn parse_io_counter(text: &str, key: &str) -> u64 {
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some(key) {
            return parts.next().and_then(|value| value.parse().ok()).unwrap_or(0);
        }
    }
    0
}

pub fn parse_nofile_soft(text: &str) -> Option<u64> {
    for line in text.lines() {
        if !line.starts_with("Max open files") {
            continue;
        }
        return line.split_whitespace().nth(3).and_then(|value| value.parse().ok());
    }
    None
}

pub fn cpu_percent(ratio: f64) -> String {
    format!("{:.0}%", ratio * 100.0)
}

pub fn human_kb(kb: u64) -> String {
    if kb >= 1024 * 1024 {
        format!("{:.1}GiB", kb as f64 / 1024.0 / 1024.0)
    } else if kb >= 1024 {
        format!("{:.0}MiB", kb as f64 / 1024.0)
    } else {
        format!("{kb}KiB")
    }
}

pub fn human_bps(bps: f64) -> String {
    let sign = if bps < 0.0 { "-" } else { "" };
    let n = bps.abs();
    if n >= 1_000_000_000.0 {
        format!("{sign}{:.1}GB/s", n / 1_000_000_000.0)
    } else if n >= 1_000_000.0 {
        format!("{sign}{:.1}MB/s", n / 1_000_000.0)
    } else if n >= 1_000.0 {
        format!("{sign}{:.0}KB/s", n / 1_000.0)
    } else {
        format!("{sign}{:.0}B/s", n)
    }
}

pub fn display_cmd(proc: &ProcRate, width: usize) -> String {
    let raw = if proc.cmdline.is_empty() {
        format!("[{}]", proc.comm)
    } else {
        proc.cmdline.clone()
    };
    if raw.chars().count() <= width {
        raw
    } else {
        let keep = width.saturating_sub(1);
        format!("{}…", raw.chars().take(keep).collect::<String>())
    }
}

pub fn format_table(rows: &[ProcRate]) -> String {
    let mut lines = vec![format!(
        "{:>4}  {:>7}  {:>6}  {:>8}  {:>10}  {:>10}  {:<5}  {}",
        "#", "PID", "CPU", "RSS", "读", "写", "状态", "命令"
    )];
    for (index, proc) in rows.iter().enumerate() {
        lines.push(format!(
            "{:>4}  {:>7}  {:>6}  {:>8}  {:>10}  {:>10}  {:<5}  {}",
            index + 1,
            proc.pid,
            cpu_percent(proc.cpu_ratio),
            human_kb(proc.rss_kb),
            human_bps(proc.read_bps),
            human_bps(proc.write_bps),
            state_label(&proc.state),
            display_cmd(proc, 64),
        ));
    }
    if rows.is_empty() {
        lines.push("这一窗口没有值得列出的进程。".into());
    }
    lines.join("\n")
}

pub fn state_label(state: &str) -> String {
    match state {
        "R" => "运行".into(),
        "S" => "睡眠".into(),
        "D" => "等IO".into(),
        "T" | "t" => "停止".into(),
        "Z" => "僵尸".into(),
        "I" => "空闲".into(),
        other => other.to_string(),
    }
}

fn score(proc: &ProcRate) -> f64 {
    let waiting = if proc.state == "D" { 0.8 } else { 0.0 };
    proc.cpu_ratio + proc.write_bps / 50_000_000.0 + proc.read_bps / 80_000_000.0 + waiting
}

fn list_procs() -> Vec<ProcPoint> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut procs = Vec::new();
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        if let Some(proc) = read_proc(pid) {
            procs.push(proc);
        }
    }
    procs
}

fn read_proc(pid: i32) -> Option<ProcPoint> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (parsed_pid, comm, fields) = parse_stat(&stat)?;
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let kv = parse_status_kv(&status);
    let io = fs::read_to_string(format!("/proc/{pid}/io")).unwrap_or_default();
    let cmdline = fs::read(format!("/proc/{pid}/cmdline"))
        .map(|bytes| parse_cmdline(&bytes))
        .unwrap_or_default();
    let wchan = fs::read_to_string(format!("/proc/{pid}/wchan"))
        .unwrap_or_default()
        .trim()
        .to_string();
    let wchan = if wchan == "0" { String::new() } else { wchan };
    let uid = kv
        .get("Uid")
        .and_then(|text| text.split_whitespace().next())
        .and_then(|text| text.parse().ok())
        .unwrap_or(0);
    Some(ProcPoint {
        pid: parsed_pid,
        comm,
        cmdline,
        state: fields.first().cloned().unwrap_or_default(),
        ppid: fields.get(1).and_then(|text| text.parse().ok()).unwrap_or(0),
        uid,
        utime: fields.get(11).and_then(|text| text.parse().ok()).unwrap_or(0),
        stime: fields.get(12).and_then(|text| text.parse().ok()).unwrap_or(0),
        rss_kb: kb_field(&kv, "VmRSS").unwrap_or(0),
        vmsize_kb: kb_field(&kv, "VmSize").unwrap_or(0),
        vmswap_kb: kb_field(&kv, "VmSwap").unwrap_or(0),
        threads: kv
            .get("Threads")
            .and_then(|text| text.parse().ok())
            .unwrap_or_else(|| fields.get(17).and_then(|text| text.parse().ok()).unwrap_or(1)),
        read_bytes: parse_io_counter(&io, "read_bytes:"),
        write_bytes: parse_io_counter(&io, "write_bytes:"),
        vol_ctxt: kv
            .get("voluntary_ctxt_switches")
            .and_then(|text| text.parse().ok())
            .unwrap_or(0),
        nonvol_ctxt: kv
            .get("nonvoluntary_ctxt_switches")
            .and_then(|text| text.parse().ok())
            .unwrap_or(0),
        wchan,
    })
}

fn kb_field(kv: &HashMap<String, String>, key: &str) -> Option<u64> {
    kv.get(key)
        .and_then(|text| text.split_whitespace().next())
        .and_then(|text| text.parse().ok())
}

fn uid_of(pid: i32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let kv = parse_status_kv(&status);
    kv.get("Uid")?
        .split_whitespace()
        .next()
        .and_then(|text| text.parse().ok())
}

fn passwd_users() -> HashMap<u32, String> {
    let mut users = HashMap::new();
    let Ok(text) = fs::read_to_string("/etc/passwd") else {
        return users;
    };
    for line in text.lines() {
        let mut parts = line.split(':');
        let name = parts.next().unwrap_or("");
        let uid = parts.nth(1).and_then(|text| text.parse().ok());
        if let Some(uid) = uid {
            users.entry(uid).or_insert_with(|| name.to_string());
        }
    }
    users
}

fn uptime_ms() -> u64 {
    let Ok(text) = fs::read_to_string("/proc/uptime") else {
        return 0;
    };
    let secs: f64 = text.split_whitespace().next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
    (secs * 1000.0) as u64
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

pub fn proc_exists(pid: i32) -> bool {
    Path::new(&format!("/proc/{pid}")).is_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_comm_with_spaces() {
        let text = "42 (my proc) D 1 1 1 0 -1 0 0 0 0 0 10 20 0 0 20 0 3 0 0 0 12 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";
        let (pid, comm, fields) = parse_stat(text).unwrap();
        assert_eq!(pid, 42);
        assert_eq!(comm, "my proc");
        assert_eq!(fields[0], "D");
        assert_eq!(fields[1], "1");
        assert_eq!(fields[11], "10");
        assert_eq!(fields[12], "20");
        assert_eq!(fields[17], "3");
    }

    #[test]
    fn fuzzy_name_matches_cmdline_parts() {
        let proc = ProcRate {
            pid: 9,
            comm: "java".into(),
            cmdline: "java -jar /opt/pay/app.jar".into(),
            state: "S".into(),
            ppid: 1,
            uid: 1000,
            cpu_ratio: 0.2,
            rss_kb: 1,
            vmsize_kb: 1,
            vmswap_kb: 0,
            threads: 8,
            read_bps: 0.0,
            write_bps: 0.0,
            vol_ctxt_per_sec: 0.0,
            nonvol_ctxt_per_sec: 0.0,
            wchan: String::new(),
        };
        assert!(matches(&proc, "pay jar"));
        assert!(matches(&proc, "9"));
        assert!(!matches(&proc, "nginx"));
    }

    #[test]
    fn nofile_soft_comes_from_limits() {
        let text = "\
Limit                     Soft Limit           Hard Limit           Units\n\
Max open files            1024                 4096                 files\n";
        assert_eq!(parse_nofile_soft(text), Some(1024));
    }

    #[test]
    fn service_name_comes_from_the_cgroup_path() {
        assert_eq!(
            systemd_unit("/system.slice/nginx.service"),
            Some("nginx.service".into())
        );
        assert_eq!(
            systemd_unit("/user.slice/user-1000.slice/user@1000.service/app.slice/api.service"),
            Some("api.service".into())
        );
        assert_eq!(systemd_unit("/user.slice/session-3.scope"), None);
    }
}
