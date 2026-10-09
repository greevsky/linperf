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
    pub runtime: String,
    pub namespaces: String,
    pub netns_private: bool,
    pub rss_anon_kb: Option<u64>,
    pub rss_file_kb: Option<u64>,
    pub rss_shmem_kb: Option<u64>,
    pub vm_hwm_kb: Option<u64>,
    pub vm_data_kb: Option<u64>,
    pub vm_pte_kb: Option<u64>,
    pub read_bytes: Option<u64>,
    pub write_bytes: Option<u64>,
    pub syscr: Option<u64>,
    pub syscw: Option<u64>,
    pub blkio_secs: Option<f64>,
    pub runqueue_ms: Option<f64>,
    pub fd_files: usize,
    pub fd_sockets: usize,
    pub fd_pipes: usize,
    pub net: ProcNet,
}

#[derive(Debug, Clone)]
pub struct ProcNet {
    pub established: usize,
    pub listen: usize,
    pub close_wait: usize,
    pub time_wait: usize,
    pub syn: usize,
    pub udp: usize,
    pub retrans: u64,
    pub rx_queue: u64,
    pub tx_queue: u64,
    pub listen_backlog: u64,
    pub sockets: Vec<String>,
    pub hidden: usize,
    pub ifaces: Vec<IfaceCount>,
    pub note: String,
}

#[derive(Debug, Clone)]
pub struct IfaceCount {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub drops: u64,
    pub errs: u64,
    pub fifo: u64,
    pub frame: u64,
    pub carrier: u64,
    pub colls: u64,
}

impl ProcNet {
    pub fn empty() -> Self {
        Self {
            established: 0,
            listen: 0,
            close_wait: 0,
            time_wait: 0,
            syn: 0,
            udp: 0,
            retrans: 0,
            rx_queue: 0,
            tx_queue: 0,
            listen_backlog: 0,
            sockets: Vec::new(),
            hidden: 0,
            ifaces: Vec::new(),
            note: String::new(),
        }
    }
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
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let kv = parse_status_kv(&status);
    let (fd_files, fd_sockets, fd_pipes, socket_inodes) = fd_kinds(pid);
    let fd_count = Some(fd_files + fd_sockets + fd_pipes);
    let nofile_soft = fs::read_to_string(format!("/proc/{pid}/limits"))
        .ok()
        .as_deref()
        .and_then(parse_nofile_soft);
    let stack = fs::read_to_string(format!("/proc/{pid}/stack")).ok().map(|text| {
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .take(16)
            .collect::<Vec<_>>()
            .join("\n")
    }).filter(|text| !text.trim().is_empty());
    let isolated = isolated_namespaces(pid);
    let (runtime, namespaces) = describe_runtime(&cgroup, &isolated);
    let netns_private = isolated.iter().any(|item| item == "net");
    let io = fs::read_to_string(format!("/proc/{pid}/io")).unwrap_or_default();
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let blkio_secs = parse_stat(&stat).and_then(|(_, _, fields)| {
        fields
            .get(39)
            .and_then(|text| text.parse::<u64>().ok())
            .map(|ticks| ticks as f64 / USER_HZ)
    });
    let runqueue_ms = fs::read_to_string(format!("/proc/{pid}/schedstat"))
        .ok()
        .and_then(|text| text.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map(|ns| ns as f64 / 1_000_000.0);
    ProcExtra {
        user,
        cgroup,
        fd_count,
        nofile_soft,
        stack,
        runtime,
        namespaces,
        netns_private,
        rss_anon_kb: kb_field(&kv, "RssAnon"),
        rss_file_kb: kb_field(&kv, "RssFile"),
        rss_shmem_kb: kb_field(&kv, "RssShmem"),
        vm_hwm_kb: kb_field(&kv, "VmHWM"),
        vm_data_kb: kb_field(&kv, "VmData"),
        vm_pte_kb: kb_field(&kv, "VmPTE"),
        read_bytes: io_opt(&io, "read_bytes:"),
        write_bytes: io_opt(&io, "write_bytes:"),
        syscr: io_opt(&io, "syscr:"),
        syscw: io_opt(&io, "syscw:"),
        blkio_secs,
        runqueue_ms,
        fd_files,
        fd_sockets,
        fd_pipes,
        net: collect_net(pid, &socket_inodes),
    }
}

pub fn describe_runtime(cgroup: &str, isolated: &[String]) -> (String, String) {
    let namespaces = if isolated.is_empty() {
        "与宿主机相同".into()
    } else {
        format!("{} 与宿主机隔离", isolated.join("、"))
    };
    let runtime = if let Some((kind, id)) = container_identity(cgroup) {
        format!("容器 · {kind} · {id}")
    } else if isolated.iter().any(|item| item == "pid" || item == "mnt") {
        "容器 · 运行时未从 cgroup 识别".into()
    } else if let Some(unit) = systemd_unit(cgroup) {
        format!("宿主机 · systemd · {unit}")
    } else if cgroup.contains("user.slice") || cgroup.contains("session") {
        "宿主机 · 用户会话".into()
    } else if isolated.iter().any(|item| item == "net") {
        "宿主机 · 独立网络命名空间".into()
    } else {
        "宿主机".into()
    };
    (runtime, namespaces)
}

fn container_identity(cgroup: &str) -> Option<(&'static str, String)> {
    let lower = cgroup.to_ascii_lowercase();
    let kind = if lower.contains("kubepods") {
        "kubernetes"
    } else if lower.contains("docker") {
        "docker"
    } else if lower.contains("containerd") {
        "containerd"
    } else if lower.contains("crio") || lower.contains("cri-o") {
        "cri-o"
    } else if lower.contains("libpod") || lower.contains("podman") {
        "podman"
    } else if lower.contains("/lxc/") || lower.contains("lxc-") {
        "lxc"
    } else {
        return None;
    };
    let id = hex_token(cgroup).unwrap_or_else(|| "未写出 id".into());
    Some((kind, id))
}

fn hex_token(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let mut index = 0;
    let mut found = None;
    while index < bytes.len() {
        if bytes[index].is_ascii_hexdigit() {
            let start = index;
            while index < bytes.len() && bytes[index].is_ascii_hexdigit() {
                index += 1;
            }
            if index - start >= 12 {
                found = Some(path[start..start + 12].to_string());
            }
        } else {
            index += 1;
        }
    }
    found
}

#[derive(Debug, Clone)]
pub struct ContainerGroup {
    pub runtime: String,
    pub id: String,
    pub tasks: usize,
    pub rss_kb: u64,
    pub comms: String,
}

pub fn list_containers() -> Vec<ContainerGroup> {
    let mut groups: HashMap<(String, String), (usize, u64, Vec<String>)> = HashMap::new();
    let Ok(dir) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let page_kb = page_kb();
    for entry in dir.flatten() {
        let pid = entry.file_name();
        let pid = pid.to_string_lossy();
        if !pid.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .ok()
            .and_then(|text| crate::parse::parse_cgroup_path(&text))
            .unwrap_or_default();
        let Some((runtime, id)) = container_identity(&cgroup) else {
            continue;
        };
        let pages = fs::read_to_string(format!("/proc/{pid}/statm"))
            .ok()
            .and_then(|text| text.split_whitespace().nth(1)?.parse::<u64>().ok())
            .unwrap_or(0);
        let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let slot = groups.entry((runtime.to_string(), id)).or_default();
        slot.0 += 1;
        slot.1 += pages * page_kb;
        if !comm.is_empty() && !slot.2.contains(&comm) && slot.2.len() < 4 {
            slot.2.push(comm);
        }
    }
    let mut rows: Vec<_> = groups
        .into_iter()
        .map(|((runtime, id), (tasks, rss_kb, comms))| ContainerGroup {
            runtime,
            id,
            tasks,
            rss_kb,
            comms: comms.join("、"),
        })
        .collect();
    rows.sort_by(|left, right| right.rss_kb.cmp(&left.rss_kb).then(left.id.cmp(&right.id)));
    rows
}

pub fn demo_containers() -> Vec<ContainerGroup> {
    vec![ContainerGroup {
        runtime: "docker".into(),
        id: "a247dff2ff6d".into(),
        tasks: 21,
        rss_kb: 133 * 1024,
        comms: "minio".into(),
    }]
}

fn page_kb() -> u64 {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page > 0 {
        page as u64 / 1024
    } else {
        4
    }
}

fn isolated_namespaces(pid: i32) -> Vec<String> {
    ["pid", "mnt", "net", "uts", "ipc", "user"]
        .into_iter()
        .filter(|name| namespace_differs(pid, name))
        .map(|name| name.to_string())
        .collect()
}

fn namespace_differs(pid: i32, name: &str) -> bool {
    let own = fs::read_link(format!("/proc/{pid}/ns/{name}")).ok();
    let mine = fs::read_link(format!("/proc/self/ns/{name}")).ok();
    match (own, mine) {
        (Some(left), Some(right)) => left != right,
        _ => false,
    }
}

fn fd_kinds(pid: i32) -> (usize, usize, usize, Vec<u64>) {
    let Ok(entries) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return (0, 0, 0, Vec::new());
    };
    let mut files = 0;
    let mut sockets = 0;
    let mut pipes = 0;
    let mut inodes = Vec::new();
    for entry in entries.flatten() {
        let Ok(target) = fs::read_link(entry.path()) else {
            files += 1;
            continue;
        };
        let target = target.to_string_lossy();
        if let Some(inode) = target
            .strip_prefix("socket:[")
            .and_then(|rest| rest.strip_suffix(']'))
            .and_then(|text| text.parse().ok())
        {
            sockets += 1;
            inodes.push(inode);
        } else if target.starts_with("pipe:") {
            pipes += 1;
        } else {
            files += 1;
        }
    }
    (files, sockets, pipes, inodes)
}

fn io_opt(text: &str, key: &str) -> Option<u64> {
    if text.is_empty() {
        return None;
    }
    Some(parse_io_counter(text, key))
}

pub fn collect_net(pid: i32, inodes: &[u64]) -> ProcNet {
    if inodes.is_empty() {
        let mut net = ProcNet::empty();
        net.ifaces = read_ifaces(pid);
        return net;
    }
    let mut wanted = std::collections::HashSet::new();
    wanted.extend(inodes.iter().copied());
    let mut socks = Vec::new();
    for name in ["tcp", "tcp6"] {
        if let Ok(text) = fs::read_to_string(format!("/proc/{pid}/net/{name}")) {
            socks.extend(parse_tcp_table(&text).into_iter().filter(|sock| wanted.contains(&sock.inode)));
        }
    }
    let mut udp = 0usize;
    for name in ["udp", "udp6"] {
        if let Ok(text) = fs::read_to_string(format!("/proc/{pid}/net/{name}")) {
            udp += parse_tcp_table(&text)
                .into_iter()
                .filter(|sock| wanted.contains(&sock.inode))
                .count();
        }
    }
    summarize_sockets(socks, udp, read_ifaces(pid))
}

fn read_ifaces(pid: i32) -> Vec<IfaceCount> {
    fs::read_to_string(format!("/proc/{pid}/net/dev"))
        .ok()
        .map(|text| parse_netdev(&text))
        .unwrap_or_default()
}

pub fn parse_tcp_table(text: &str) -> Vec<TcpSock> {
    text.lines().filter_map(parse_tcp_row).collect()
}

pub fn parse_tcp_row(line: &str) -> Option<TcpSock> {
    let mut parts = line.split_whitespace();
    let sl = parts.next()?;
    if sl == "sl" {
        return None;
    }
    let local = hex_endpoint(parts.next()?)?;
    let remote = hex_endpoint(parts.next()?)?;
    let state = tcp_state(parts.next()?);
    let queues = parts.next()?;
    let (tx, rx) = queues.split_once(':')?;
    let tx_queue = u64::from_str_radix(tx, 16).ok()?;
    let rx_queue = u64::from_str_radix(rx, 16).ok()?;
    let _timer = parts.next()?;
    let retrans = u64::from_str_radix(parts.next()?, 16).ok()?;
    let _uid = parts.next()?;
    let _timeout = parts.next()?;
    let inode = parts.next()?.parse().ok()?;
    Some(TcpSock {
        local,
        remote,
        state,
        tx_queue,
        rx_queue,
        retrans,
        inode,
    })
}

#[derive(Debug, Clone)]
pub struct TcpSock {
    pub local: String,
    pub remote: String,
    pub state: String,
    pub tx_queue: u64,
    pub rx_queue: u64,
    pub retrans: u64,
    pub inode: u64,
}

fn summarize_sockets(mut socks: Vec<TcpSock>, udp: usize, ifaces: Vec<IfaceCount>) -> ProcNet {
    socks.sort_by(|left, right| {
        right
            .retrans
            .cmp(&left.retrans)
            .then(right.tx_queue.cmp(&left.tx_queue))
            .then(left.state.cmp(&right.state))
    });
    let mut net = ProcNet::empty();
    net.udp = udp;
    net.ifaces = ifaces;
    for sock in &socks {
        match sock.state.as_str() {
            "已建立" => net.established += 1,
            "监听" => {
                net.listen += 1;
                net.listen_backlog = net.listen_backlog.max(sock.tx_queue);
            }
            "等关闭" => net.close_wait += 1,
            "时间等待" => net.time_wait += 1,
            "发出握手" | "收到握手" => net.syn += 1,
            _ => {}
        }
        net.retrans += sock.retrans;
        net.rx_queue += sock.rx_queue;
        net.tx_queue += sock.tx_queue;
    }
    let limit = 24;
    net.hidden = socks.len().saturating_sub(limit);
    net.sockets = socks
        .iter()
        .take(limit)
        .map(|sock| {
            if sock.state == "监听" {
                format!(
                    "{:<22}  {:<8}  未取走 {}",
                    sock.local,
                    sock.state,
                    human_bytes(sock.tx_queue)
                )
            } else {
                format!(
                    "{:<22} ← {:<22}  {:<8}  重传 {}  收 {}  发 {}",
                    sock.local,
                    sock.remote,
                    sock.state,
                    sock.retrans,
                    human_bytes(sock.rx_queue),
                    human_bytes(sock.tx_queue)
                )
            }
        })
        .collect();
    net.note = net_note(&net);
    net
}

fn net_note(net: &ProcNet) -> String {
    let mut parts = Vec::new();
    if net.close_wait >= 5 {
        parts.push(format!(
            "有 {} 条等关闭（CLOSE_WAIT）。对端已经关闭，本进程还没 close，先查连接是否泄漏。",
            net.close_wait
        ));
    }
    if net.retrans > 0 {
        parts.push(format!(
            "套接字重传累计 {}。链路丢包或对端处理不过来时，业务会先变慢。",
            net.retrans
        ));
    }
    if net.listen_backlog >= 32 {
        parts.push(format!(
            "监听队列里有 {} 字节未取走。accept 跟不上新连接。",
            human_bytes(net.listen_backlog)
        ));
    }
    if net.time_wait >= 200 {
        parts.push(format!(
            "时间等待 {} 条。短连接过多时会占满本地端口。",
            net.time_wait
        ));
    }
    parts.join(" ")
}

pub fn hex_endpoint(text: &str) -> Option<String> {
    let (addr, port) = text.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    if addr.len() == 8 {
        let raw = u32::from_str_radix(addr, 16).ok()?;
        let bytes = raw.to_be_bytes();
        return Some(format!(
            "{}.{}.{}.{}:{port}",
            bytes[3], bytes[2], bytes[1], bytes[0]
        ));
    }
    if addr.len() == 32 {
        let mut groups = Vec::new();
        for index in 0..4 {
            let word = u32::from_str_radix(&addr[index * 8..index * 8 + 8], 16).ok()?;
            let bytes = word.to_be_bytes();
            groups.push(format!("{:02x}{:02x}", bytes[3], bytes[2]));
            groups.push(format!("{:02x}{:02x}", bytes[1], bytes[0]));
        }
        return Some(format!("[{}]:{port}", groups.join(":")));
    }
    None
}

fn tcp_state(code: &str) -> String {
    match code.to_ascii_uppercase().as_str() {
        "01" => "已建立",
        "02" => "发出握手",
        "03" => "收到握手",
        "04" | "05" => "结束等待",
        "06" => "时间等待",
        "07" => "关闭",
        "08" => "等关闭",
        "09" => "最后确认",
        "0A" => "监听",
        "0B" => "关闭中",
        _ => "未知",
    }
    .into()
}

pub fn parse_netdev(text: &str) -> Vec<IfaceCount> {
    let mut rows = Vec::new();
    for line in text.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        let num = |parts: &mut std::str::SplitWhitespace| {
            parts.next().and_then(|value| value.parse().ok()).unwrap_or(0)
        };
        let rx_bytes = num(&mut parts);
        let _rx_packets = parts.next();
        let rx_err = num(&mut parts);
        let rx_drop = num(&mut parts);
        let rx_fifo = num(&mut parts);
        let rx_frame = num(&mut parts);
        let _rx_compressed = parts.next();
        let _rx_multicast = parts.next();
        let tx_bytes = num(&mut parts);
        let _tx_packets = parts.next();
        let tx_err = num(&mut parts);
        let tx_drop = num(&mut parts);
        let tx_fifo = num(&mut parts);
        let tx_colls = num(&mut parts);
        let tx_carrier = num(&mut parts);
        rows.push(IfaceCount {
            name: name.trim().to_string(),
            rx_bytes,
            tx_bytes,
            drops: rx_drop + tx_drop,
            errs: rx_err + tx_err,
            fifo: rx_fifo + tx_fifo,
            frame: rx_frame,
            carrier: tx_carrier,
            colls: tx_colls,
        });
    }
    rows
}

pub fn human_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1}GiB", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
    } else if bytes >= 1024 * 1024 {
        format!("{:.1}MiB", bytes as f64 / 1024.0 / 1024.0)
    } else if bytes >= 1024 {
        format!("{:.0}KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes}B")
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

    #[test]
    fn docker_scope_is_a_container() {
        let path = "/system.slice/docker-a247dff2ff6d1a9e19b1cddeb11725d937bf0b2533b9f3f7bf011b21f242097d.scope";
        let (runtime, namespaces) = describe_runtime(path, &["pid".into(), "mnt".into(), "net".into()]);
        assert_eq!(runtime, "容器 · docker · a247dff2ff6d");
        assert!(namespaces.contains("net"));
        let (host, same) = describe_runtime("/system.slice/nginx.service", &[]);
        assert_eq!(host, "宿主机 · systemd · nginx.service");
        assert_eq!(same, "与宿主机相同");
    }

    #[test]
    fn tcp_row_keeps_address_retrans_and_inode() {
        let line = "   0: 0100007F:0050 00000000:1F90 01 00000010:00000020 00:00000000 00000002     0        0 4242 1 0 0 0";
        let sock = parse_tcp_row(line).unwrap();
        assert_eq!(sock.local, "127.0.0.1:80");
        assert_eq!(sock.remote, "0.0.0.0:8080");
        assert_eq!(sock.state, "已建立");
        assert_eq!(sock.tx_queue, 0x10);
        assert_eq!(sock.rx_queue, 0x20);
        assert_eq!(sock.retrans, 2);
        assert_eq!(sock.inode, 4242);
    }
}
