use std::fs;
use std::net::Ipv4Addr;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct Addr {
    pub iface: String,
    pub family: String,
    pub addr: String,
}

#[derive(Debug, Clone)]
pub struct Route4 {
    pub iface: String,
    pub destination: String,
    pub gateway: String,
    pub metric: u32,
}

#[derive(Debug, Clone)]
pub struct Route6 {
    pub iface: String,
    pub destination: String,
    pub gateway: String,
}

#[derive(Debug, Clone)]
pub struct NicInfo {
    pub name: String,
    pub mac: String,
    pub state: String,
    pub mtu: String,
    pub speed: String,
    pub physical: bool,
}

#[derive(Debug, Clone)]
pub struct Sysctl {
    pub label: String,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct NetConfig {
    pub addrs: Vec<Addr>,
    pub routes: Vec<Route4>,
    pub routes6: Vec<Route6>,
    pub nics: Vec<NicInfo>,
    pub sysctls: Vec<Sysctl>,
}

#[derive(Debug, Clone)]
pub struct FirewallView {
    pub lines: Vec<(String, String)>,
    pub rules_note: String,
    pub rules: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct HwDisk {
    pub name: String,
    #[allow(dead_code)]
    pub size: String,
    pub bytes: u64,
    #[allow(dead_code)]
    pub model: String,
    #[allow(dead_code)]
    pub serial: String,
    #[allow(dead_code)]
    pub kind: String,
}

#[derive(Debug, Clone)]
pub struct HardwareInfo {
    pub vendor: String,
    pub product: String,
    #[allow(dead_code)]
    pub version: String,
    pub serial: String,
    #[allow(dead_code)]
    pub uuid: String,
    #[allow(dead_code)]
    pub bios: String,
    #[allow(dead_code)]
    pub board: String,
    pub cpu: String,
    #[allow(dead_code)]
    pub memory: String,
    pub disks: Vec<HwDisk>,
}

impl NetConfig {
    pub fn empty() -> Self {
        Self {
            addrs: Vec::new(),
            routes: Vec::new(),
            routes6: Vec::new(),
            nics: Vec::new(),
            sysctls: Vec::new(),
        }
    }
}

impl FirewallView {
    pub fn empty() -> Self {
        Self {
            lines: Vec::new(),
            rules_note: String::new(),
            rules: Vec::new(),
        }
    }
}

impl HardwareInfo {
    #[allow(dead_code)]
    pub fn empty() -> Self {
        Self {
            vendor: String::new(),
            product: String::new(),
            version: String::new(),
            serial: String::new(),
            uuid: String::new(),
            bios: String::new(),
            board: String::new(),
            cpu: String::new(),
            memory: String::new(),
            disks: Vec::new(),
        }
    }
}

pub fn load_net() -> NetConfig {
    NetConfig {
        addrs: read_addrs(),
        routes: parse_route4(&read_text("/proc/net/route")),
        routes6: parse_route6(&read_text("/proc/net/ipv6_route")),
        nics: read_nics(),
        sysctls: read_sysctls(),
    }
}

pub fn load_firewall() -> FirewallView {
    let tables = parse_table_names(&read_text("/proc/net/ip_tables_names"));
    let forward = read_sysctl("net.ipv4.ip_forward");
    let rp = read_sysctl("net.ipv4.conf.all.rp_filter");
    let count = read_sysctl("net.netfilter.nf_conntrack_count");
    let max = read_sysctl("net.netfilter.nf_conntrack_max");
    let backend = detect_backend(&tables);
    let table_text = if tables.is_empty() {
        "内核没有列出 ip 表".to_string()
    } else {
        tables.join("、")
    };
    let conntrack = match (count, max) {
        (Some(count), Some(max)) => format!("{count} / {max}"),
        (Some(count), None) => count,
        _ => "读不到".into(),
    };
    let (rules_note, rules) = load_rules();
    FirewallView {
        lines: vec![
            ("防火墙".into(), backend),
            ("过滤表".into(), table_text),
            ("转发 (net.ipv4.ip_forward)".into(), explain_forward(forward.as_deref())),
            (
                "反向路径 (net.ipv4.conf.all.rp_filter)".into(),
                explain_rp(rp.as_deref()),
            ),
            (
                "连接跟踪 (nf_conntrack_count / nf_conntrack_max)".into(),
                conntrack,
            ),
            ("规则来源".into(), rules_note.clone()),
        ],
        rules_note,
        rules,
    }
}

pub fn demo_net() -> NetConfig {
    NetConfig {
        addrs: vec![
            Addr {
                iface: "eth0".into(),
                family: "IPv4".into(),
                addr: "10.0.0.8/24".into(),
            },
            Addr {
                iface: "eth0".into(),
                family: "IPv6".into(),
                addr: "fe80::1/64".into(),
            },
            Addr {
                iface: "docker0".into(),
                family: "IPv4".into(),
                addr: "172.17.0.1/16".into(),
            },
        ],
        routes: vec![Route4 {
            iface: "eth0".into(),
            destination: "0.0.0.0/0".into(),
            gateway: "10.0.0.1".into(),
            metric: 100,
        }],
        routes6: vec![Route6 {
            iface: "eth0".into(),
            destination: "::/0".into(),
            gateway: "fe80::1".into(),
        }],
        nics: vec![
            NicInfo {
                name: "eth0".into(),
                mac: "02:42:0a:00:00:08".into(),
                state: "up".into(),
                mtu: "1500".into(),
                speed: "10000 Mb/s".into(),
                physical: true,
            },
            NicInfo {
                name: "docker0".into(),
                mac: "02:42:ac:11:00:01".into(),
                state: "up".into(),
                mtu: "1500".into(),
                speed: "未知".into(),
                physical: false,
            },
        ],
        sysctls: vec![
            Sysctl {
                label: "拥塞控制".into(),
                key: "net.ipv4.tcp_congestion_control".into(),
                value: "cubic".into(),
            },
            Sysctl {
                label: "监听队列上限".into(),
                key: "net.core.somaxconn".into(),
                value: "4096".into(),
            },
        ],
    }
}

pub fn demo_firewall() -> FirewallView {
    FirewallView {
        lines: vec![
            ("防火墙".into(), "nftables".into()),
            ("过滤表".into(), "filter、nat".into()),
            ("转发 (net.ipv4.ip_forward)".into(), "开启".into()),
            ("反向路径 (net.ipv4.conf.all.rp_filter)".into(), "松散".into()),
            ("连接跟踪 (nf_conntrack_count / nf_conntrack_max)".into(), "32 / 262144".into()),
            ("规则来源".into(), "nft list ruleset".into()),
        ],
        rules_note: "nft list ruleset".into(),
        rules: vec![
            "table ip filter {".into(),
            "    chain INPUT {".into(),
            "        type filter hook input priority filter; policy drop;".into(),
            "        tcp dport 22 accept".into(),
            "    }".into(),
            "}".into(),
        ],
    }
}

pub fn demo_hardware() -> HardwareInfo {
    HardwareInfo {
        vendor: "示例厂商".into(),
        product: "示例机型".into(),
        version: "1.0".into(),
        serial: "SN-DEMO-001".into(),
        uuid: "00000000-0000-0000-0000-000000000000".into(),
        bios: "演示 BIOS  2024-01-01".into(),
        board: "演示主板".into(),
        cpu: "演示处理器  4 线程  每槽 4 核".into(),
        memory: "8.0 GiB".into(),
        disks: vec![
            HwDisk {
                name: "vda".into(),
                size: "100.0GiB".into(),
                bytes: 100 * 1024 * 1024 * 1024u64,
                model: "DEMO DISK".into(),
                serial: "DISKSN".into(),
                kind: "虚拟".into(),
            },
            HwDisk {
                name: "vdb".into(),
                size: "500.0GiB".into(),
                bytes: 500 * 1024 * 1024 * 1024u64,
                model: "DEMO DISK".into(),
                serial: "DISKSN2".into(),
                kind: "虚拟".into(),
            },
        ],
    }
}

pub fn load_hardware() -> HardwareInfo {
    let cpuinfo = read_text("/proc/cpuinfo");
    let meminfo = read_text("/proc/meminfo");
    HardwareInfo {
        vendor: dmi("sys_vendor"),
        product: dmi("product_name"),
        version: dmi("product_version"),
        serial: first_nonempty(&[dmi("product_serial"), dmi("chassis_serial")]),
        uuid: dmi("product_uuid"),
        bios: join_nonempty(&[dmi("bios_vendor"), dmi("bios_version"), dmi("bios_date")]),
        board: join_nonempty(&[dmi("board_vendor"), dmi("board_name"), dmi("board_serial")]),
        cpu: cpu_summary(&cpuinfo),
        memory: mem_total(&meminfo),
        disks: read_disks(),
    }
}

pub fn human_sectors(sectors: u64) -> String {
    let bytes = sectors.saturating_mul(512);
    if bytes >= 1024 * 1024 * 1024 * 1024 {
        format!("{:.1} TiB", bytes as f64 / 1024.0 / 1024.0 / 1024.0 / 1024.0)
    } else if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1} GiB", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
    } else if bytes >= 1024 * 1024 {
        format!("{:.0} MiB", bytes as f64 / 1024.0 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

pub fn parse_route4(text: &str) -> Vec<Route4> {
    let mut rows = Vec::new();
    for line in text.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 8 {
            continue;
        }
        let destination = match (hex_ipv4(parts[1]), prefix_len(parts[7])) {
            (Some(ip), Some(prefix)) => format!("{ip}/{prefix}"),
            _ => continue,
        };
        let gateway = match hex_ipv4(parts[2]) {
            Some(ip) if ip != "0.0.0.0" => ip,
            Some(_) => "直连".into(),
            None => continue,
        };
        rows.push(Route4 {
            iface: parts[0].to_string(),
            destination,
            gateway,
            metric: parts[6].parse().unwrap_or(0),
        });
    }
    rows
}

pub fn parse_route6(text: &str) -> Vec<Route6> {
    let mut rows = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        let Some(dest) = hex_ipv6(parts[0]) else {
            continue;
        };
        let prefix = u32::from_str_radix(parts[1], 16).unwrap_or(0);
        let gateway = hex_ipv6(parts[4]).unwrap_or_else(|| "直连".into());
        let via = if gateway == "::" { "直连".to_string() } else { gateway };
        rows.push(Route6 {
            iface: parts[9].to_string(),
            destination: format!("{dest}/{prefix}"),
            gateway: via,
        });
    }
    rows
}

pub fn parse_table_names(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| line.to_string())
        .collect()
}

pub fn hex_ipv4(text: &str) -> Option<String> {
    let value = u32::from_str_radix(text, 16).ok()?;
    let bytes = value.to_ne_bytes();
    Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string())
}

fn prefix_len(text: &str) -> Option<u32> {
    let value = u32::from_str_radix(text, 16).ok()?;
    Some(value.to_ne_bytes().iter().map(|byte| byte.count_ones()).sum())
}

pub fn hex_ipv6(text: &str) -> Option<String> {
    if text.len() != 32 || !text.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0u8; 16];
    for index in 0..16 {
        bytes[index] = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(compress_ipv6(&bytes))
}

fn compress_ipv6(bytes: &[u8; 16]) -> String {
    let groups: Vec<u16> = (0..8)
        .map(|index| u16::from_be_bytes([bytes[index * 2], bytes[index * 2 + 1]]))
        .collect();
    let mut best = (0usize, 0usize);
    let mut index = 0;
    while index < groups.len() {
        if groups[index] != 0 {
            index += 1;
            continue;
        }
        let start = index;
        while index < groups.len() && groups[index] == 0 {
            index += 1;
        }
        if index - start > best.1 - best.0 {
            best = (start, index);
        }
    }
    if best.1 - best.0 < 2 {
        return groups
            .iter()
            .map(|group| format!("{group:x}"))
            .collect::<Vec<_>>()
            .join(":");
    }
    let head = groups[..best.0]
        .iter()
        .map(|group| format!("{group:x}"))
        .collect::<Vec<_>>()
        .join(":");
    let tail = groups[best.1..]
        .iter()
        .map(|group| format!("{group:x}"))
        .collect::<Vec<_>>()
        .join(":");
    if head.is_empty() && tail.is_empty() {
        "::".into()
    } else if head.is_empty() {
        format!("::{tail}")
    } else if tail.is_empty() {
        format!("{head}::")
    } else {
        format!("{head}::{tail}")
    }
}

fn explain_forward(value: Option<&str>) -> String {
    match value.map(str::trim) {
        Some("1") => "开启".into(),
        Some("0") => "关闭".into(),
        Some(other) => other.into(),
        None => "读不到".into(),
    }
}

fn explain_rp(value: Option<&str>) -> String {
    match value.map(str::trim) {
        Some("0") => "关闭".into(),
        Some("1") => "严格".into(),
        Some("2") => "松散".into(),
        Some(other) => other.into(),
        None => "读不到".into(),
    }
}

fn detect_backend(tables: &[String]) -> String {
    if read_text("/etc/ufw/ufw.conf")
        .lines()
        .any(|line| line.trim() == "ENABLED=yes")
    {
        return "ufw".into();
    }
    if comm_running("firewalld") {
        return "firewalld".into();
    }
    if read_text("/etc/nftables.conf").contains("table") {
        return "nftables".into();
    }
    if !tables.is_empty() {
        return "iptables".into();
    }
    "没有发现".into()
}

fn comm_running(name: &str) -> bool {
    let Ok(dir) = fs::read_dir("/proc") else {
        return false;
    };
    for entry in dir.flatten() {
        let pid = entry.file_name();
        let pid = pid.to_string_lossy();
        if !pid.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        if read_text(&format!("/proc/{pid}/comm")).trim() == name {
            return true;
        }
    }
    false
}

fn read_nics() -> Vec<NicInfo> {
    let Ok(dir) = fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    let mut rows: Vec<_> = dir
        .flatten()
        .map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            let base = format!("/sys/class/net/{name}");
            let speed = read_text(&format!("{base}/speed"));
            let speed = match speed.trim() {
                "" | "-1" => "未知".into(),
                text => format!("{text} Mb/s"),
            };
            NicInfo {
                mac: fallback(&read_text(&format!("{base}/address")), "没有"),
                state: fallback(&read_text(&format!("{base}/operstate")), "未知"),
                mtu: fallback(&read_text(&format!("{base}/mtu")), "未知"),
                speed,
                physical: std::path::Path::new(&format!("{base}/device")).exists(),
                name,
            }
        })
        .collect();
    rows.sort_by(|left, right| left.name.cmp(&right.name));
    rows
}

fn read_addrs() -> Vec<Addr> {
    #[cfg(target_os = "linux")]
    {
        unsafe { collect_addrs() }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
unsafe fn collect_addrs() -> Vec<Addr> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if libc::getifaddrs(&mut head) != 0 || head.is_null() {
        return Vec::new();
    }
    let mut rows = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        let item = &*cursor;
        if !item.ifa_name.is_null() && !item.ifa_addr.is_null() {
            let name = std::ffi::CStr::from_ptr(item.ifa_name).to_string_lossy().to_string();
            if let Some((family, addr)) = format_sockaddr(item.ifa_addr, item.ifa_netmask) {
                rows.push(Addr {
                    iface: name,
                    family,
                    addr,
                });
            }
        }
        cursor = item.ifa_next;
    }
    libc::freeifaddrs(head);
    rows.sort_by(|left, right| {
        left.iface
            .cmp(&right.iface)
            .then(left.family.cmp(&right.family))
            .then(left.addr.cmp(&right.addr))
    });
    rows
}

#[cfg(target_os = "linux")]
unsafe fn format_sockaddr(addr: *const libc::sockaddr, mask: *const libc::sockaddr) -> Option<(String, String)> {
    let family = (*addr).sa_family as i32;
    if family == libc::AF_INET {
        let inet = &*(addr as *const libc::sockaddr_in);
        let ip = Ipv4Addr::from(u32::from_be(inet.sin_addr.s_addr));
        let prefix = prefix_from_mask(mask, true);
        return Some(("IPv4".into(), format!("{ip}/{prefix}")));
    }
    if family == libc::AF_INET6 {
        let inet = &*(addr as *const libc::sockaddr_in6);
        let ip = compress_ipv6(&inet.sin6_addr.s6_addr);
        let prefix = prefix_from_mask(mask, false);
        return Some(("IPv6".into(), format!("{ip}/{prefix}")));
    }
    None
}

#[cfg(target_os = "linux")]
unsafe fn prefix_from_mask(mask: *const libc::sockaddr, v4: bool) -> u32 {
    if mask.is_null() {
        return if v4 { 32 } else { 128 };
    }
    if v4 {
        let inet = &*(mask as *const libc::sockaddr_in);
        u32::from_be(inet.sin_addr.s_addr).count_ones()
    } else {
        let inet = &*(mask as *const libc::sockaddr_in6);
        inet.sin6_addr
            .s6_addr
            .iter()
            .map(|byte| byte.count_ones())
            .sum()
    }
}

fn read_sysctls() -> Vec<Sysctl> {
    [
        ("net.ipv4.ip_forward", "转发"),
        ("net.ipv4.conf.all.rp_filter", "反向路径过滤"),
        ("net.ipv4.tcp_congestion_control", "拥塞控制"),
        ("net.core.somaxconn", "监听队列上限"),
        ("net.ipv4.tcp_max_syn_backlog", "SYN 队列"),
        ("net.core.netdev_max_backlog", "网卡 backlog"),
        ("net.ipv4.ip_local_port_range", "本地端口"),
        ("net.ipv4.tcp_fin_timeout", "FIN 超时"),
        ("net.ipv4.tcp_tw_reuse", "TIME_WAIT 复用"),
        ("net.ipv4.tcp_keepalive_time", "保活秒数"),
        ("net.ipv4.tcp_rmem", "TCP 接收缓冲"),
        ("net.ipv4.tcp_wmem", "TCP 发送缓冲"),
        ("net.core.rmem_max", "接收缓冲上限"),
        ("net.core.wmem_max", "发送缓冲上限"),
        ("net.netfilter.nf_conntrack_count", "连接跟踪数"),
        ("net.netfilter.nf_conntrack_max", "连接跟踪上限"),
    ]
    .into_iter()
    .map(|(key, label)| Sysctl {
        label: label.into(),
        key: key.into(),
        value: read_sysctl(key).unwrap_or_else(|| "读不到".into()),
    })
    .collect()
}

fn read_sysctl(key: &str) -> Option<String> {
    let rest = key.strip_prefix("net.")?;
    let path = format!("/proc/sys/net/{}", rest.replace('.', "/"));
    let text = read_text(&path);
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

fn load_rules() -> (String, Vec<String>) {
    if let Some(text) = command_text("nft", &["list", "ruleset"]) {
        let lines = rule_lines(&text);
        if !lines.is_empty() {
            return ("nft list ruleset".into(), lines);
        }
    }
    let mut lines = Vec::new();
    if let Some(text) = command_text("iptables-save", &[]) {
        lines.extend(rule_lines(&text));
    }
    if let Some(text) = command_text("ip6tables-save", &[]) {
        lines.extend(rule_lines(&text));
    }
    if !lines.is_empty() {
        return ("iptables-save".into(), lines);
    }
    (
        "没有读到规则。nft 和 iptables-save 都没有返回内容。".into(),
        Vec::new(),
    )
}

fn command_text(bin: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(bin)
        .args(args)
        .env("TERM", "dumb")
        .output()
        .ok()?;
    if !output.status.success() && output.stdout.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    if text.trim().is_empty() {
        None
    } else {
        Some(text)
    }
}

pub fn plain_line(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            match chars.peek().copied() {
                Some('[') => {
                    chars.next();
                    for next in chars.by_ref() {
                        if ('@'..='~').contains(&next) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    chars.next();
                    while let Some(next) = chars.next() {
                        if next == '\u{7}' {
                            break;
                        }
                        if next == '\u{1b}' {
                            if chars.peek() == Some(&'\\') {
                                chars.next();
                            }
                            break;
                        }
                    }
                }
                Some(_) => {
                    chars.next();
                }
                None => {}
            }
            continue;
        }
        if ch == '\t' {
            out.push_str("    ");
            continue;
        }
        if ch.is_control() {
            continue;
        }
        out.push(ch);
    }
    out
}

fn rule_lines(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = text
        .lines()
        .map(plain_line)
        .map(|line| line.trim_end().to_string())
        .filter(|line| !line.is_empty())
        .take(1500)
        .collect();
    if text.lines().filter(|line| !line.trim().is_empty()).count() > lines.len() {
        lines.push(format!("还有规则没有放进这一页，先显示前 {} 行", lines.len()));
    }
    lines
}

fn dmi(name: &str) -> String {
    let text = read_text(&format!("/sys/class/dmi/id/{name}"));
    let text = text.trim();
    if text.is_empty() || text == "None" || text.eq_ignore_ascii_case("not specified") {
        String::new()
    } else {
        text.to_string()
    }
}

fn first_nonempty(values: &[String]) -> String {
    values
        .iter()
        .find(|item| !item.is_empty())
        .cloned()
        .unwrap_or_else(|| "读不到".into())
}

fn join_nonempty(values: &[String]) -> String {
    let text = values
        .iter()
        .filter(|item| !item.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join("  ");
    if text.is_empty() {
        "读不到".into()
    } else {
        text
    }
}

fn cpu_summary(cpuinfo: &str) -> String {
    let mut model = String::new();
    let mut threads = 0u32;
    let mut cores = 0u32;
    let mut cache = String::new();
    let mut mhz = String::new();
    for line in cpuinfo.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "processor" => threads += 1,
            "model name" if model.is_empty() => model = value.to_string(),
            "cpu cores" if cores == 0 => cores = value.parse().unwrap_or(0),
            "cache size" if cache.is_empty() => cache = value.to_string(),
            "cpu MHz" if mhz.is_empty() => mhz = value.split('.').next().unwrap_or(value).to_string(),
            _ => {}
        }
    }
    if model.is_empty() {
        return "读不到".into();
    }
    let mut text = model;
    if threads > 0 {
        text.push_str(&format!("  {threads} 线程"));
    }
    if cores > 0 {
        text.push_str(&format!("  每槽 {cores} 核"));
    }
    if !cache.is_empty() {
        text.push_str(&format!("  缓存 {cache}"));
    }
    if !mhz.is_empty() {
        text.push_str(&format!("  {mhz} MHz"));
    }
    text
}

fn mem_total(meminfo: &str) -> String {
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: u64 = rest.split_whitespace().next().unwrap_or("0").parse().unwrap_or(0);
            return human_kb(kb);
        }
    }
    "读不到".into()
}

fn human_kb(kb: u64) -> String {
    if kb >= 1024 * 1024 {
        format!("{:.1} GiB", kb as f64 / 1024.0 / 1024.0)
    } else if kb >= 1024 {
        format!("{:.0} MiB", kb as f64 / 1024.0)
    } else {
        format!("{kb} KiB")
    }
}

fn read_disks() -> Vec<HwDisk> {
    let Ok(dir) = fs::read_dir("/sys/block") else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if ["loop", "ram", "fd", "sr", "zram"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
        {
            continue;
        }
        let base = format!("/sys/block/{name}");
        let sectors: u64 = read_text(&format!("{base}/size")).parse().unwrap_or(0);
        let model = fallback(&read_text(&format!("{base}/device/model")), "");
        let serial = fallback(&read_text(&format!("{base}/device/serial")), "");
        let vendor = read_text(&format!("{base}/device/vendor"));
        let rotational = read_text(&format!("{base}/queue/rotational"));
        let model = join_nonempty(&[vendor, model.clone()]);
        let kind = if rotational.trim() == "0" {
            "固态"
        } else if model.contains("0x") || model.is_empty() {
            "虚拟"
        } else {
            "机械"
        };
        rows.push(HwDisk {
            name,
            size: human_sectors(sectors),
            bytes: sectors.saturating_mul(512),
            model: if model.is_empty() { "读不到".into() } else { model },
            serial: if serial.is_empty() { "读不到".into() } else { serial },
            kind: kind.into(),
        });
    }
    rows.sort_by(|left, right| left.name.cmp(&right.name));
    rows
}

fn read_text(path: &str) -> String {
    fs::read_to_string(path)
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn fallback(text: &str, missing: &str) -> String {
    let text = text.trim();
    if text.is_empty() {
        missing.into()
    } else {
        text.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_line_drops_color_and_controls() {
        assert_eq!(plain_line("\u{1b}[31mdrop\u{1b}[0m"), "drop");
        assert_eq!(plain_line("a\tb\r\nc"), "a    bc");
    }

    #[test]
    fn disk_size_uses_binary_units() {
        assert_eq!(human_sectors(2 * 1024 * 1024), "1.0 GiB");
    }

    #[test]
    fn route_file_keeps_gateway_and_prefix() {
        let text = "\
Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
eth0 00000000 0100A8C0 0003 0 0 100 00000000 0 0 0
tun0 0000080A 00000000 0001 0 0 0 00FFFFFF 0 0 0
";
        let rows = parse_route4(text);
        assert_eq!(rows[0].destination, "0.0.0.0/0");
        assert_eq!(rows[0].gateway, "192.168.0.1");
        assert_eq!(rows[0].metric, 100);
        assert_eq!(rows[1].destination, "10.8.0.0/24");
        assert_eq!(rows[1].gateway, "直连");
    }

    #[test]
    fn ipv6_route_compresses_the_address() {
        let line = "fd7a115ca1e000000000000000000053 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00000001 tailscale0\n";
        let rows = parse_route6(line);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].destination, "fd7a:115c:a1e0::53/128");
        assert_eq!(rows[0].iface, "tailscale0");
        assert_eq!(rows[0].gateway, "直连");
    }
}
