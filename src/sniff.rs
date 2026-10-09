use std::collections::HashMap;
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    Tcp,
    Udp,
    Icmp,
    Arp,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KindFilter {
    All,
    Tcp,
    Udp,
    Icmp,
}

impl KindFilter {
    pub fn label(self) -> &'static str {
        match self {
            KindFilter::All => "全部",
            KindFilter::Tcp => "只看 TCP",
            KindFilter::Udp => "只看 UDP",
            KindFilter::Icmp => "只看 ICMP",
        }
    }

    pub fn allows(self, kind: PacketKind) -> bool {
        match self {
            KindFilter::All => true,
            KindFilter::Tcp => kind == PacketKind::Tcp,
            KindFilter::Udp => kind == PacketKind::Udp,
            KindFilter::Icmp => kind == PacketKind::Icmp,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PacketView {
    pub kind: PacketKind,
    pub summary: String,
    pub layers: Vec<String>,
    pub abnormal: bool,
    pub reason: String,
}

pub struct Capture {
    fd: i32,
    names: HashMap<i32, String>,
    label: String,
}

impl Capture {
    pub fn closed() -> Self {
        Self {
            fd: -1,
            names: HashMap::new(),
            label: String::new(),
        }
    }

    pub fn is_open(&self) -> bool {
        self.fd >= 0
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn open(iface: Option<&str>) -> Result<Self, String> {
        #[cfg(target_os = "linux")]
        {
            open_linux(iface)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = iface;
            Err("抓包只在 Linux 上可用".into())
        }
    }

    pub fn recv(&self) -> Option<(String, PacketView)> {
        if self.fd < 0 {
            return None;
        }
        #[cfg(target_os = "linux")]
        {
            recv_one(self.fd, &self.names)
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
            self.fd = -1;
        }
    }
}

pub fn describe(frame: &[u8]) -> PacketView {
    if frame.len() >= 14 {
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        if matches!(ethertype, 0x0800 | 0x86DD | 0x0806 | 0x8100) {
            let mut layers = vec![ethernet_line(frame, ethertype)];
            match ethertype {
                0x0800 => return describe_ip4(&frame[14..], frame.len(), layers),
                0x86DD => return describe_ip6(&frame[14..], frame.len(), layers),
                0x0806 => return describe_arp(&frame[14..], frame.len(), layers),
                0x8100 if frame.len() >= 18 => {
                    let tci = u16::from_be_bytes([frame[14], frame[15]]);
                    layers.push(format!("VLAN  {}  优先级 {}", tci & 0x0fff, tci >> 13));
                    let inner = u16::from_be_bytes([frame[16], frame[17]]);
                    let payload = &frame[18..];
                    return match inner {
                        0x0800 => describe_ip4(payload, frame.len(), layers),
                        0x86DD => describe_ip6(payload, frame.len(), layers),
                        0x0806 => describe_arp(payload, frame.len(), layers),
                        _ => broken(frame.len(), layers, "VLAN 后面的类型不认识"),
                    };
                }
                _ => {}
            }
        }
    }
    match frame.first().map(|byte| byte >> 4) {
        Some(4) => describe_ip4(frame, frame.len(), Vec::new()),
        Some(6) => describe_ip6(frame, frame.len(), Vec::new()),
        _ => broken(frame.len(), Vec::new(), "认不出报文头"),
    }
}

pub fn query_match(text: &str, query: &str) -> bool {
    let query = query.trim();
    if query.is_empty() {
        return true;
    }
    let haystack = text.to_ascii_lowercase();
    query
        .split_whitespace()
        .all(|token| haystack.contains(&token.to_ascii_lowercase()))
}

pub fn demo_packets() -> Vec<(String, PacketView)> {
    vec![
        demo_line(
            "14:00:01.100  eth0  TCP  10.0.0.8:45211 → 10.0.0.1:80  SYN  66B",
            PacketKind::Tcp,
            &[
                "以太网  源 02:42:0a:00:00:08  目的 02:42:0a:00:00:01  IPv4",
                "IPv4  10.0.0.8 → 10.0.0.1  TTL 64  协议 TCP  不分片",
                "TCP  45211 → 80  SYN  序号 1000  确认 0  窗口 65535",
                "载荷  没有",
            ],
            "",
        ),
        demo_line(
            "14:00:01.108  eth0  TCP  10.0.0.1:80 → 10.0.0.8:45211  SYN+ACK  66B",
            PacketKind::Tcp,
            &[
                "以太网  源 02:42:0a:00:00:01  目的 02:42:0a:00:00:08  IPv4",
                "IPv4  10.0.0.1 → 10.0.0.8  TTL 64  协议 TCP  不分片",
                "TCP  80 → 45211  SYN+ACK  序号 2000  确认 1001  窗口 65535",
                "载荷  没有",
            ],
            "",
        ),
        demo_line(
            "14:00:01.120  eth0  TCP  10.0.0.1:80 → 10.0.0.8:45211  RST  54B",
            PacketKind::Tcp,
            &[
                "IPv4  10.0.0.1 → 10.0.0.8  TTL 64  协议 TCP  不分片",
                "TCP  80 → 45211  RST  序号 2001  确认 0  窗口 0",
                "载荷  没有",
            ],
            "RST",
        ),
        demo_line(
            "14:00:01.200  eth0  UDP  10.0.0.8:5353 → 224.0.0.251:5353  80B",
            PacketKind::Udp,
            &[
                "IPv4  10.0.0.8 → 224.0.0.251  TTL 1  协议 UDP  不分片",
                "UDP  5353 → 5353  长度 60",
                "载荷  52 字节，不展示内容",
            ],
            "",
        ),
        demo_line(
            "14:00:01.300  eth0  ICMP  10.0.0.8 → 1.1.1.1  不可达  98B",
            PacketKind::Icmp,
            &[
                "IPv4  10.0.0.8 → 1.1.1.1  TTL 64  协议 ICMP  不分片",
                "ICMP  类型 3  端口不可达  代码 3",
            ],
            "端口不可达",
        ),
    ]
}

fn demo_line(text: &str, kind: PacketKind, layers: &[&str], reason: &str) -> (String, PacketView) {
    (
        text.into(),
        PacketView {
            kind,
            summary: text.into(),
            layers: layers.iter().map(|line| (*line).to_string()).collect(),
            abnormal: !reason.is_empty(),
            reason: reason.into(),
        },
    )
}

fn broken(len: usize, layers: Vec<String>, reason: &str) -> PacketView {
    PacketView {
        kind: PacketKind::Other,
        summary: format!("其他  {len}B"),
        layers,
        abnormal: true,
        reason: reason.into(),
    }
}

fn describe_ip4(packet: &[u8], frame_len: usize, mut layers: Vec<String>) -> PacketView {
    if packet.len() < 20 {
        return broken(frame_len, layers, "IPv4 头不完整");
    }
    let header = ((packet[0] & 0x0f) as usize) * 4;
    if header < 20 || packet.len() < header {
        return broken(frame_len, layers, "IPv4 头不完整");
    }
    let src = ipv4(&packet[12..16]);
    let dst = ipv4(&packet[16..20]);
    let total = u16::from_be_bytes([packet[2], packet[3]]);
    let frag = u16::from_be_bytes([packet[6], packet[7]]);
    let offset = frag & 0x1fff;
    let more = frag & 0x2000 != 0;
    let mut reasons = Vec::new();
    if offset != 0 || more {
        reasons.push("分片".into());
    }
    layers.push(format!(
        "IPv4  {src} → {dst}  TTL {}  协议 {}  头 {header}  总长 {total}  {}",
        packet[8],
        ip_proto(packet[9]),
        if offset == 0 && !more {
            "不分片".to_string()
        } else {
            format!("分片偏移 {offset}")
        }
    ));
    if offset != 0 {
        return finish(
            PacketKind::Other,
            format!("IPv4 分片  {src} → {dst}  {frame_len}B"),
            layers,
            reasons,
        );
    }
    match packet[9] {
        6 => describe_tcp(&packet[header..], &src, &dst, frame_len, layers, reasons),
        17 => describe_udp(&packet[header..], &src, &dst, frame_len, layers, reasons),
        1 => describe_icmp(&packet[header..], &src, &dst, frame_len, layers, reasons, false),
        proto => finish(
            PacketKind::Other,
            format!("IP 协议 {proto}  {src} → {dst}  {frame_len}B"),
            layers,
            reasons,
        ),
    }
}

fn describe_ip6(packet: &[u8], frame_len: usize, mut layers: Vec<String>) -> PacketView {
    if packet.len() < 40 {
        return broken(frame_len, layers, "IPv6 头不完整");
    }
    let src = ipv6(&packet[8..24]);
    let dst = ipv6(&packet[24..40]);
    let next = packet[6];
    layers.push(format!(
        "IPv6  {src} → {dst}  跳数限制 {}  下一头 {}",
        packet[7],
        ip_proto(next)
    ));
    match next {
        6 => describe_tcp(&packet[40..], &src, &dst, frame_len, layers, Vec::new()),
        17 => describe_udp(&packet[40..], &src, &dst, frame_len, layers, Vec::new()),
        58 => describe_icmp(&packet[40..], &src, &dst, frame_len, layers, Vec::new(), true),
        proto => finish(
            PacketKind::Other,
            format!("IPv6 协议 {proto}  {src} → {dst}  {frame_len}B"),
            layers,
            Vec::new(),
        ),
    }
}

fn describe_tcp(
    packet: &[u8],
    src: &str,
    dst: &str,
    frame_len: usize,
    mut layers: Vec<String>,
    mut reasons: Vec<String>,
) -> PacketView {
    if packet.len() < 20 {
        return broken(frame_len, layers, "TCP 头不完整");
    }
    let sport = u16::from_be_bytes([packet[0], packet[1]]);
    let dport = u16::from_be_bytes([packet[2], packet[3]]);
    let seq = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
    let ack = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);
    let header = ((packet[12] >> 4) as usize) * 4;
    let flags_byte = packet[13];
    let window = u16::from_be_bytes([packet[14], packet[15]]);
    let flags = tcp_flags(flags_byte);
    if flags_byte & 0x04 != 0 {
        reasons.push("RST".into());
    }
    if flags_byte & 0x02 != 0 && flags_byte & 0x01 != 0 {
        reasons.push("SYN+FIN".into());
    }
    if flags_byte == 0 {
        reasons.push("没有标志".into());
    }
    if window == 0 && flags_byte & 0x10 != 0 && flags_byte & 0x02 == 0 {
        reasons.push("零窗口".into());
    }
    if header < 20 {
        reasons.push("TCP 头不完整".into());
    }
    let payload = packet.len().saturating_sub(header.max(20));
    layers.push(format!(
        "TCP  {sport} → {dport}  {flags}  序号 {seq}  确认 {ack}  窗口 {window}  头 {header}"
    ));
    layers.push(payload_line(payload));
    finish(
        PacketKind::Tcp,
        format!("TCP  {src}:{sport} → {dst}:{dport}  {flags}  {frame_len}B"),
        layers,
        reasons,
    )
}

fn describe_udp(
    packet: &[u8],
    src: &str,
    dst: &str,
    frame_len: usize,
    mut layers: Vec<String>,
    reasons: Vec<String>,
) -> PacketView {
    if packet.len() < 8 {
        return broken(frame_len, layers, "UDP 头不完整");
    }
    let sport = u16::from_be_bytes([packet[0], packet[1]]);
    let dport = u16::from_be_bytes([packet[2], packet[3]]);
    let len = u16::from_be_bytes([packet[4], packet[5]]);
    let payload = packet.len().saturating_sub(8);
    layers.push(format!("UDP  {sport} → {dport}  长度 {len}"));
    layers.push(payload_line(payload));
    finish(
        PacketKind::Udp,
        format!("UDP  {src}:{sport} → {dst}:{dport}  {frame_len}B"),
        layers,
        reasons,
    )
}

fn describe_icmp(
    packet: &[u8],
    src: &str,
    dst: &str,
    frame_len: usize,
    mut layers: Vec<String>,
    mut reasons: Vec<String>,
    v6: bool,
) -> PacketView {
    let kind = packet.first().copied();
    let code = packet.get(1).copied().unwrap_or(0);
    let (name, bad) = icmp_detail(kind, code, v6);
    if let Some(reason) = bad {
        reasons.push(reason);
    }
    let title = if v6 { "ICMPv6" } else { "ICMP" };
    layers.push(format!("{title}  类型 {}  {name}  代码 {code}", kind.unwrap_or(255)));
    finish(
        PacketKind::Icmp,
        format!("{title}  {src} → {dst}  {name}  {frame_len}B"),
        layers,
        reasons,
    )
}

fn describe_arp(packet: &[u8], frame_len: usize, mut layers: Vec<String>) -> PacketView {
    if packet.len() < 28 {
        return broken(frame_len, layers, "ARP 不完整");
    }
    let op = u16::from_be_bytes([packet[6], packet[7]]);
    let sender = ipv4(&packet[14..18]);
    let target = ipv4(&packet[24..28]);
    let verb = match op {
        1 => format!("谁有 {target}  告诉 {sender}"),
        2 => format!("{sender} 在  {target} 不必再问"),
        _ => format!("操作 {op}  {sender} → {target}"),
    };
    layers.push(format!("ARP  {verb}"));
    finish(PacketKind::Arp, format!("ARP  {verb}  {frame_len}B"), layers, Vec::new())
}

fn finish(kind: PacketKind, summary: String, layers: Vec<String>, reasons: Vec<String>) -> PacketView {
    PacketView {
        kind,
        summary,
        layers,
        abnormal: !reasons.is_empty(),
        reason: reasons.join("、"),
    }
}

fn payload_line(len: usize) -> String {
    if len == 0 {
        "载荷  没有".into()
    } else {
        format!("载荷  {len} 字节，不展示内容")
    }
}

fn ethernet_line(frame: &[u8], ethertype: u16) -> String {
    format!(
        "以太网  源 {}  目的 {}  {}",
        mac(&frame[6..12]),
        mac(&frame[0..6]),
        ether_name(ethertype)
    )
}

fn mac(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(":")
}

fn ether_name(ethertype: u16) -> &'static str {
    match ethertype {
        0x0800 => "IPv4",
        0x86DD => "IPv6",
        0x0806 => "ARP",
        0x8100 => "VLAN",
        _ => "其他",
    }
}

fn ip_proto(proto: u8) -> String {
    match proto {
        1 => "ICMP".into(),
        6 => "TCP".into(),
        17 => "UDP".into(),
        58 => "ICMPv6".into(),
        other => other.to_string(),
    }
}

fn tcp_flags(flags: u8) -> String {
    let mut names = Vec::new();
    if flags & 0x02 != 0 {
        names.push("SYN");
    }
    if flags & 0x10 != 0 {
        names.push("ACK");
    }
    if flags & 0x01 != 0 {
        names.push("FIN");
    }
    if flags & 0x04 != 0 {
        names.push("RST");
    }
    if flags & 0x08 != 0 {
        names.push("PSH");
    }
    if names.is_empty() {
        "无标志".into()
    } else {
        names.join("+")
    }
}

fn icmp_detail(kind: Option<u8>, code: u8, v6: bool) -> (&'static str, Option<String>) {
    if v6 {
        return match kind {
            Some(1) => ("目的不可达", Some("目的不可达".into())),
            Some(2) => ("包太大", Some("包太大".into())),
            Some(3) => ("超时", Some("超时".into())),
            Some(4) => ("参数问题", Some("参数问题".into())),
            Some(128) => ("请求", None),
            Some(129) => ("回应", None),
            _ => ("其他", None),
        };
    }
    match (kind, code) {
        (Some(0), _) => ("回应", None),
        (Some(8), _) => ("请求", None),
        (Some(3), 0) => ("网络不可达", Some("网络不可达".into())),
        (Some(3), 1) => ("主机不可达", Some("主机不可达".into())),
        (Some(3), 3) => ("端口不可达", Some("端口不可达".into())),
        (Some(3), 4) => ("需要分片", Some("需要分片".into())),
        (Some(3), _) => ("不可达", Some("不可达".into())),
        (Some(5), _) => ("重定向", Some("重定向".into())),
        (Some(11), _) => ("超时", Some("超时".into())),
        (Some(12), _) => ("参数问题", Some("参数问题".into())),
        _ => ("其他", None),
    }
}

fn ipv4(bytes: &[u8]) -> String {
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

fn ipv6(bytes: &[u8]) -> String {
    let mut groups = Vec::new();
    for index in 0..8 {
        groups.push(format!(
            "{:x}",
            u16::from_be_bytes([bytes[index * 2], bytes[index * 2 + 1]])
        ));
    }
    groups.join(":")
}

#[cfg(target_os = "linux")]
fn open_linux(iface: Option<&str>) -> Result<Capture, String> {
    let protocol = (libc::ETH_P_ALL as u16).to_be() as i32;
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, protocol) };
    if fd < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::PermissionDenied {
            return Err("抓包需要 root 或 CAP_NET_RAW。当前用户打不开网卡。".into());
        }
        return Err(format!("打开网卡失败: {err}"));
    }
    unsafe {
        libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
    }
    if let Some(name) = iface {
        let index = std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
            .ok()
            .and_then(|text| text.trim().parse::<i32>().ok())
            .ok_or_else(|| {
                unsafe { libc::close(fd); }
                format!("没有网卡 {name}")
            })?;
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        addr.sll_ifindex = index;
        let bound = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if bound != 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd); }
            return Err(format!("绑定 {name} 失败: {err}"));
        }
    }
    Ok(Capture {
        fd,
        names: nic_names(),
        label: iface.unwrap_or("全部网卡").to_string(),
    })
}

#[cfg(target_os = "linux")]
fn recv_one(fd: i32, names: &HashMap<i32, String>) -> Option<(String, PacketView)> {
    let mut buf = [0u8; 256];
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
    let size = unsafe {
        libc::recvfrom(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            libc::MSG_TRUNC,
            &mut addr as *mut libc::sockaddr_ll as *mut libc::sockaddr,
            &mut len,
        )
    };
    if size < 0 {
        return None;
    }
    let copied = (size as usize).min(buf.len());
    let mut view = describe(&buf[..copied]);
    view.summary = view.summary.replace(&format!(" {copied}B"), &format!(" {size}B"));
    let iface = names
        .get(&addr.sll_ifindex)
        .cloned()
        .unwrap_or_else(|| format!("if{}", addr.sll_ifindex));
    let text = format!("{}  {iface}  {}", clock_ms(), view.summary);
    Some((text, view))
}

#[cfg(target_os = "linux")]
fn nic_names() -> HashMap<i32, String> {
    let mut names = HashMap::new();
    let Ok(dir) = std::fs::read_dir("/sys/class/net") else {
        return names;
    };
    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if let Ok(text) = std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex")) {
            if let Ok(index) = text.trim().parse::<i32>() {
                names.insert(index, name);
            }
        }
    }
    names
}

#[cfg(target_os = "linux")]
fn clock_ms() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as libc::time_t)
        .unwrap_or(0);
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.subsec_millis())
        .unwrap_or(0);
    unsafe {
        let mut tm = std::mem::zeroed();
        if libc::localtime_r(&secs, &mut tm).is_null() {
            return format!("--:--:--.{millis:03}");
        }
        format!("{:02}:{:02}:{:02}.{millis:03}", tm.tm_hour, tm.tm_min, tm.tm_sec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_syn_is_a_sentence() {
        let mut frame = vec![0u8; 54];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[14] = 0x45;
        frame[23] = 6;
        frame[26] = 10;
        frame[27] = 0;
        frame[28] = 0;
        frame[29] = 8;
        frame[30] = 10;
        frame[31] = 0;
        frame[32] = 0;
        frame[33] = 1;
        frame[34] = 0x00;
        frame[35] = 0x50;
        frame[36] = 0x11;
        frame[37] = 0x5c;
        frame[46] = 0x50;
        frame[47] = 0x02;
        let view = describe(&frame);
        assert_eq!(view.kind, PacketKind::Tcp);
        assert_eq!(view.summary, "TCP  10.0.0.8:80 → 10.0.0.1:4444  SYN  54B");
        assert!(!view.abnormal, "{}", view.reason);
        assert!(view.layers.iter().any(|line| line.contains("序号")), "{:?}", view.layers);
        assert!(view.layers.iter().any(|line| line.contains("不展示内容") || line.contains("载荷  没有")));
    }

    #[test]
    fn rst_and_unreachable_are_abnormal() {
        let mut frame = vec![0u8; 54];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[14] = 0x45;
        frame[23] = 6;
        frame[34] = 0x50;
        frame[47] = 0x04;
        let view = describe(&frame);
        assert!(view.abnormal);
        assert!(view.reason.contains("RST"), "{}", view.reason);

        let mut icmp = vec![0u8; 42];
        icmp[12] = 0x08;
        icmp[13] = 0x00;
        icmp[14] = 0x45;
        icmp[23] = 1;
        icmp[34] = 3;
        icmp[35] = 3;
        let view = describe(&icmp);
        assert_eq!(view.kind, PacketKind::Icmp);
        assert!(view.reason.contains("端口不可达"), "{}", view.reason);
    }

    #[test]
    fn fuzzy_query_matches_every_word() {
        let text = "TCP  10.0.0.8:80 → 10.0.0.1:4444  SYN";
        assert!(query_match(text, "10.0.0 syn"));
        assert!(!query_match(text, "10.0.0 udp"));
        assert!(query_match(text, "   "));
    }

    #[test]
    fn filter_hides_other_protocols() {
        assert!(KindFilter::Tcp.allows(PacketKind::Tcp));
        assert!(!KindFilter::Tcp.allows(PacketKind::Udp));
        assert!(KindFilter::All.allows(PacketKind::Arp));
    }
}
