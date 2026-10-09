use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAGIC: &[u8; 4] = b"LPB1";
const UPLOAD: u8 = 1;
const HELLO: u8 = 1;
const ACK: u8 = 2;
const DATA: u8 = 3;
const STATS: u8 = 4;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn label(self) -> &'static str {
        match self {
            Proto::Tcp => "TCP",
            Proto::Udp => "UDP",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Snap {
    pub sent: u64,
    pub recv: u64,
    pub sent_pkts: u64,
    pub recv_pkts: u64,
    pub lost: u64,
    pub elapsed: Duration,
    pub running: bool,
    pub error: String,
    pub phase: String,
}

struct Inner {
    sent: u64,
    recv: u64,
    sent_pkts: u64,
    recv_pkts: u64,
    lost: u64,
    started: Option<Instant>,
    running: bool,
    error: String,
    phase: String,
}

impl Inner {
    fn snap(&self) -> Snap {
        Snap {
            sent: self.sent,
            recv: self.recv,
            sent_pkts: self.sent_pkts,
            recv_pkts: self.recv_pkts,
            lost: self.lost,
            elapsed: self.started.map(|at| at.elapsed()).unwrap_or_default(),
            running: self.running,
            error: self.error.clone(),
            phase: self.phase.clone(),
        }
    }
}

pub struct Session {
    stop: Arc<AtomicBool>,
    stats: Arc<Mutex<Inner>>,
    handle: Option<JoinHandle<()>>,
}

impl Session {
    pub fn idle() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(Mutex::new(Inner {
                sent: 0,
                recv: 0,
                sent_pkts: 0,
                recv_pkts: 0,
                lost: 0,
                started: None,
                running: false,
                error: String::new(),
                phase: "等待开始".into(),
            })),
            handle: None,
        }
    }

    pub fn snap(&self) -> Snap {
        self.stats
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .snap()
    }

    pub fn note_error(&mut self, message: String) {
        if let Ok(mut row) = self.stats.lock() {
            row.error = message.clone();
            row.phase = message;
            row.running = false;
        }
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        if let Ok(mut stats) = self.stats.lock() {
            stats.running = false;
        }
    }

    pub fn start_preview(&mut self) {
        self.stop();
        self.stop = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&self.stop);
        let stats = Arc::new(Mutex::new(Inner {
            sent: 0,
            recv: 0,
            sent_pkts: 0,
            recv_pkts: 0,
            lost: 0,
            started: Some(Instant::now()),
            running: true,
            error: String::new(),
            phase: "演示数据，没有打开端口".into(),
        }));
        self.stats = Arc::clone(&stats);
        self.handle = Some(thread::spawn(move || {
            let chunk = 12_500_000u64;
            for _ in 0..100 {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
                if let Ok(mut row) = stats.lock() {
                    row.sent += chunk / 10;
                    row.recv += chunk / 10;
                    row.sent_pkts += 80;
                    row.recv_pkts += 80;
                }
            }
            if let Ok(mut row) = stats.lock() {
                row.running = false;
                row.phase = "完成".into();
            }
        }));
    }

    pub fn start_client(&mut self, host: &str, port: u16, proto: Proto, seconds: u64) -> Result<(), String> {
        let addr = resolve(host, port)?;
        let seconds = seconds.clamp(1, 10);
        self.spawn(move |stop, stats| match proto {
            Proto::Tcp => tcp_client(addr, seconds, stop, stats),
            Proto::Udp => udp_client(addr, seconds, stop, stats),
        });
        Ok(())
    }

    pub fn start_server(&mut self, port: u16, proto: Proto) -> Result<(), String> {
        self.spawn(move |stop, stats| match proto {
            Proto::Tcp => tcp_server(port, stop, stats),
            Proto::Udp => udp_server(port, stop, stats),
        });
        Ok(())
    }

    fn spawn(&mut self, work: impl FnOnce(Arc<AtomicBool>, Arc<Mutex<Inner>>) + Send + 'static) {
        self.stop();
        self.stop = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&self.stop);
        let stats = Arc::new(Mutex::new(Inner {
            sent: 0,
            recv: 0,
            sent_pkts: 0,
            recv_pkts: 0,
            lost: 0,
            started: Some(Instant::now()),
            running: true,
            error: String::new(),
            phase: "正在准备".into(),
        }));
        self.stats = Arc::clone(&stats);
        self.handle = Some(thread::spawn(move || {
            work(stop, Arc::clone(&stats));
            if let Ok(mut row) = stats.lock() {
                row.running = false;
                if row.error.is_empty() && row.phase != "完成" {
                    row.phase = "已停止".into();
                }
            }
        }));
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn megabits_per_sec(bytes: u64, elapsed: Duration) -> f64 {
    let millis = elapsed.as_secs_f64() * 1000.0;
    if millis < 1.0 {
        return 0.0;
    }
    bytes as f64 * 8.0 / (millis / 1000.0) / 1_000_000.0
}

pub fn mebibytes_per_sec(bytes: u64, elapsed: Duration) -> f64 {
    let millis = elapsed.as_secs_f64() * 1000.0;
    if millis < 1.0 {
        return 0.0;
    }
    bytes as f64 / (millis / 1000.0) / (1024.0 * 1024.0)
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr, String> {
    let host = host.trim().trim_matches(|ch| ch == '[' || ch == ']');
    if host.is_empty() || host.chars().any(|ch| ch.is_whitespace()) || host.starts_with('-') {
        return Err("主机不能为空，不能含空格，也不能以 - 开头".into());
    }
    if port == 0 {
        return Err("端口要在 1 到 65535".into());
    }
    let spec = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    spec.to_socket_addrs_msg()
}

trait ResolveMsg {
    fn to_socket_addrs_msg(&self) -> Result<SocketAddr, String>;
}

impl ResolveMsg for String {
    fn to_socket_addrs_msg(&self) -> Result<SocketAddr, String> {
        use std::net::ToSocketAddrs;
        self.to_socket_addrs()
            .map_err(|err| format!("无法解析地址: {err}"))?
            .next()
            .ok_or_else(|| "无法解析地址".into())
    }
}

fn set_phase(stats: &Mutex<Inner>, phase: &str) {
    if let Ok(mut row) = stats.lock() {
        row.phase = phase.into();
    }
}

fn fail(stats: &Mutex<Inner>, message: String) {
    if let Ok(mut row) = stats.lock() {
        row.error = message.clone();
        row.phase = message;
        row.running = false;
    }
}

fn add_sent(stats: &Mutex<Inner>, bytes: u64, packets: u64) {
    if let Ok(mut row) = stats.lock() {
        row.sent += bytes;
        row.sent_pkts += packets;
    }
}

fn add_recv(stats: &Mutex<Inner>, bytes: u64, packets: u64) {
    if let Ok(mut row) = stats.lock() {
        row.recv += bytes;
        row.recv_pkts += packets;
    }
}

fn tcp_client(addr: SocketAddr, seconds: u64, stop: Arc<AtomicBool>, stats: Arc<Mutex<Inner>>) {
    set_phase(&stats, "正在连接");
    let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
        Ok(stream) => stream,
        Err(err) => {
            fail(&stats, format!("连接失败: {err}"));
            return;
        }
    };
    let _ = stream.set_nodelay(true);
    let mut header = [0u8; 8];
    header[0..4].copy_from_slice(MAGIC);
    header[4] = UPLOAD;
    header[6..8].copy_from_slice(&(seconds as u16).to_be_bytes());
    set_phase(&stats, "等待对端确认");
    if let Err(err) = write_all_stop(&stream, &header, &stop) {
        fail(&stats, format!("无法发送握手: {err}"));
        return;
    }
    let mut ack = [0u8; 1];
    if read_exact_deadline(&mut stream, &mut ack, Duration::from_secs(2), &stop).is_err() || ack[0] != b'K' {
        fail(
            &stats,
            "对端没有确认吞吐协议，已停止，没有发送测试数据".into(),
        );
        return;
    }
    set_phase(&stats, "测试中");
    let buf = vec![0u8; 16 * 1024];
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));
    while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
        match stream.write(&buf) {
            Ok(0) => break,
            Ok(n) => add_sent(&stats, n as u64, 1),
            Err(err) if paused(&err) => continue,
            Err(err) => {
                fail(&stats, format!("发送中断: {err}"));
                return;
            }
        }
    }
    let _ = stream.shutdown(std::net::Shutdown::Write);
    finish(&stats);
}

fn tcp_server(port: u16, stop: Arc<AtomicBool>, stats: Arc<Mutex<Inner>>) {
    let listener = match TcpListener::bind(("0.0.0.0", port)) {
        Ok(listener) => listener,
        Err(err) => {
            fail(&stats, format!("无法监听 {port}: {err}"));
            return;
        }
    };
    let bound = listener.local_addr().map(|addr| addr.port()).unwrap_or(port);
    let _ = listener.set_nonblocking(true);
    set_phase(&stats, &format!("监听 0.0.0.0:{bound}，等待一次 TCP 测试"));
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => tcp_serve_one(stream, &stop, &stats),
            Err(err) if paused(&err) => thread::sleep(Duration::from_millis(40)),
            Err(err) => {
                fail(&stats, format!("监听中断: {err}"));
                return;
            }
        }
    }
}

fn tcp_serve_one(mut stream: TcpStream, stop: &AtomicBool, stats: &Mutex<Inner>) {
    let _ = stream.set_nodelay(true);
    let mut header = [0u8; 8];
    if read_exact_deadline(&mut stream, &mut header, Duration::from_secs(2), stop).is_err()
        || header[0..4] != *MAGIC
        || header[4] != UPLOAD
    {
        set_phase(stats, "收到的不是 linuxtui 吞吐握手，继续等待");
        return;
    }
    let seconds = u16::from_be_bytes([header[6], header[7]]).clamp(1, 10);
    if write_all_stop(&stream, b"K", stop).is_err() {
        fail(stats, "无法确认握手".into());
        return;
    }
    set_phase(stats, "测试中");
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut buf = [0u8; 16 * 1024];
    let deadline = Instant::now() + Duration::from_secs(seconds as u64 + 2);
    while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => add_recv(stats, n as u64, 1),
            Err(err) if paused(&err) => continue,
            Err(_) => break,
        }
    }
    note_listen(stats);
}

fn udp_client(addr: SocketAddr, seconds: u64, stop: Arc<AtomicBool>, stats: Arc<Mutex<Inner>>) {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => socket,
        Err(err) => {
            fail(&stats, format!("无法打开 UDP: {err}"));
            return;
        }
    };
    let _ = socket.set_nonblocking(true);
    let mut hello = [0u8; 64];
    hello[0..4].copy_from_slice(MAGIC);
    hello[4] = HELLO;
    hello[6..8].copy_from_slice(&(seconds as u16).to_be_bytes());
    set_phase(&stats, "等待对端确认");
    if socket.send_to(&hello, addr).is_err() {
        fail(&stats, "无法发送 UDP 握手".into());
        return;
    }
    let mut buf = [0u8; 64];
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut acked = false;
    while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
        match socket.recv_from(&mut buf) {
            Ok((n, _)) if n >= 5 && buf[0..4] == *MAGIC && buf[4] == ACK => {
                acked = true;
                break;
            }
            Ok(_) => {}
            Err(err) if paused(&err) => thread::sleep(Duration::from_millis(20)),
            Err(err) => {
                fail(&stats, format!("UDP 握手失败: {err}"));
                return;
            }
        }
    }
    if !acked {
        fail(
            &stats,
            "对端没有确认吞吐协议，已停止，没有发送测试数据".into(),
        );
        return;
    }
    set_phase(&stats, "测试中");
    let mut packet = vec![0u8; 1400];
    packet[0..4].copy_from_slice(MAGIC);
    packet[4] = DATA;
    let end = Instant::now() + Duration::from_secs(seconds);
    let mut seq = 0u32;
    while Instant::now() < end && !stop.load(Ordering::Relaxed) {
        seq = seq.wrapping_add(1);
        packet[8..12].copy_from_slice(&seq.to_be_bytes());
        match socket.send_to(&packet, addr) {
            Ok(n) => add_sent(&stats, n as u64, 1),
            Err(err) if paused(&err) => {}
            Err(err) => {
                fail(&stats, format!("发送中断: {err}"));
                return;
            }
        }
        if let Ok((n, _)) = socket.recv_from(&mut buf) {
            if n >= 20 && buf[0..4] == *MAGIC && buf[4] == STATS {
                let remote_bytes = u64::from_be_bytes(buf[8..16].try_into().unwrap_or([0; 8]));
                let remote_pkts = u32::from_be_bytes(buf[16..20].try_into().unwrap_or([0; 4])) as u64;
                if let Ok(mut row) = stats.lock() {
                    row.recv = remote_bytes;
                    row.recv_pkts = remote_pkts;
                    row.lost = row.sent_pkts.saturating_sub(remote_pkts);
                }
            }
        }
    }
    finish(&stats);
}

fn udp_server(port: u16, stop: Arc<AtomicBool>, stats: Arc<Mutex<Inner>>) {
    let socket = match UdpSocket::bind(("0.0.0.0", port)) {
        Ok(socket) => socket,
        Err(err) => {
            fail(&stats, format!("无法监听 {port}: {err}"));
            return;
        }
    };
    let bound = socket.local_addr().map(|addr| addr.port()).unwrap_or(port);
    let _ = socket.set_read_timeout(Some(Duration::from_millis(200)));
    set_phase(&stats, &format!("监听 0.0.0.0:{bound}，等待一次 UDP 测试"));
    let mut buf = [0u8; 2048];
    while !stop.load(Ordering::Relaxed) {
        let (len, peer) = match socket.recv_from(&mut buf) {
            Ok(pair) => pair,
            Err(err) if paused(&err) => continue,
            Err(err) => {
                fail(&stats, format!("监听中断: {err}"));
                return;
            }
        };
        if len < 8 || buf[0..4] != *MAGIC || buf[4] != HELLO {
            continue;
        }
        let seconds = u16::from_be_bytes([buf[6], buf[7]]).clamp(1, 10);
        let mut ack = [0u8; 16];
        ack[0..4].copy_from_slice(MAGIC);
        ack[4] = ACK;
        if socket.send_to(&ack, peer).is_err() {
            continue;
        }
        set_phase(&stats, "测试中");
        let deadline = Instant::now() + Duration::from_secs(seconds as u64 + 1);
        let mut last_stats = Instant::now();
        while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
            match socket.recv_from(&mut buf) {
                Ok((n, from)) if n >= 12 && buf[0..4] == *MAGIC && buf[4] == DATA && from == peer => {
                    add_recv(&stats, n as u64, 1);
                }
                Ok(_) => {}
                Err(err) if paused(&err) => {}
                Err(_) => break,
            }
            if last_stats.elapsed() >= Duration::from_millis(100) {
                send_stats(&socket, peer, &stats);
                last_stats = Instant::now();
            }
        }
        send_stats(&socket, peer, &stats);
        note_listen(&stats);
    }
}

fn send_stats(socket: &UdpSocket, peer: SocketAddr, stats: &Mutex<Inner>) {
    let (bytes, pkts) = stats
        .lock()
        .map(|row| (row.recv, row.recv_pkts))
        .unwrap_or((0, 0));
    let mut packet = [0u8; 24];
    packet[0..4].copy_from_slice(MAGIC);
    packet[4] = STATS;
    packet[8..16].copy_from_slice(&bytes.to_be_bytes());
    packet[16..20].copy_from_slice(&(pkts as u32).to_be_bytes());
    let _ = socket.send_to(&packet, peer);
}

fn note_listen(stats: &Mutex<Inner>) {
    if let Ok(mut row) = stats.lock() {
        if row.error.is_empty() {
            row.phase = "完成，仍在监听".into();
        }
    }
}

fn finish(stats: &Mutex<Inner>) {
    if let Ok(mut row) = stats.lock() {
        if row.error.is_empty() {
            row.phase = "完成".into();
            row.running = false;
        }
    }
}

fn paused(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

fn write_all_stop(mut stream: &TcpStream, mut buf: &[u8], stop: &AtomicBool) -> io::Result<()> {
    let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));
    while !buf.is_empty() {
        if stop.load(Ordering::Relaxed) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "stopped"));
        }
        match stream.write(buf) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "closed")),
            Ok(n) => buf = &buf[n..],
            Err(err) if paused(&err) => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn read_exact_deadline(stream: &mut TcpStream, buf: &mut [u8], budget: Duration, stop: &AtomicBool) -> io::Result<()> {
    let deadline = Instant::now() + budget;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut got = 0;
    while got < buf.len() {
        if stop.load(Ordering::Relaxed) || Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "handshake"));
        }
        match stream.read(&mut buf[got..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed")),
            Ok(n) => got += n,
            Err(err) if paused(&err) => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_megabyte_per_second_is_about_eight_megabits() {
        let rate = megabits_per_sec(1_000_000, Duration::from_secs(1));
        assert!((rate - 8.0).abs() < 0.01, "{rate}");
        let mib = mebibytes_per_sec(1024 * 1024, Duration::from_secs(1));
        assert!((mib - 1.0).abs() < 0.01, "{mib}");
    }

    #[test]
    fn tcp_upload_needs_a_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 8];
            let _ = stream.read(&mut buf);
            thread::sleep(Duration::from_millis(300));
        });
        let mut client = Session::idle();
        client.start_client("127.0.0.1", port, Proto::Tcp, 1).unwrap();
        wait_until(&client, Duration::from_secs(4));
        let snap = client.snap();
        assert_eq!(snap.sent, 0, "{}", snap.phase);
        assert!(snap.phase.contains("没有确认") || snap.error.contains("没有确认"), "{}", snap.phase);
        let _ = accepted.join();
    }

    #[test]
    fn tcp_loopback_reports_received_bytes() {
        let mut server = Session::idle();
        server.start_server(0, Proto::Tcp).unwrap();
        let port = wait_port(&server, Proto::Tcp);
        let mut client = Session::idle();
        client.start_client("127.0.0.1", port, Proto::Tcp, 1).unwrap();
        wait_until(&client, Duration::from_secs(4));
        let sent = client.snap().sent;
        let recv = wait_recv(&server, Duration::from_secs(2));
        assert!(sent > 100_000, "sent {sent}");
        assert!(recv > 100_000, "recv {recv} phase {}", server.snap().phase);
        client.stop();
        server.stop();
    }

    #[test]
    fn udp_without_peer_sends_no_payload() {
        let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = sink.local_addr().unwrap().port();
        let mut client = Session::idle();
        client
            .start_client("127.0.0.1", port, Proto::Udp, 1)
            .unwrap();
        wait_until(&client, Duration::from_secs(4));
        let snap = client.snap();
        assert_eq!(snap.sent_pkts, 0, "{}", snap.phase);
        assert!(snap.phase.contains("没有确认"), "{}", snap.phase);
    }

    #[test]
    fn udp_loopback_counts_packets() {
        let mut server = Session::idle();
        server.start_server(0, Proto::Udp).unwrap();
        let port = wait_port(&server, Proto::Udp);
        let mut client = Session::idle();
        client.start_client("127.0.0.1", port, Proto::Udp, 1).unwrap();
        wait_until(&client, Duration::from_secs(4));
        thread::sleep(Duration::from_millis(200));
        let snap = client.snap();
        assert!(snap.sent_pkts > 0, "{}", snap.phase);
        assert!(snap.recv_pkts > 0, "remote {} phase {}", snap.recv_pkts, snap.phase);
        client.stop();
        server.stop();
    }

    fn wait_recv(session: &Session, budget: Duration) -> u64 {
        let deadline = Instant::now() + budget;
        let mut recv = 0;
        while Instant::now() < deadline {
            recv = session.snap().recv;
            if recv > 100_000 {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        recv
    }

    fn wait_until(session: &Session, budget: Duration) {
        let deadline = Instant::now() + budget;
        while Instant::now() < deadline && session.snap().running {
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_port(session: &Session, proto: Proto) -> u16 {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            let phase = session.snap().phase;
            if let Some(port) = phase.split(':').nth(1).and_then(|text| {
                text.chars()
                    .take_while(|ch| ch.is_ascii_digit())
                    .collect::<String>()
                    .parse()
                    .ok()
            }) {
                let _ = proto;
                return port;
            }
            if !session.snap().error.is_empty() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("server did not bind: {}", session.snap().phase);
    }
}
