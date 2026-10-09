use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::process::Command;

use crate::board::plain_line;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LogKind {
    Quick,
    Audit,
    Units,
    Kernel,
    System,
    Auth,
    Service,
    Cron,
}

impl LogKind {
    pub fn from_index(index: usize) -> Self {
        match index {
            1 => LogKind::Audit,
            2 => LogKind::Units,
            3 => LogKind::Kernel,
            4 => LogKind::System,
            5 => LogKind::Auth,
            6 => LogKind::Service,
            7 => LogKind::Cron,
            _ => LogKind::Quick,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            LogKind::Quick => "快捷操作",
            LogKind::Audit => "审计",
            LogKind::Units => "系统服务",
            LogKind::Kernel => "内核",
            LogKind::System => "系统",
            LogKind::Auth => "认证",
            LogKind::Service => "服务",
            LogKind::Cron => "定时任务",
        }
    }
}

pub struct LogView {
    pub source: String,
    pub lines: Vec<String>,
}

pub fn load(kind: LogKind) -> LogView {
    match kind {
        LogKind::Quick => load_quick(),
        LogKind::Audit => load_audit(),
        LogKind::Units => load_units(),
        _ => load_journal_kind(kind),
    }
}

pub fn load_unit(unit: &str) -> LogView {
    if !safe_unit(unit) {
        return LogView {
            source: "单元名不能交给 journalctl".into(),
            lines: vec!["这个名字里有不能用的字符".into()],
        };
    }
    if let Some(lines) = journal_args(&["-u", unit, "-n", "200"]) {
        return LogView {
            source: format!("journalctl -u {unit}"),
            lines,
        };
    }
    LogView {
        source: unit.into(),
        lines: vec![format!("{unit} 没有读到日志")],
    }
}

pub fn unit_name(line: &str) -> Option<String> {
    let name = line.split_whitespace().next()?;
    if safe_unit(name) {
        Some(name.to_string())
    } else {
        None
    }
}

pub fn demo(kind: LogKind) -> LogView {
    let lines = match kind {
        LogKind::Quick => vec![
            "失败的服务".into(),
            service_line("nginx.service", "failed", "failed", "演示站点"),
            "最近的错误".into(),
            "systemd  error  单元异常退出".into(),
            "审计拒绝".into(),
            "audit  avc denied  comm=nginx".into(),
        ],
        LogKind::Audit => vec!["type=AVC msg=audit(1.2:3): avc: denied { read } comm=\"nginx\"".into()],
        LogKind::Units => vec![
            service_line("nginx.service", "failed", "failed", "演示站点"),
            service_line("ssh.service", "active", "running", "安全外壳"),
        ],
        LogKind::Kernel => vec!["内核  eth0 链路就绪".into(), "内核  error 磁盘延迟升高".into()],
        LogKind::System => vec!["systemd  服务已启动".into(), "systemd  warning  单元重启了一次".into()],
        LogKind::Auth => vec!["sshd  接受了公钥登录".into(), "sudo  error  认证失败".into()],
        LogKind::Service => vec!["dockerd  容器运行时就绪".into()],
        LogKind::Cron => vec!["cron  每天的备份任务开始".into()],
    };
    LogView {
        source: format!("演示 {}", kind.label()),
        lines,
    }
}

pub fn demo_unit(unit: &str) -> LogView {
    LogView {
        source: format!("演示 {unit}"),
        lines: vec![format!("{unit}  演示日志  最近一次失败")],
    }
}

pub fn take_tail(text: &str, max: usize) -> Vec<String> {
    let lines: Vec<String> = text
        .lines()
        .map(plain_line)
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();
    if lines.len() <= max {
        lines
    } else {
        lines[lines.len() - max..].to_vec()
    }
}

fn load_quick() -> LogView {
    let mut lines = Vec::new();
    lines.push("失败的服务".into());
    let failed = failed_units();
    if failed.is_empty() {
        lines.push("没有失败的服务".into());
    } else {
        lines.extend(failed);
    }
    lines.push(String::new());
    lines.push("最近的错误".into());
    match journal_args(&["-p", "err", "-n", "40", "--system"]) {
        Some(rows) => lines.extend(rows),
        None => lines.push("没有错误日志".into()),
    }
    lines.push(String::new());
    lines.push("审计拒绝".into());
    let denied = audit_lines()
        .into_iter()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("denied") || lower.contains("res=failed")
        })
        .collect::<Vec<_>>();
    if denied.is_empty() {
        lines.push("没有审计拒绝".into());
    } else {
        lines.extend(denied.into_iter().rev().take(40).collect::<Vec<_>>().into_iter().rev());
    }
    LogView {
        source: "失败服务在前，接着是错误和审计拒绝".into(),
        lines,
    }
}

fn load_audit() -> LogView {
    let lines = audit_lines();
    if lines.is_empty() {
        LogView {
            source: "没有读到审计日志".into(),
            lines: vec!["auditd 和 /var/log/audit/audit.log 都没有内容".into()],
        }
    } else {
        LogView {
            source: "audit.log / journal 审计".into(),
            lines,
        }
    }
}

fn audit_lines() -> Vec<String> {
    if let Some(lines) = journal_args(&["_TRANSPORT=audit", "-n", "200"]) {
        return lines;
    }
    tail_file("/var/log/audit/audit.log", 200).unwrap_or_default()
}

fn load_units() -> LogView {
    let Some(text) = command_text(
        "systemctl",
        &[
            "list-units",
            "--type=service",
            "--all",
            "--no-legend",
            "--plain",
            "--no-pager",
        ],
    ) else {
        return LogView {
            source: "systemctl 不可用".into(),
            lines: vec!["没有读到 systemd 服务列表".into()],
        };
    };
    let mut rows = parse_units(&text);
    rows.sort_by(|left, right| {
        active_rank(&left.active)
            .cmp(&active_rank(&right.active))
            .then_with(|| left.unit.cmp(&right.unit))
    });
    if rows.is_empty() {
        return LogView {
            source: "systemctl list-units".into(),
            lines: vec!["没有服务".into()],
        };
    }
    LogView {
        source: "失败的排在前面。回车查看该服务的日志".into(),
        lines: rows
            .into_iter()
            .map(|row| service_line(&row.unit, &row.active, &row.sub, &row.description))
            .collect(),
    }
}

struct UnitRow {
    unit: String,
    active: String,
    sub: String,
    description: String,
}

fn parse_units(text: &str) -> Vec<UnitRow> {
    text.lines()
        .filter_map(|line| {
            let line = plain_line(line);
            let mut parts = line.split_whitespace();
            let unit = parts.next()?.to_string();
            if !unit.ends_with(".service") {
                return None;
            }
            let _load = parts.next()?;
            let active = parts.next()?.to_string();
            let sub = parts.next().unwrap_or("").to_string();
            let description = parts.collect::<Vec<_>>().join(" ");
            Some(UnitRow {
                unit,
                active,
                sub,
                description,
            })
        })
        .collect()
}

fn active_rank(active: &str) -> u8 {
    match active {
        "failed" => 0,
        "activating" | "deactivating" | "reloading" => 1,
        "active" => 2,
        _ => 3,
    }
}

fn service_line(unit: &str, active: &str, sub: &str, description: &str) -> String {
    let description: String = description.chars().take(80).collect();
    format!("{unit:<42} {active:<12} {sub:<14} {description}")
}

fn failed_units() -> Vec<String> {
    let Some(text) = command_text(
        "systemctl",
        &[
            "list-units",
            "--type=service",
            "--state=failed",
            "--no-legend",
            "--plain",
            "--no-pager",
        ],
    ) else {
        return Vec::new();
    };
    parse_units(&text)
        .into_iter()
        .take(30)
        .map(|row| service_line(&row.unit, &row.active, &row.sub, &row.description))
        .collect()
}

fn load_journal_kind(kind: LogKind) -> LogView {
    if let Some(view) = from_journal(kind) {
        return view;
    }
    for path in files(kind) {
        if let Some(lines) = tail_file(path, 400) {
            return LogView {
                source: (*path).to_string(),
                lines,
            };
        }
    }
    LogView {
        source: "没有可用的日志来源".into(),
        lines: vec!["journalctl 读不到，对应的 /var/log 文件也没有内容".into()],
    }
}

fn from_journal(kind: LogKind) -> Option<LogView> {
    let lines = match kind {
        LogKind::Kernel => journal_args(&["-k", "-n", "400"])?,
        LogKind::System => journal_args(&["--system", "-n", "400"])?,
        LogKind::Auth => journal_args(&["SYSLOG_FACILITY=4", "+", "SYSLOG_FACILITY=10", "-n", "400"])?,
        LogKind::Service => journal_args(&["SYSLOG_FACILITY=3", "-n", "400"])?,
        LogKind::Cron => journal_args(&[
            "SYSLOG_FACILITY=9",
            "+",
            "_SYSTEMD_UNIT=cron.service",
            "+",
            "_SYSTEMD_UNIT=crond.service",
            "-n",
            "200",
        ])?,
        _ => return None,
    };
    Some(LogView {
        source: format!("journalctl  {}", kind.label()),
        lines,
    })
}

fn journal_args(extra: &[&str]) -> Option<Vec<String>> {
    let mut args = vec!["--no-pager", "-o", "short-iso", "--quiet"];
    args.extend_from_slice(extra);
    let text = command_text("journalctl", &args)?;
    let lines = take_tail(&text, 400);
    if lines.is_empty() {
        None
    } else {
        Some(lines)
    }
}

fn files(kind: LogKind) -> &'static [&'static str] {
    match kind {
        LogKind::Kernel => &["/var/log/kern.log", "/var/log/dmesg"],
        LogKind::System => &["/var/log/syslog", "/var/log/messages"],
        LogKind::Auth => &["/var/log/auth.log", "/var/log/secure"],
        LogKind::Service => &["/var/log/daemon.log", "/var/log/syslog"],
        LogKind::Cron => &["/var/log/cron", "/var/log/cron.log"],
        LogKind::Audit => &["/var/log/audit/audit.log"],
        _ => &[],
    }
}

fn tail_file(path: &str, max_lines: usize) -> Option<Vec<String>> {
    let mut file = File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    if len == 0 {
        return None;
    }
    let take = len.min(512 * 1024);
    if len > take {
        file.seek(SeekFrom::Start(len - take)).ok()?;
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok()?;
    let buf = String::from_utf8_lossy(&bytes);
    let text = if len > take {
        buf.split_once('\n').map(|(_, rest)| rest).unwrap_or("")
    } else {
        buf.as_ref()
    };
    let lines = take_tail(text, max_lines);
    if lines.is_empty() {
        None
    } else {
        Some(lines)
    }
}

fn command_text(bin: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(bin)
        .args(args)
        .env("TERM", "dumb")
        .env("SYSTEMD_COLORS", "0")
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

pub fn safe_unit(name: &str) -> bool {
    name.ends_with(".service")
        && (1..128).contains(&name.len())
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '@' | ':' | '\\'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_keeps_the_newest_lines() {
        let text = "one\ntwo\nthree\n";
        assert_eq!(take_tail(text, 2), vec!["two".to_string(), "three".to_string()]);
    }

    #[test]
    fn shortcuts_come_before_kernel() {
        assert_eq!(LogKind::from_index(0).label(), "快捷操作");
        assert_eq!(LogKind::from_index(1).label(), "审计");
        assert_eq!(LogKind::from_index(2).label(), "系统服务");
        assert_eq!(LogKind::from_index(3).label(), "内核");
    }

    #[test]
    fn failed_services_sort_ahead_of_running_ones() {
        let rows = parse_units("ssh.service loaded active running OpenSSH\nnginx.service loaded failed failed site\n");
        let mut rows = rows;
        rows.sort_by(|left, right| active_rank(&left.active).cmp(&active_rank(&right.active)));
        assert_eq!(rows[0].unit, "nginx.service");
        assert!(unit_name(&service_line("nginx.service", "failed", "failed", "site")).is_some());
        assert!(unit_name("失败的服务").is_none());
        assert!(!safe_unit("nginx.service;rm"));
    }
}
