use std::fs;
use std::io::{self, IsTerminal};
use std::path::Path;

use serde::Serialize;

use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Fail,
    Manual,
    Unreadable,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Pass => "通过",
            Verdict::Fail => "不符合",
            Verdict::Manual => "需人工",
            Verdict::Unreadable => "读不到",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckItem {
    pub domain: String,
    pub title: String,
    pub verdict: Verdict,
    pub evidence: String,
    pub suggestion: String,
}

#[derive(Debug, Clone)]
pub struct BaselineInput {
    pub passwd: String,
    pub shadow: Option<String>,
    pub login_defs: String,
    pub profile: String,
    pub sshd_config: String,
    pub pam_password: String,
    pub pam_auth: String,
    pub faillock: String,
    pub sysctl: Vec<(String, String)>,
    pub listening_ports: Vec<u16>,
    pub auditd_running: bool,
    pub audit_rules: String,
    pub journal_persistent: bool,
    pub syslog_running: bool,
    pub mac: String,
    pub malware: Vec<String>,
    pub ima: bool,
    pub modes: Vec<(String, Option<u32>)>,
    pub firewall: String,
    pub sudoers: Option<String>,
}

const DOMAINS: &[&str] = &[
    "身份鉴别",
    "访问控制",
    "安全审计",
    "入侵防范",
    "恶意代码防范",
    "可信验证",
    "数据备份与剩余信息",
];

pub fn evaluate(input: &BaselineInput) -> Vec<CheckItem> {
    let mut items = Vec::new();
    items.extend(identity(input));
    items.extend(access(input));
    items.extend(audit(input));
    items.extend(intrusion(input));
    items.extend(malware(input));
    items.extend(trust(input));
    items.extend(backup());
    items
}

pub fn format_report(items: &[CheckItem], host: &str, color: bool) -> String {
    let mut pass = 0;
    let mut fail = 0;
    let mut manual = 0;
    let mut unread = 0;
    for item in items {
        match item.verdict {
            Verdict::Pass => pass += 1,
            Verdict::Fail => fail += 1,
            Verdict::Manual => manual += 1,
            Verdict::Unreadable => unread += 1,
        }
    }
    let widths = table_widths();
    let mut lines = vec![
        "linperf  等保三级安全基线".into(),
        format!("主机    {host}"),
        "标准    GB/T 22239-2019 安全计算环境。下表只列本机可自动核对的控制点，通过不等于测评结论。".into(),
        String::new(),
        summary_table(pass, fail, manual, unread, color),
    ];
    for domain in DOMAINS {
        let rows: Vec<_> = items.iter().filter(|item| item.domain == *domain).collect();
        if rows.is_empty() {
            continue;
        }
        lines.push(String::new());
        lines.push(dye(color, 1, domain));
        lines.push(render_domain_table(&rows, &widths, color));
    }
    lines.join("\n")
}

fn table_widths() -> [usize; 4] {
    let detected = if std::io::stdout().is_terminal() {
        crossterm::terminal::size()
            .map(|(width, _)| width as usize)
            .unwrap_or(108)
    } else {
        108
    };
    let total = detected.clamp(88, 140);
    let content = total.saturating_sub(13);
    let result = 6;
    let title = 20;
    let rest = content.saturating_sub(result + title).max(36);
    let evidence = rest / 2;
    let suggestion = rest - evidence;
    [result, title, evidence.max(18), suggestion.max(18)]
}

fn summary_table(pass: usize, fail: usize, manual: usize, unread: usize, color: bool) -> String {
    let labels = ["通过", "不符合", "需人工", "读不到"];
    let colors = [32u8, 31, 33, 90];
    let values = [pass, fail, manual, unread];
    let width = 8usize;
    let top = hline('┌', '┬', '┐', &[width; 4]);
    let mid = hline('├', '┼', '┤', &[width; 4]);
    let bot = hline('└', '┴', '┘', &[width; 4]);
    let head = row_line(
        &labels
            .iter()
            .enumerate()
            .map(|(index, label)| colored_cell(label, width, color, colors[index]))
            .collect::<Vec<_>>(),
    );
    let body = row_line(
        &values
            .iter()
            .map(|value| pad_cell(&value.to_string(), width))
            .collect::<Vec<_>>(),
    );
    [top, head, mid, body, bot].join("\n")
}

fn render_domain_table(items: &[&CheckItem], widths: &[usize; 4], color: bool) -> String {
    let header = ["结果", "检查项", "现状", "建议"];
    let mut lines = vec![
        hline('┌', '┬', '┐', widths),
        row_line(
            &header
                .iter()
                .enumerate()
                .map(|(index, label)| pad_cell(label, widths[index]))
                .collect::<Vec<_>>(),
        ),
        hline('├', '┼', '┤', widths),
    ];
    for (nth, item) in items.iter().enumerate() {
        if nth > 0 {
            lines.push(hline('├', '┼', '┤', widths));
        }
        let suggestion = if item.suggestion.is_empty() {
            "—"
        } else {
            item.suggestion.as_str()
        };
        let title_lines = wrap_cols(&item.title, widths[1]);
        let evidence_lines = wrap_cols(&item.evidence, widths[2]);
        let suggestion_lines = wrap_cols(suggestion, widths[3]);
        let height = title_lines
            .len()
            .max(evidence_lines.len())
            .max(suggestion_lines.len());
        for line in 0..height {
            let result = if line == 0 {
                colored_cell(item.verdict.label(), widths[0], color, verdict_color(item.verdict))
            } else {
                pad_cell("", widths[0])
            };
            let title = title_lines.get(line).map(String::as_str).unwrap_or("");
            let evidence = evidence_lines.get(line).map(String::as_str).unwrap_or("");
            let advice = suggestion_lines.get(line).map(String::as_str).unwrap_or("");
            lines.push(row_line(&[
                result,
                pad_cell(title, widths[1]),
                pad_cell(evidence, widths[2]),
                pad_cell(advice, widths[3]),
            ]));
        }
    }
    lines.push(hline('└', '┴', '┘', widths));
    lines.join("\n")
}

fn hline(left: char, mid: char, right: char, widths: &[usize]) -> String {
    let mut line = String::new();
    line.push(left);
    for (index, width) in widths.iter().enumerate() {
        line.push_str(&"─".repeat(width + 2));
        line.push(if index + 1 == widths.len() { right } else { mid });
    }
    line
}

fn row_line(cells: &[String]) -> String {
    let mut line = String::from("│");
    for cell in cells {
        line.push(' ');
        line.push_str(cell);
        line.push(' ');
        line.push('│');
    }
    line
}

fn colored_cell(text: &str, width: usize, color: bool, code: u8) -> String {
    let gap = " ".repeat(width.saturating_sub(columns(text)));
    format!("{}{gap}", dye(color, code, text))
}

fn pad_cell(text: &str, width: usize) -> String {
    let gap = " ".repeat(width.saturating_sub(columns(text)));
    format!("{text}{gap}")
}

fn wrap_cols(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut used = 0usize;
    for token in tokenize(text) {
        let token_width = columns(&token).max(1);
        let blank = token.chars().all(char::is_whitespace);
        if used > 0 && used + token_width > width {
            lines.push(std::mem::take(&mut current));
            used = 0;
            if blank {
                continue;
            }
        }
        if blank && current.is_empty() {
            continue;
        }
        if token_width > width && current.is_empty() {
            for ch in token.chars() {
                let ch_width = columns(&ch.to_string()).max(1);
                if used > 0 && used + ch_width > width {
                    lines.push(std::mem::take(&mut current));
                    used = 0;
                }
                current.push(ch);
                used += ch_width;
            }
            continue;
        }
        current.push_str(&token);
        used += token_width;
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

fn tokenize(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut buf = String::new();
    let mut spaces = None;
    for ch in text.chars() {
        if columns(&ch.to_string()) == 2 {
            if !buf.is_empty() {
                tokens.push(std::mem::take(&mut buf));
                spaces = None;
            }
            tokens.push(ch.to_string());
            continue;
        }
        let is_space = ch.is_whitespace();
        match spaces {
            Some(prev) if prev == is_space => buf.push(ch),
            Some(_) => {
                tokens.push(std::mem::take(&mut buf));
                buf.push(ch);
                spaces = Some(is_space);
            }
            None => {
                buf.push(ch);
                spaces = Some(is_space);
            }
        }
    }
    if !buf.is_empty() {
        tokens.push(buf);
    }
    tokens
}

pub fn collect() -> Result<BaselineInput> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = ();
        return Err(crate::error::Error::NotLinux);
    }
    #[cfg(target_os = "linux")]
    {
        Ok(collect_linux())
    }
}

#[cfg(target_os = "linux")]
fn collect_linux() -> BaselineInput {
    let tcp = fs::read_to_string("/proc/net/tcp").unwrap_or_default();
    let tcp6 = fs::read_to_string("/proc/net/tcp6").unwrap_or_default();
    let mut ports = listening_ports(&tcp);
    ports.extend(listening_ports(&tcp6));
    ports.sort_unstable();
    ports.dedup();
    let audit_rules = [
        "/etc/audit/audit.rules",
        "/etc/audit/rules.d/audit.rules",
    ]
    .iter()
    .filter_map(|path| fs::read_to_string(path).ok())
    .chain(read_dir_files("/etc/audit/rules.d"))
    .collect::<Vec<_>>()
    .join("\n");
    BaselineInput {
        passwd: read_text("/etc/passwd"),
        shadow: fs::read_to_string("/etc/shadow").ok(),
        login_defs: read_text("/etc/login.defs"),
        profile: [read_text("/etc/profile"), read_text("/etc/bash.bashrc")].join("\n"),
        sshd_config: read_text("/etc/ssh/sshd_config"),
        pam_password: first_text(&[
            "/etc/pam.d/common-password",
            "/etc/pam.d/system-auth",
            "/etc/pam.d/password-auth",
        ]),
        pam_auth: first_text(&[
            "/etc/pam.d/common-auth",
            "/etc/pam.d/system-auth",
            "/etc/pam.d/password-auth",
        ]),
        faillock: read_text("/etc/security/faillock.conf"),
        sysctl: SYSCTLS
            .iter()
            .filter_map(|key| {
                let path = format!("/proc/sys/{}", key.replace('.', "/"));
                fs::read_to_string(path).ok().map(|value| ((*key).to_string(), value.trim().to_string()))
            })
            .collect(),
        listening_ports: ports,
        auditd_running: comm_running("auditd"),
        audit_rules,
        journal_persistent: Path::new("/var/log/journal").is_dir(),
        syslog_running: comm_running("rsyslogd") || comm_running("syslog-ng"),
        mac: detect_mac(),
        malware: malware_paths(),
        ima: Path::new("/sys/kernel/security/ima").exists(),
        modes: [" /etc/passwd", "/etc/shadow", "/etc/group", "/etc/ssh/sshd_config"]
            .iter()
            .map(|path| {
                let path = path.trim();
                (path.to_string(), file_mode(path))
            })
            .collect(),
        firewall: detect_firewall(),
        sudoers: fs::read_to_string("/etc/sudoers").ok(),
    }
}

const SYSCTLS: &[&str] = &[
    "net.ipv4.tcp_syncookies",
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.all.send_redirects",
    "net.ipv4.conf.all.accept_source_route",
    "net.ipv4.conf.all.rp_filter",
    "net.ipv4.ip_forward",
    "kernel.randomize_va_space",
    "kernel.kptr_restrict",
    "kernel.dmesg_restrict",
    "fs.suid_dumpable",
    "kernel.yama.ptrace_scope",
];

fn identity(input: &BaselineInput) -> Vec<CheckItem> {
    let mut items = Vec::new();
    items.push(unique_uid(input));
    items.push(empty_password(input));
    items.push(password_age(input));
    items.push(password_complexity(input));
    items.push(login_lockout(input));
    items.push(session_timeout(input));
    items.push(ssh_root(input));
    items.push(ssh_encrypted(input));
    items.push(two_factor(input));
    items
}

fn access(input: &BaselineInput) -> Vec<CheckItem> {
    vec![
        file_perm(input, "/etc/passwd", 0o644, "口令文件对其他用户只读"),
        file_perm(input, "/etc/shadow", 0o640, "影子口令不对其他用户开放"),
        file_perm(input, "/etc/group", 0o644, "组文件对其他用户只读"),
        file_perm(input, "/etc/ssh/sshd_config", 0o600, "SSH 配置不对其他用户开放"),
        umask_item(input),
        system_shells(input),
        sudo_item(input),
    ]
}

fn audit(input: &BaselineInput) -> Vec<CheckItem> {
    let running = if input.auditd_running {
        item("安全审计", "审计进程在运行", Verdict::Pass, "auditd 正在运行", "")
    } else {
        item(
            "安全审计",
            "审计进程在运行",
            Verdict::Fail,
            "没有看到 auditd",
            "安装并启用 auditd，防止审计进程被随意停掉。",
        )
    };
    let rules = if input.audit_rules.lines().any(|line| {
        let line = line.trim();
        !line.is_empty() && !line.starts_with('#') && (line.contains("-w") || line.contains("-a"))
    }) {
        item("安全审计", "审计覆盖重要事件", Verdict::Pass, "审计规则里有文件监视或 syscall 规则", "")
    } else if input.audit_rules.trim().is_empty() {
        item(
            "安全审计",
            "审计覆盖重要事件",
            Verdict::Fail,
            "没有读到有效的 audit 规则",
            "至少监视 /etc/passwd、/etc/shadow、sudoers 和登录相关 syscall。",
        )
    } else {
        item(
            "安全审计",
            "审计覆盖重要事件",
            Verdict::Fail,
            "规则文件存在，但没有 -w 或 -a",
            "加上对账户、权限和登录事件的监视规则。",
        )
    };
    let log = if input.journal_persistent || input.syslog_running {
        item(
            "安全审计",
            "日志守护进程",
            Verdict::Pass,
            if input.journal_persistent {
                "journald 使用持久目录 /var/log/journal".to_string()
            } else {
                "syslog 进程在运行".to_string()
            },
            "",
        )
    } else {
        item(
            "安全审计",
            "日志守护进程",
            Verdict::Fail,
            "没有持久 journal，也没有看到 rsyslog/syslog-ng",
            "打开 journald 持久化或启用 rsyslog，并限制日志目录权限。",
        )
    };
    let protect = item(
        "安全审计",
        "审计记录防篡改",
        Verdict::Manual,
        "自动检查只能确认进程和规则，不能证明日志已备份且不可被管理员删除",
        "把审计日志转到独立主机，并保留备份和访问记录。",
    );
    vec![running, rules, log, protect]
}

fn intrusion(input: &BaselineInput) -> Vec<CheckItem> {
    let mut items = vec![
        ports_item(input),
        firewall_item(input),
        mac_item(input),
        sysctl_eq(input, "net.ipv4.tcp_syncookies", "1", "SYN Cookie", "打开 tcp_syncookies，减轻 SYN 洪水。"),
        sysctl_eq(input, "net.ipv4.conf.all.accept_redirects", "0", "拒绝 ICMP 重定向", "accept_redirects 设为 0。"),
        sysctl_eq(input, "net.ipv4.conf.all.send_redirects", "0", "不发送 ICMP 重定向", "send_redirects 设为 0。"),
        sysctl_eq(input, "net.ipv4.conf.all.accept_source_route", "0", "拒绝源路由", "accept_source_route 设为 0。"),
        sysctl_one_of(input, "net.ipv4.conf.all.rp_filter", &["1", "2"], "反向路径过滤", "rp_filter 设为 1 或 2。"),
        sysctl_eq(input, "kernel.randomize_va_space", "2", "地址空间随机化", "randomize_va_space 设为 2。"),
        sysctl_at_least(input, "kernel.kptr_restrict", 1, "隐藏内核指针", "kptr_restrict 至少为 1。"),
        sysctl_eq(input, "kernel.dmesg_restrict", "1", "限制 dmesg", "dmesg_restrict 设为 1。"),
        sysctl_eq(input, "fs.suid_dumpable", "0", "禁止 SUID 转储", "suid_dumpable 设为 0。"),
        sysctl_at_least(input, "kernel.yama.ptrace_scope", 1, "限制 ptrace", "ptrace_scope 至少为 1，避免任意进程互相调试。"),
        forward_item(input),
    ];
    items.push(item(
        "入侵防范",
        "已知漏洞修补",
        Verdict::Manual,
        "本机没有漏洞库，不能判断补丁是否过期",
        "对照发行版安全通告核对内核和 OpenSSH 版本，保留修补记录。",
    ));
    items
}

fn malware(input: &BaselineInput) -> Vec<CheckItem> {
    if input.malware.is_empty() {
        vec![item(
            "恶意代码防范",
            "防恶意代码软件",
            Verdict::Fail,
            "没有发现 clamd、clamscan 或其他常见扫描器",
            "部署防恶意代码软件并保持特征库更新。只装包、不更新，不算满足。",
        )]
    } else {
        vec![item(
            "恶意代码防范",
            "防恶意代码软件",
            Verdict::Pass,
            format!("发现 {}", input.malware.join("，")),
            "",
        )]
    }
}

fn trust(input: &BaselineInput) -> Vec<CheckItem> {
    if input.ima {
        vec![item(
            "可信验证",
            "启动链或 IMA",
            Verdict::Manual,
            "存在 /sys/kernel/security/ima。策略是否覆盖引导程序和重要配置，需要人工看策略",
            "核对 IMA 策略是否度量引导组件、内核模块和重要配置。",
        )]
    } else {
        vec![item(
            "可信验证",
            "启动链或 IMA",
            Verdict::Fail,
            "没有发现 IMA",
            "三级要求基于可信根做验证。启用 IMA/TPM，或记录等价的可信启动措施。",
        )]
    }
}

fn backup() -> Vec<CheckItem> {
    vec![
        item(
            "数据备份与剩余信息",
            "备份与恢复",
            Verdict::Manual,
            "本地文件看不出备份频率、异地副本和恢复演练",
            "保留备份范围、周期、离线副本和最近一次恢复记录。",
        ),
        item(
            "数据备份与剩余信息",
            "剩余信息保护",
            Verdict::Manual,
            "看不出换页、删除文件和磁盘报废时是否清除数据",
            "明确内存、交换区和退役磁盘的清除方式。",
        ),
    ]
}

fn unique_uid(input: &BaselineInput) -> CheckItem {
    if input.passwd.trim().is_empty() {
        return item("身份鉴别", "身份标识唯一", Verdict::Unreadable, "读不到 /etc/passwd", "用有权限的账户重新检查。");
    }
    let mut seen: std::collections::HashMap<u32, Vec<String>> = std::collections::HashMap::new();
    for line in input.passwd.lines() {
        let mut parts = line.split(':');
        let name = parts.next().unwrap_or("").to_string();
        let uid: u32 = match parts.nth(1).and_then(|text| text.parse().ok()) {
            Some(uid) => uid,
            None => continue,
        };
        seen.entry(uid).or_default().push(name);
    }
    let dup: Vec<_> = seen.into_iter().filter(|(_, names)| names.len() > 1).collect();
    if dup.is_empty() {
        item("身份鉴别", "身份标识唯一", Verdict::Pass, "没有重复 UID，UID 0 只有一个账户", "")
    } else {
        let text = dup
            .iter()
            .map(|(uid, names)| format!("UID {uid}: {}", names.join(",")))
            .collect::<Vec<_>>()
            .join("；");
        item("身份鉴别", "身份标识唯一", Verdict::Fail, text, "拆开共享 UID，保证 UID 0 只有 root。")
    }
}

fn empty_password(input: &BaselineInput) -> CheckItem {
    let Some(shadow) = input.shadow.as_deref() else {
        return item("身份鉴别", "不存在空口令", Verdict::Unreadable, "读不到 /etc/shadow", "用 root 重新检查空口令。");
    };
    let mut empty = Vec::new();
    for line in shadow.lines() {
        let mut parts = line.split(':');
        let name = parts.next().unwrap_or("");
        let hash = parts.next().unwrap_or("");
        if name.is_empty() {
            continue;
        }
        if hash.is_empty() {
            empty.push(name.to_string());
        }
    }
    if empty.is_empty() {
        item("身份鉴别", "不存在空口令", Verdict::Pass, "影子文件里没有空口令字段", "")
    } else {
        item(
            "身份鉴别",
            "不存在空口令",
            Verdict::Fail,
            format!("空口令: {}", empty.join(",")),
            "给这些账户设置口令或锁定。",
        )
    }
}

fn password_age(input: &BaselineInput) -> CheckItem {
    let max_days = defs_int(&input.login_defs, "PASS_MAX_DAYS");
    let min_days = defs_int(&input.login_defs, "PASS_MIN_DAYS");
    let warn = defs_int(&input.login_defs, "PASS_WARN_AGE");
    match (max_days, min_days, warn) {
        (Some(max), Some(min), Some(warn)) if max > 0 && max <= 90 && min >= 1 && warn >= 7 => item(
            "身份鉴别",
            "口令定期更换",
            Verdict::Pass,
            format!("PASS_MAX_DAYS={max} PASS_MIN_DAYS={min} PASS_WARN_AGE={warn}"),
            "",
        ),
        (max, min, warn) => item(
            "身份鉴别",
            "口令定期更换",
            Verdict::Fail,
            format!(
                "PASS_MAX_DAYS={} PASS_MIN_DAYS={} PASS_WARN_AGE={}",
                show_opt(max),
                show_opt(min),
                show_opt(warn)
            ),
            "设为最长 90 天、最短至少 1 天、到期前提醒至少 7 天。",
        ),
    }
}

fn password_complexity(input: &BaselineInput) -> CheckItem {
    let pam = input.pam_password.to_ascii_lowercase();
    let minlen = defs_int(&input.login_defs, "PASS_MIN_LEN");
    let has_module = pam.contains("pam_pwquality") || pam.contains("pam_cracklib") || pam.contains("pam_passwdqc");
    if has_module && minlen.is_some_and(|len| len >= 8) {
        item("身份鉴别", "口令复杂度", Verdict::Pass, "PAM 有口令强度模块，PASS_MIN_LEN 不少于 8", "")
    } else if has_module {
        item(
            "身份鉴别",
            "口令复杂度",
            Verdict::Fail,
            format!("有强度模块，PASS_MIN_LEN={minlen:?}"),
            "PASS_MIN_LEN 至少 8，并在 PAM 里要求字符类别。",
        )
    } else {
        item(
            "身份鉴别",
            "口令复杂度",
            Verdict::Fail,
            "PAM 口令栈里没有 pam_pwquality、pam_cracklib 或 pam_passwdqc",
            "启用口令强度模块，最短长度至少 8。",
        )
    }
}

fn login_lockout(input: &BaselineInput) -> CheckItem {
    let deny = faillock_deny(input);
    match deny {
        Some(deny) if deny > 0 && deny <= 5 => item(
            "身份鉴别",
            "登录失败处理",
            Verdict::Pass,
            format!("失败锁定阈值 {deny}"),
            "",
        ),
        Some(deny) => item(
            "身份鉴别",
            "登录失败处理",
            Verdict::Fail,
            format!("失败锁定阈值 {deny}"),
            "连续失败不超过 5 次就锁定，并设置解锁时间。",
        ),
        None => item(
            "身份鉴别",
            "登录失败处理",
            Verdict::Fail,
            "没有看到 pam_faillock、pam_tally2 或 faillock.conf 的 deny",
            "启用登录失败锁定。",
        ),
    }
}

fn session_timeout(input: &BaselineInput) -> CheckItem {
    let interval = sshd_int(&input.sshd_config, "ClientAliveInterval").unwrap_or(0);
    let count = sshd_int(&input.sshd_config, "ClientAliveCountMax").unwrap_or(3);
    let ssh_ok = interval > 0 && interval.saturating_mul(count) <= 600;
    let tmout = profile_tmout(&input.profile);
    let shell_ok = tmout.is_some_and(|value| value > 0 && value <= 600);
    if ssh_ok || shell_ok {
        item(
            "身份鉴别",
            "空闲超时退出",
            Verdict::Pass,
            format!("ClientAliveInterval={interval} ClientAliveCountMax={count} TMOUT={}", show_opt(tmout.map(|value| value as i64))),
            "",
        )
    } else {
        item(
            "身份鉴别",
            "空闲超时退出",
            Verdict::Fail,
            format!("ClientAliveInterval={interval} TMOUT={}", show_opt(tmout.map(|value| value as i64))),
            "SSH 空闲断开不超过 10 分钟，或在 /etc/profile 设置 TMOUT。",
        )
    }
}

fn ssh_root(input: &BaselineInput) -> CheckItem {
    if input.sshd_config.trim().is_empty() {
        return item("身份鉴别", "禁止 root 远程登录", Verdict::Unreadable, "读不到 sshd_config", "检查 SSH 配置是否另有路径。");
    }
    match sshd_value(&input.sshd_config, "PermitRootLogin").as_deref() {
        Some("no") => item("身份鉴别", "禁止 root 远程登录", Verdict::Pass, "PermitRootLogin no", ""),
        Some(other) => item(
            "身份鉴别",
            "禁止 root 远程登录",
            Verdict::Fail,
            format!("PermitRootLogin {other}"),
            "设为 no。prohibit-password 仍允许 root 公钥登录。",
        ),
        None => item(
            "身份鉴别",
            "禁止 root 远程登录",
            Verdict::Fail,
            "未配置 PermitRootLogin，OpenSSH 默认仍可能允许 root 公钥",
            "显式设为 no。",
        ),
    }
}

fn ssh_encrypted(input: &BaselineInput) -> CheckItem {
    let risky: Vec<_> = input
        .listening_ports
        .iter()
        .copied()
        .filter(|port| HIGH_RISK_PORTS.contains(port))
        .collect();
    let empty = sshd_value(&input.sshd_config, "PermitEmptyPasswords").unwrap_or_else(|| "no".into());
    if risky.is_empty() && empty == "no" {
        item(
            "身份鉴别",
            "远程管理加密传输",
            Verdict::Pass,
            "没有 telnet/rsh 等高危监听，PermitEmptyPasswords 不是 yes",
            "",
        )
    } else {
        item(
            "身份鉴别",
            "远程管理加密传输",
            Verdict::Fail,
            format!("高危端口 {risky:?}，PermitEmptyPasswords={empty}"),
            "关闭 telnet、rsh、ftp，远程管理只走 SSH，并禁止空口令。",
        )
    }
}

fn two_factor(input: &BaselineInput) -> CheckItem {
    let pam = format!("{}\n{}", input.pam_auth, input.pam_password).to_ascii_lowercase();
    let marks = ["pam_google_authenticator", "pam_oath", "pam_yk", "pam_u2f", "pam_pkcs11"];
    if marks.iter().any(|mark| pam.contains(mark)) {
        item("身份鉴别", "两种以上鉴别", Verdict::Pass, "PAM 中有第二种鉴别模块", "")
    } else {
        item(
            "身份鉴别",
            "两种以上鉴别",
            Verdict::Fail,
            "没有看到令牌、证书或一次性口令模块",
            "在 SSH 或登录 PAM 上增加公钥之外的第二种鉴别，其中一种使用密码技术。",
        )
    }
}

fn file_perm(input: &BaselineInput, path: &str, max_mode: u32, title: &str) -> CheckItem {
    let mode = match input.modes.iter().find(|(name, _)| name == path) {
        Some((_, Some(mode))) => *mode & 0o777,
        _ => {
            return item(
                "访问控制",
                title,
                Verdict::Unreadable,
                format!("没有 {path}"),
                "确认文件存在且权限可检查。",
            );
        }
    };
    let world = mode & 0o007;
    let ok = if path == "/etc/shadow" || path == "/etc/ssh/sshd_config" {
        mode <= max_mode && world == 0
    } else {
        mode <= max_mode
    };
    if ok {
        item("访问控制", title, Verdict::Pass, format!("{path} {mode:o}"), "")
    } else {
        item(
            "访问控制",
            title,
            Verdict::Fail,
            format!("{path} {mode:o}"),
            format!("权限收紧到 {max_mode:o} 或更严。"),
        )
    }
}

fn umask_item(input: &BaselineInput) -> CheckItem {
    let value = umask_value(&input.profile).or_else(|| defs_int(&input.login_defs, "UMASK"));
    match value {
        Some(mask) if mask >= 0o027 => item("访问控制", "默认 umask", Verdict::Pass, format!("umask {mask:03o}"), ""),
        Some(mask) => item(
            "访问控制",
            "默认 umask",
            Verdict::Fail,
            format!("umask {mask:03o}"),
            "把登录默认 umask 设为 027，避免新建文件对同组以外的用户可读。",
        ),
        None => item("访问控制", "默认 umask", Verdict::Manual, "没有在 profile 或 login.defs 里找到 umask", "在 /etc/profile 设置 umask 027。"),
    }
}

fn system_shells(input: &BaselineInput) -> CheckItem {
    let mut bad = Vec::new();
    for line in input.passwd.lines() {
        let parts: Vec<_> = line.split(':').collect();
        if parts.len() < 7 {
            continue;
        }
        let uid: u32 = parts[2].parse().unwrap_or(u32::MAX);
        if uid == 0 || uid >= 1000 {
            continue;
        }
        let shell = parts[6];
        if interactive_shell(shell) {
            bad.push(format!("{}({shell})", parts[0]));
        }
    }
    if bad.is_empty() {
        item("访问控制", "系统账户不可登录", Verdict::Pass, "UID 1–999 没有交互式 shell", "")
    } else {
        item(
            "访问控制",
            "系统账户不可登录",
            Verdict::Fail,
            bad.join(" "),
            "把这些系统账户的 shell 改成 nologin。",
        )
    }
}

fn sudo_item(input: &BaselineInput) -> CheckItem {
    let Some(text) = input.sudoers.as_deref() else {
        return item("访问控制", "sudo 最小权限", Verdict::Unreadable, "读不到 /etc/sudoers", "用 root 检查是否存在 NOPASSWD: ALL。");
    };
    let loose: Vec<_> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| {
            let upper = line.to_ascii_uppercase();
            upper.contains("NOPASSWD") && upper.contains("ALL") && !line.starts_with("root") && !line.starts_with("%root")
        })
        .take(3)
        .collect();
    if loose.is_empty() {
        item("访问控制", "sudo 最小权限", Verdict::Pass, "sudoers 里没有看到非 root 的 NOPASSWD ALL", "")
    } else {
        item(
            "访问控制",
            "sudo 最小权限",
            Verdict::Fail,
            loose.join(" | "),
            "去掉免密的全部权限，按命令授权。",
        )
    }
}

fn ports_item(input: &BaselineInput) -> CheckItem {
    let risky: Vec<_> = input
        .listening_ports
        .iter()
        .copied()
        .filter(|port| HIGH_RISK_PORTS.contains(port))
        .collect();
    if risky.is_empty() {
        item("入侵防范", "关闭高危端口", Verdict::Pass, "没有监听 21/23/69/512/513/514 等端口", "")
    } else {
        item(
            "入侵防范",
            "关闭高危端口",
            Verdict::Fail,
            format!("正在监听 {risky:?}"),
            "关闭 telnet、ftp、rsh、tftp 等服务，只保留业务需要的端口。",
        )
    }
}

fn firewall_item(input: &BaselineInput) -> CheckItem {
    if input.firewall == "none" {
        item(
            "入侵防范",
            "主机防火墙",
            Verdict::Fail,
            "没有发现 ufw、firewalld、nftables 或 iptables 规则文件",
            "启用主机防火墙，默认拒绝，只放行管理地址和业务端口。",
        )
    } else {
        item("入侵防范", "主机防火墙", Verdict::Pass, format!("发现 {}", input.firewall), "")
    }
}

fn mac_item(input: &BaselineInput) -> CheckItem {
    match input.mac.as_str() {
        "selinux-enforcing" => item("入侵防范", "强制访问控制", Verdict::Pass, "SELinux 处于 enforcing", ""),
        "apparmor-enforce" => item("入侵防范", "强制访问控制", Verdict::Pass, "AppArmor 有 enforce 配置", ""),
        "apparmor-complain" => item(
            "入侵防范",
            "强制访问控制",
            Verdict::Fail,
            "AppArmor 只有 complain，没有 enforce",
            "把重要服务的配置改为 enforce。",
        ),
        _ => item(
            "入侵防范",
            "强制访问控制",
            Verdict::Fail,
            "没有 SELinux enforcing，也没有 AppArmor enforce",
            "启用 SELinux 或 AppArmor，满足主体和客体的强制访问控制。",
        ),
    }
}

fn forward_item(input: &BaselineInput) -> CheckItem {
    match sysctl(input, "net.ipv4.ip_forward").as_deref() {
        Some("0") => item("入侵防范", "关闭 IP 转发", Verdict::Pass, "net.ipv4.ip_forward=0", ""),
        Some(other) => item(
            "入侵防范",
            "关闭 IP 转发",
            Verdict::Fail,
            format!("net.ipv4.ip_forward={other}"),
            "不是路由器或容器宿主机就设为 0。如果必须开启，保留变更说明。",
        ),
        None => item("入侵防范", "关闭 IP 转发", Verdict::Unreadable, "读不到 ip_forward", "检查 /proc/sys 是否挂载。"),
    }
}

fn sysctl_eq(input: &BaselineInput, key: &str, expect: &str, title: &str, suggestion: &str) -> CheckItem {
    match sysctl(input, key) {
        Some(value) if value == expect => item("入侵防范", title, Verdict::Pass, format!("{key}={value}"), ""),
        Some(value) => item("入侵防范", title, Verdict::Fail, format!("{key}={value}"), suggestion),
        None => item("入侵防范", title, Verdict::Unreadable, format!("读不到 {key}"), suggestion),
    }
}

fn sysctl_one_of(input: &BaselineInput, key: &str, expect: &[&str], title: &str, suggestion: &str) -> CheckItem {
    match sysctl(input, key) {
        Some(value) if expect.contains(&value.as_str()) => item("入侵防范", title, Verdict::Pass, format!("{key}={value}"), ""),
        Some(value) => item("入侵防范", title, Verdict::Fail, format!("{key}={value}"), suggestion),
        None => item("入侵防范", title, Verdict::Unreadable, format!("读不到 {key}"), suggestion),
    }
}

fn sysctl_at_least(input: &BaselineInput, key: &str, min: i64, title: &str, suggestion: &str) -> CheckItem {
    match sysctl(input, key).and_then(|value| value.parse::<i64>().ok()) {
        Some(value) if value >= min => item("入侵防范", title, Verdict::Pass, format!("{key}={value}"), ""),
        Some(value) => item("入侵防范", title, Verdict::Fail, format!("{key}={value}"), suggestion),
        None => item("入侵防范", title, Verdict::Unreadable, format!("读不到 {key}"), suggestion),
    }
}

fn show_opt(value: Option<i64>) -> String {
    value.map(|item| item.to_string()).unwrap_or_else(|| "未配置".into())
}

fn item(domain: &str, title: &str, verdict: Verdict, evidence: impl Into<String>, suggestion: impl Into<String>) -> CheckItem {
    CheckItem {
        domain: domain.into(),
        title: title.into(),
        verdict,
        evidence: evidence.into(),
        suggestion: suggestion.into(),
    }
}

fn sysctl(input: &BaselineInput, key: &str) -> Option<String> {
    input
        .sysctl
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.clone())
}

pub fn defs_int(text: &str, key: &str) -> Option<i64> {
    defs_value(text, key)?.parse().ok()
}

pub fn defs_value(text: &str, key: &str) -> Option<String> {
    let mut found = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        if parts.next().is_some_and(|item| item.eq_ignore_ascii_case(key)) {
            found = parts.next().map(|item| item.to_string());
        }
    }
    found
}

pub fn sshd_value(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.to_ascii_lowercase().starts_with("match ") {
            break;
        }
        let mut parts = line.split_whitespace();
        if parts.next().is_some_and(|item| item.eq_ignore_ascii_case(key)) {
            let value = parts.collect::<Vec<_>>().join(" ");
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

fn sshd_int(text: &str, key: &str) -> Option<u64> {
    sshd_value(text, key)?.parse().ok()
}

fn profile_tmout(text: &str) -> Option<u64> {
    for line in text.lines() {
        let line = line.trim().trim_start_matches("export ").trim();
        if let Some(value) = line.strip_prefix("TMOUT=") {
            return value.trim().trim_matches('"').parse().ok();
        }
    }
    None
}

fn umask_value(text: &str) -> Option<i64> {
    let mut found = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        if parts.next().is_some_and(|item| item == "umask") {
            found = parts.next().and_then(|value| i64::from_str_radix(value, 8).ok());
        }
    }
    found
}

fn faillock_deny(input: &BaselineInput) -> Option<i64> {
    if let Some(value) = assignment_int(&input.faillock, "deny") {
        return Some(value);
    }
    for text in [&input.pam_auth, &input.pam_password] {
        for line in text.lines() {
            let lower = line.to_ascii_lowercase();
            if !(lower.contains("pam_faillock") || lower.contains("pam_tally2") || lower.contains("pam_tally")) {
                continue;
            }
            for token in line.split_whitespace() {
                if let Some(value) = token.strip_prefix("deny=") {
                    if let Ok(value) = value.parse() {
                        return Some(value);
                    }
                }
            }
        }
    }
    None
}

fn assignment_int(text: &str, key: &str) -> Option<i64> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.trim_start_matches("export ");
        if let Some(rest) = line.strip_prefix(key) {
            let rest = rest.trim().trim_start_matches('=').trim();
            if let Ok(value) = rest.parse() {
                return Some(value);
            }
        }
    }
    None
}

fn interactive_shell(shell: &str) -> bool {
    let shell = shell.trim();
    if shell.is_empty() {
        return false;
    }
    let lower = shell.to_ascii_lowercase();
    !(lower.contains("nologin") || lower.contains("false") || lower.ends_with("/sync") || lower.ends_with("/halt") || lower.ends_with("/shutdown"))
}

pub fn listening_ports(text: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for line in text.lines().skip(1) {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() < 4 || parts[3] != "0A" {
            continue;
        }
        if let Some(port) = parts[1].rsplit(':').next().and_then(|value| u16::from_str_radix(value, 16).ok()) {
            ports.push(port);
        }
    }
    ports
}

const HIGH_RISK_PORTS: &[u16] = &[21, 23, 69, 111, 135, 139, 445, 512, 513, 514, 2049];

fn columns(text: &str) -> usize {
    text.chars()
        .map(|ch| {
            let n = ch as u32;
            if (0x1100..=0x115F).contains(&n) || n >= 0x2E80 {
                2
            } else {
                1
            }
        })
        .sum()
}

fn dye(on: bool, code: u8, text: &str) -> String {
    if on {
        format!("\u{1b}[{code}m{text}\u{1b}[0m")
    } else {
        text.to_string()
    }
}

fn verdict_color(verdict: Verdict) -> u8 {
    match verdict {
        Verdict::Pass => 32,
        Verdict::Fail => 31,
        Verdict::Manual => 33,
        Verdict::Unreadable => 90,
    }
}

fn read_text(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

fn first_text(paths: &[&str]) -> String {
    paths.iter().find_map(|path| fs::read_to_string(path).ok()).unwrap_or_default()
}

fn read_dir_files(dir: &str) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| fs::read_to_string(entry.path()).ok())
        .collect()
}

#[cfg(target_os = "linux")]
fn comm_running(name: &str) -> bool {
    let Ok(entries) = fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy().parse::<i32>().is_err() {
            continue;
        }
        let comm = fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
        if comm.trim() == name {
            return true;
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn detect_mac() -> String {
    if fs::read_to_string("/sys/fs/selinux/enforce").ok().as_deref().map(str::trim) == Some("1") {
        return "selinux-enforcing".into();
    }
    let profiles = fs::read_to_string("/sys/kernel/security/apparmor/profiles").unwrap_or_default();
    if profiles.contains("(enforce)") {
        return "apparmor-enforce".into();
    }
    if profiles.contains("(complain)") {
        return "apparmor-complain".into();
    }
    "none".into()
}

#[cfg(target_os = "linux")]
fn malware_paths() -> Vec<String> {
    ["/usr/bin/clamscan", "/usr/sbin/clamd", "/usr/bin/sav", "/opt/eset"]
        .into_iter()
        .filter(|path| Path::new(path).exists())
        .map(|path| path.to_string())
        .collect()
}

#[cfg(target_os = "linux")]
fn detect_firewall() -> String {
    if read_text("/etc/ufw/ufw.conf").lines().any(|line| line.trim() == "ENABLED=yes") {
        return "ufw".into();
    }
    if comm_running("firewalld") {
        return "firewalld".into();
    }
    let nft = read_text("/etc/nftables.conf");
    if nft.contains("table") {
        return "nftables".into();
    }
    for path in ["/etc/iptables/rules.v4", "/etc/sysconfig/iptables"] {
        if Path::new(path).is_file() && !read_text(path).trim().is_empty() {
            return "iptables".into();
        }
    }
    "none".into()
}

#[cfg(target_os = "linux")]
fn file_mode(path: &str) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).ok().map(|meta| meta.permissions().mode())
}

pub fn stdout_color() -> bool {
    io::stdout().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> BaselineInput {
        BaselineInput {
            passwd: "root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000::/home/ubuntu:/bin/bash\nsync:x:4:65534:sync:/bin:/bin/sync\n".into(),
            shadow: Some("root:$6$abc::::::\nubuntu:$6$def::::::\n".into()),
            login_defs: "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 7\nPASS_MIN_LEN 8\nPASS_WARN_AGE 14\nUMASK 027\n".into(),
            profile: "umask 027\nTMOUT=600\n".into(),
            sshd_config: "PermitRootLogin no\nPermitEmptyPasswords no\nClientAliveInterval 300\nClientAliveCountMax 2\n".into(),
            pam_password: "password requisite pam_pwquality.so minlen=8\npassword required pam_google_authenticator.so\n".into(),
            pam_auth: "auth required pam_faillock.so deny=5 unlock_time=900\n".into(),
            faillock: String::new(),
            sysctl: vec![
                ("net.ipv4.tcp_syncookies".into(), "1".into()),
                ("net.ipv4.conf.all.accept_redirects".into(), "0".into()),
                ("net.ipv4.conf.all.send_redirects".into(), "0".into()),
                ("net.ipv4.conf.all.accept_source_route".into(), "0".into()),
                ("net.ipv4.conf.all.rp_filter".into(), "1".into()),
                ("net.ipv4.ip_forward".into(), "0".into()),
                ("kernel.randomize_va_space".into(), "2".into()),
                ("kernel.kptr_restrict".into(), "1".into()),
                ("kernel.dmesg_restrict".into(), "1".into()),
                ("fs.suid_dumpable".into(), "0".into()),
                ("kernel.yama.ptrace_scope".into(), "1".into()),
            ],
            listening_ports: vec![22, 443],
            auditd_running: true,
            audit_rules: "-w /etc/passwd -p wa -k identity\n".into(),
            journal_persistent: true,
            syslog_running: false,
            mac: "apparmor-enforce".into(),
            malware: vec!["/usr/bin/clamscan".into()],
            ima: false,
            modes: vec![
                ("/etc/passwd".into(), Some(0o100644)),
                ("/etc/shadow".into(), Some(0o100640)),
                ("/etc/group".into(), Some(0o100644)),
                ("/etc/ssh/sshd_config".into(), Some(0o100600)),
            ],
            firewall: "ufw".into(),
            sudoers: Some("root ALL=(ALL:ALL) ALL\n".into()),
        }
    }

    #[test]
    fn hardened_host_fails_only_trust_and_manual_items() {
        let items = evaluate(&good());
        let fail: Vec<_> = items.iter().filter(|item| item.verdict == Verdict::Fail).map(|item| item.title.as_str()).collect();
        assert_eq!(fail, vec!["启动链或 IMA"]);
        assert!(items.iter().any(|item| item.title == "口令定期更换" && item.verdict == Verdict::Pass));
        assert!(items.iter().any(|item| item.verdict == Verdict::Manual));
    }

    #[test]
    fn empty_password_and_root_login_fail() {
        let mut input = good();
        input.shadow = Some("root::\nbackup:$6$x:\n".into());
        input.sshd_config = "PermitRootLogin yes\n".into();
        let items = evaluate(&input);
        assert!(items.iter().any(|item| item.title == "不存在空口令" && item.verdict == Verdict::Fail));
        assert!(items.iter().any(|item| item.title == "禁止 root 远程登录" && item.verdict == Verdict::Fail));
    }

    #[test]
    fn parses_listening_hex_port() {
        let text = "  sl  local_address rem_address   st\n   0: 00000000:0016 00000000:0000 0A 00000000:00000000\n   1: 00000000:0050 00000000:0000 01 00000000:00000000\n";
        assert_eq!(listening_ports(text), vec![22]);
    }

    #[test]
    fn report_table_columns_line_up() {
        let text = format_report(&evaluate(&good()), "Ubuntu", false);
        assert!(text.contains("│ 结果"));
        assert!(text.contains("│ 检查项"));
        assert!(text.contains("│ 现状"));
        assert!(text.contains("│ 建议"));
        let mut group = Vec::new();
        for line in text.lines() {
            let first = line.chars().next();
            if !matches!(first, Some('│') | Some('┌') | Some('├') | Some('└')) {
                continue;
            }
            group.push(line);
            if first == Some('└') {
                let width = columns(group[0]);
                for row in &group {
                    assert_eq!(columns(row), width, "{row}");
                }
                group.clear();
            }
        }
        assert!(group.is_empty());
    }
}
