use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::baseline;
use crate::ebpf;
use crate::error::{Error, Result};
use crate::flame;
use crate::procs;
use crate::session;
use crate::tui;

#[derive(Parser)]
#[command(
    name = "linuxtui",
    author,
    version,
    about = "我放在这台 Linux 上的综合工具。直接运行进入导航：硬件、进程、容器、防火墙、网络、日志",
    long_about = "linuxtui。我放在一台 Linux 上，打开先进入导航：硬件、进程、容器、防火墙、网络、日志。性能定位、等保基线、抓包和吞吐都在里面。\n版权所有 © 2026 lei <mr.greevsky@gmail.com>\nhttps://github.com/greevsky/linperf"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// 检查本机能走哪条采集路径
    Check,
    /// 采样两次并输出结论
    Snapshot {
        /// 两次采样的间隔，单位秒
        #[arg(long, default_value_t = 1)]
        interval: u64,
        /// 输出 JSON
        #[arg(long)]
        json: bool,
        /// 使用内置磁盘饱和样本
        #[arg(long)]
        demo: bool,
    },
    /// 终端实时界面
    Watch {
        #[arg(long, default_value_t = 1)]
        interval: u64,
        #[arg(long)]
        demo: bool,
    },
    /// 把一次快照写成 JSON
    Export {
        #[arg(short, long)]
        out: PathBuf,
        #[arg(long, default_value_t = 1)]
        interval: u64,
        #[arg(long)]
        demo: bool,
    },
    /// 由 folded stacks 生成 SVG 火焰图
    Flame {
        #[arg(short, long)]
        input: Option<PathBuf>,
        #[arg(short, long)]
        out: PathBuf,
        #[arg(long)]
        demo: bool,
        #[arg(long, default_value = "linuxtui")]
        title: String,
    },
    /// 采集 on-CPU 或 off-CPU 栈。当前构建未嵌入字节码时会说明原因
    Profile {
        /// oncpu 或 offcpu
        kind: String,
        #[arg(long, default_value_t = 5)]
        seconds: u64,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// 列出这一窗口里最忙的进程，可用名字模糊筛选
    Ps {
        /// 进程名或命令行片段，空格分隔表示都要出现
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value_t = 1)]
        interval: u64,
    },
    /// 按 PID 或进程名查看资源，并给出优化建议
    Inspect {
        #[arg(long)]
        pid: Option<i32>,
        /// 模糊匹配 comm 和命令行
        #[arg(long)]
        name: Option<String>,
        /// 在终端里从列表选择
        #[arg(long)]
        pick: bool,
        #[arg(long, default_value_t = 1)]
        interval: u64,
    },
    /// 按等保三级检查本机安全基线
    Baseline {
        /// 把纯文本报告写到文件，便于打印留档
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// 输出 JSON
        #[arg(long)]
        json: bool,
        /// 关闭颜色
        #[arg(long)]
        no_color: bool,
    },
}

pub fn run() -> Result<()> {
    let command = Cli::parse()
        .command
        .unwrap_or(Command::Watch {
            interval: 1,
            demo: false,
        });
    match command {
        Command::Check => {
            println!("{}", session::check_text()?);
        }
        Command::Snapshot {
            interval,
            json,
            demo,
        } => {
            let snapshot = session::snapshot(interval, demo)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&snapshot).map_err(|err| {
                    Error::Message(format!("JSON 编码失败: {err}"))
                })?);
            } else {
                println!("{}", session::format_snapshot_text(&snapshot));
            }
        }
        Command::Watch { interval, demo } => tui::run(interval, demo)?,
        Command::Export { out, interval, demo } => {
            let snapshot = session::snapshot(interval, demo)?;
            let json = serde_json::to_string_pretty(&snapshot)
                .map_err(|err| Error::Message(format!("JSON 编码失败: {err}")))?;
            fs::write(&out, json + "\n")?;
            println!("已写入 {}", out.display());
        }
        Command::Flame {
            input,
            out,
            demo,
            title,
        } => {
            if demo {
                flame::render_demo(&out)?;
            } else {
                let path = input.ok_or_else(|| {
                    Error::Message("flame 需要 --demo 或 --input".into())
                })?;
                let folded = fs::read_to_string(path)?;
                flame::render_folded(&folded, &title, &out)?;
            }
            println!("已写入 {}", out.display());
        }
        Command::Profile { kind, seconds, out } => {
            let folded = ebpf::sample_folded(&kind, seconds)?;
            match out {
                Some(path) => {
                    fs::write(&path, folded)?;
                    println!("已写入 {}", path.display());
                }
                None => print!("{folded}"),
            }
        }
        Command::Ps { name, interval } => {
            let query = name.unwrap_or_default();
            let rows = session::process_table(interval, &query)?;
            println!("{}", procs::format_table(&rows));
        }
        Command::Inspect {
            pid,
            name,
            pick,
            interval,
        } => {
            let pid = resolve_pid(interval, pid, name.as_deref(), pick)?;
            println!("{}", session::inspect_text(interval, pid)?);
        }
        Command::Baseline { out, json, no_color } => {
            let input = baseline::collect()?;
            let items = baseline::evaluate(&input);
            if json {
                println!("{}", serde_json::to_string_pretty(&items).map_err(|err| {
                    Error::Message(format!("JSON 编码失败: {err}"))
                })?);
            }
            let color = !no_color && baseline::stdout_color() && !json;
            let host = crate::compat::detect()
                .map(|caps| format!("{}  {}", caps.os, caps.kernel))
                .unwrap_or_else(|_| "Linux".into());
            let plain = baseline::format_report(&items, &host, false);
            let shown = if color {
                baseline::format_report(&items, &host, true)
            } else {
                plain.clone()
            };
            if !json {
                println!("{shown}");
            }
            if let Some(path) = out {
                fs::write(&path, plain + "\n")?;
                println!("已写入 {}", path.display());
            }
        }
    }
    Ok(())
}

fn resolve_pid(interval: u64, pid: Option<i32>, name: Option<&str>, pick: bool) -> Result<i32> {
    if let Some(pid) = pid {
        return Ok(pid);
    }
    if pick || name.is_none() {
        return pick_pid(interval, name.unwrap_or(""));
    }
    let query = name.unwrap_or("");
    let rows = session::process_table(interval, query)?;
    match rows.as_slice() {
        [] => Err(Error::Message(format!("没有匹配到进程: {query}"))),
        [one] => Ok(one.pid),
        _ if io::stdin().is_terminal() => pick_from(&rows),
        _ => {
            println!("{}", procs::format_table(&rows));
            Err(Error::Message(
                "匹配到多个进程。指定 --pid，或在终端里运行以便选择。".into(),
            ))
        }
    }
}

fn pick_pid(interval: u64, query: &str) -> Result<i32> {
    if !io::stdin().is_terminal() {
        return Err(Error::Message(
            "交互选择需要终端。改用 --pid 或 --name。".into(),
        ));
    }
    let mut rows = session::process_table(interval, query)?;
    if rows.len() > 20 {
        rows.truncate(20);
    }
    if rows.is_empty() {
        return Err(Error::Message("没有可选进程。".into()));
    }
    println!("{}", procs::format_table(&rows));
    pick_from(&rows)
}

fn pick_from(rows: &[crate::procs::ProcRate]) -> Result<i32> {
    eprint!("序号或 PID: ");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    let line = line.trim();
    if let Ok(index) = line.parse::<usize>() {
        if (1..=rows.len()).contains(&index) {
            return Ok(rows[index - 1].pid);
        }
    }
    if let Ok(pid) = line.parse::<i32>() {
        if rows.iter().any(|proc| proc.pid == pid) || crate::procs::proc_exists(pid) {
            return Ok(pid);
        }
    }
    Err(Error::Message("没有这个序号或 PID。".into()))
}
