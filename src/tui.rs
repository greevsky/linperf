use std::cmp::Ordering;
use std::io::{self, IsTerminal, Stdout};
use std::process::Command;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, HighlightSpacing, Paragraph, Row, Table, TableState,
};
use ratatui::{Frame, Terminal};

use crate::advise;
use crate::bench;
use crate::analyze::{Finding, Severity};
use crate::board;
use crate::sniff;
use crate::syslog;
use crate::collect;
use crate::compat;
use crate::containers;
use crate::error::{Error, Result};
use crate::model::HostSample;
use crate::procs::{self, ProcExtra, ProcRate, ProcShot};
use crate::rate::Rates;
use crate::session;

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortKey {
    Cpu,
    Mem,
    Read,
    Write,
    Pid,
    Name,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Procs,
    Process,
    Logs,
    Containers,
    Firewall,
    Network,
    Syslog,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ContainerAction {
    Logs,
    Inspect,
    Top,
    Stats,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NetFocus {
    Config,
    Ifaces,
    Capture,
    Ssh,
    Bench,
}

#[derive(Clone)]
struct ShownPacket {
    kind: sniff::PacketKind,
    text: String,
    layers: Vec<String>,
    abnormal: bool,
    reason: String,
}

struct App {
    demo: bool,
    demo_index: usize,
    previous: Option<HostSample>,
    latest: Option<HostSample>,
    prev_procs: Option<ProcShot>,
    rates: Option<Rates>,
    findings: Vec<Finding>,
    processes: Vec<ProcRate>,
    cursor: usize,
    home_pid: Option<i32>,
    focus_pid: Option<i32>,
    table_state: TableState,
    sort_key: SortKey,
    descending: bool,
    filtering: bool,
    filter: String,
    screen: Screen,
    board_scroll: usize,
    inventory: containers::Inventory,
    container_picks: Vec<Option<containers::Pick>>,
    container_place: bool,
    firewall: board::FirewallView,
    net: board::NetConfig,
    net_focus: NetFocus,
    capture: sniff::Capture,
    packets: Vec<ShownPacket>,
    packet_from_bottom: usize,
    cap_filter: sniff::KindFilter,
    cap_query: String,
    cap_filtering: bool,
    cap_abnormal: bool,
    cap_detail: bool,
    cap_note: String,
    cap_paused: bool,
    cap_iface: Option<String>,
    packet_cursor: usize,
    packet_follow: bool,
    packet_scroll: usize,
    board_cursor: usize,
    board_rows: Vec<String>,
    box_cursor: usize,
    box_scroll: usize,
    syslog_anchor: Option<usize>,
    capture_from_ifaces: bool,
    hardware: board::HardwareInfo,
    box_output: bool,
    box_exec: bool,
    box_action: Option<ContainerAction>,
    box_pick: Option<containers::Pick>,
    box_title: String,
    box_lines: Vec<String>,
    iface_cursor: usize,
    ssh_host: String,
    ssh_port: String,
    ssh_field: u8,
    ssh_error: String,
    ssh_launch: bool,
    bench: bench::Session,
    bench_host: String,
    bench_port: String,
    bench_field: u8,
    bench_proto: bench::Proto,
    bench_listen: bool,
    syslog_kind: usize,
    syslog_unit: String,
    syslog_lines: Vec<String>,
    syslog_source: String,
    syslog_query: String,
    syslog_filtering: bool,
    full_clear: bool,
    last_refresh: Instant,
    help: bool,
    page_rows: usize,
    log_lines: Vec<String>,
    log_note: String,
    log_from_bottom: usize,
    log_follow: bool,
    process_scroll: usize,
    iface_prev: Option<IfacePrev>,
    status: String,
    host_line: String,
}

struct IfacePrev {
    pid: i32,
    at: std::time::Instant,
    rows: Vec<procs::IfaceCount>,
    lines: Vec<String>,
}

pub fn run(interval_secs: u64, demo: bool) -> Result<()> {
    if !io::stdin().is_terminal() {
        return Err(Error::Message(
            "watch 需要交互终端。管道里用 snapshot --json。".into(),
        ));
    }
    let host_line = if demo {
        "演示样本".into()
    } else {
        compat::detect()
            .map(|caps| format!("{}  {}  {}", caps.os, caps.kernel, caps.arch))
            .unwrap_or_else(|_| "本机".into())
    };
    let mut app = App {
        demo,
        demo_index: 1,
        previous: None,
        latest: None,
        prev_procs: None,
        rates: None,
        findings: Vec::new(),
        processes: Vec::new(),
        cursor: 0,
        home_pid: None,
        focus_pid: None,
        table_state: TableState::default(),
        sort_key: SortKey::Cpu,
        descending: true,
        filtering: false,
        filter: String::new(),
        screen: Screen::Procs,
        board_scroll: 0,
        inventory: containers::Inventory::empty(""),
        container_picks: Vec::new(),
        container_place: false,
        firewall: board::FirewallView::empty(),
        net: board::NetConfig::empty(),
        net_focus: NetFocus::Config,
        capture: sniff::Capture::closed(),
        packets: Vec::new(),
        packet_from_bottom: 0,
        cap_filter: sniff::KindFilter::All,
        cap_query: String::new(),
        cap_filtering: false,
        cap_abnormal: false,
        cap_detail: false,
        cap_note: String::new(),
        cap_paused: false,
        cap_iface: None,
        packet_cursor: 0,
        packet_follow: true,
        packet_scroll: 0,
        board_cursor: 0,
        board_rows: Vec::new(),
        box_cursor: 0,
        box_scroll: 0,
        syslog_anchor: None,
        capture_from_ifaces: false,
        hardware: if demo {
            board::demo_hardware()
        } else {
            board::load_hardware()
        },
        box_output: false,
        box_exec: false,
        box_action: None,
        box_pick: None,
        box_title: String::new(),
        box_lines: Vec::new(),
        iface_cursor: 0,
        ssh_host: String::new(),
        ssh_port: "22".into(),
        ssh_field: 0,
        ssh_error: String::new(),
        ssh_launch: false,
        bench: bench::Session::idle(),
        bench_host: "127.0.0.1".into(),
        bench_port: "5201".into(),
        bench_field: 0,
        bench_proto: bench::Proto::Tcp,
        bench_listen: false,
        syslog_kind: 0,
        syslog_unit: String::new(),
        syslog_lines: Vec::new(),
        syslog_source: String::new(),
        syslog_query: String::new(),
        syslog_filtering: false,
        full_clear: true,
        last_refresh: Instant::now(),
        help: false,
        page_rows: 20,
        log_lines: Vec::new(),
        log_note: String::new(),
        log_from_bottom: 0,
        log_follow: true,
        process_scroll: 0,
        iface_prev: None,
        status: if demo {
            "演示".into()
        } else {
            "正在采样".into()
        },
        host_line,
    };
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;
    terminal.draw(|frame| draw(frame, &mut app))?;
    refresh(&mut app)?;
    app.last_refresh = Instant::now();
    let result = event_loop(&mut terminal, &mut app, interval_secs.max(1));
    app.capture = sniff::Capture::closed();
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    result
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    interval_secs: u64,
) -> Result<()> {
    let interval = Duration::from_secs(interval_secs);
    loop {
        if app.full_clear {
            terminal.clear()?;
            app.full_clear = false;
        }
        terminal.draw(|frame| draw(frame, app))?;
        if event::poll(next_timeout(app, interval))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Release {
                    continue;
                }
                if on_key(app, key) {
                    return Ok(());
                }
                if app.ssh_launch {
                    app.ssh_launch = false;
                    launch_ssh(terminal, app)?;
                }
                if app.box_exec {
                    app.box_exec = false;
                    launch_container_exec(terminal, app)?;
                }
            }
        }
        if app.last_refresh.elapsed() >= interval {
            refresh(app)?;
            app.last_refresh = Instant::now();
        }
        drain_capture(app);
    }
}

fn next_timeout(app: &App, interval: Duration) -> Duration {
    if app.capture.is_open() || app.bench.snap().running {
        return Duration::from_millis(40);
    }
    interval
        .saturating_sub(app.last_refresh.elapsed())
        .max(Duration::from_millis(40))
}

fn on_key(app: &mut App, key: KeyEvent) -> bool {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return true;
    }
    if key.code == KeyCode::Char('?') {
        app.help = !app.help;
        return false;
    }
    if app.help {
        if key.code == KeyCode::Esc {
            app.help = false;
        }
        return false;
    }
    if app.filtering {
        return on_filter_key(app, key);
    }
    match app.screen {
        Screen::Firewall => on_scroll_key(app, key),
        Screen::Containers => on_container_key(app, key),
        Screen::Procs => on_home_key(app, key),
        Screen::Process => on_process_key(app, key),
        Screen::Logs => on_log_key(app, key),
        Screen::Network => on_net_key(app, key),
        Screen::Syslog => on_syslog_key(app, key),
    }
}

fn on_filter_key(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => {
            app.filtering = false;
            app.filter.clear();
            app.cursor = 0;
            app.home_pid = None;
        }
        KeyCode::Enter => app.filtering = false,
        KeyCode::Backspace => {
            app.filter.pop();
            app.cursor = 0;
            app.home_pid = None;
        }
        KeyCode::Char(ch) if !ch.is_control() && !key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.filter.push(ch);
            app.cursor = 0;
            app.home_pid = None;
        }
        _ => {}
    }
    false
}

fn on_home_key(app: &mut App, key: KeyEvent) -> bool {
    let visible = visible_procs(app);
    let len = visible.len();
    let page = app.page_rows.max(1);
    match key.code {
        KeyCode::Char('q') => return true,
        KeyCode::Char('j') | KeyCode::Down => move_cursor(app, &visible, 1),
        KeyCode::Char('k') | KeyCode::Up => move_cursor(app, &visible, -1),
        KeyCode::PageDown => move_cursor(app, &visible, page as isize),
        KeyCode::PageUp => move_cursor(app, &visible, -(page as isize)),
        KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            move_cursor(app, &visible, (page / 2).max(1) as isize);
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            move_cursor(app, &visible, -((page / 2).max(1) as isize));
        }
        KeyCode::Char('g') => move_cursor_to(app, &visible, 0),
        KeyCode::Char('G') => move_cursor_to(app, &visible, len.saturating_sub(1)),
        KeyCode::Enter => {
            if let Some(proc) = visible.get(app.cursor) {
                app.home_pid = Some(proc.pid);
                app.focus_pid = Some(proc.pid);
                app.screen = Screen::Process;
                app.process_scroll = 0;
                app.iface_prev = None;
            }
        }
        KeyCode::Esc => {
            if !app.filter.is_empty() {
                app.filter.clear();
                app.cursor = 0;
                app.home_pid = None;
            }
        }
        KeyCode::Char('1') => open_section(app, Screen::Containers),
        KeyCode::Char('2') => open_section(app, Screen::Firewall),
        KeyCode::Char('3') => open_section(app, Screen::Network),
        KeyCode::Char('4') => open_section(app, Screen::Syslog),
        KeyCode::Char('/') => app.filtering = true,
        KeyCode::Char('c') => toggle_sort(app, SortKey::Cpu),
        KeyCode::Char('m') => toggle_sort(app, SortKey::Mem),
        KeyCode::Char('r') => toggle_sort(app, SortKey::Read),
        KeyCode::Char('w') => toggle_sort(app, SortKey::Write),
        KeyCode::Char('p') => toggle_sort(app, SortKey::Pid),
        KeyCode::Char('n') => toggle_sort(app, SortKey::Name),
        _ => {}
    }
    false
}

fn on_process_key(app: &mut App, key: KeyEvent) -> bool {
    let page = app.page_rows.max(1);
    match key.code {
        KeyCode::Char('q') => true,
        KeyCode::Esc => {
            app.home_pid = app.focus_pid.or(app.home_pid);
            app.screen = Screen::Procs;
            false
        }
        KeyCode::Char('l') => {
            app.screen = Screen::Logs;
            app.log_from_bottom = 0;
            app.log_follow = true;
            refresh_logs(app);
            false
        }
        KeyCode::Char('j') | KeyCode::Down => {
            app.process_scroll = app.process_scroll.saturating_add(1);
            false
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.process_scroll = app.process_scroll.saturating_sub(1);
            false
        }
        KeyCode::PageDown => {
            app.process_scroll = app.process_scroll.saturating_add(page);
            false
        }
        KeyCode::PageUp => {
            app.process_scroll = app.process_scroll.saturating_sub(page);
            false
        }
        KeyCode::Char('g') => {
            app.process_scroll = 0;
            false
        }
        KeyCode::Char('G') => {
            app.process_scroll = usize::MAX / 4;
            false
        }
        _ => false,
    }
}

fn on_log_key(app: &mut App, key: KeyEvent) -> bool {
    let page = app.page_rows.max(1);
    match key.code {
        KeyCode::Char('q') => true,
        KeyCode::Esc => {
            app.screen = Screen::Process;
            false
        }
        KeyCode::Char('j') | KeyCode::Down => {
            app.log_from_bottom = app.log_from_bottom.saturating_sub(1);
            app.log_follow = app.log_from_bottom == 0;
            false
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.log_from_bottom = app.log_from_bottom.saturating_add(1);
            app.log_follow = false;
            false
        }
        KeyCode::Char('g') => {
            app.log_from_bottom = usize::MAX / 4;
            app.log_follow = false;
            false
        }
        KeyCode::Char('G') => {
            app.log_from_bottom = 0;
            app.log_follow = true;
            false
        }
        KeyCode::PageDown => {
            app.log_from_bottom = app.log_from_bottom.saturating_sub(page);
            app.log_follow = app.log_from_bottom == 0;
            false
        }
        KeyCode::PageUp => {
            app.log_from_bottom = app.log_from_bottom.saturating_add(page);
            app.log_follow = false;
            false
        }
        _ => false,
    }
}

fn toggle_sort(app: &mut App, key: SortKey) {
    if app.sort_key == key {
        app.descending = !app.descending;
    } else {
        app.sort_key = key;
        app.descending = key != SortKey::Name && key != SortKey::Pid;
    }
    app.cursor = 0;
    app.home_pid = None;
}

fn move_cursor(app: &mut App, visible: &[ProcRate], delta: isize) {
    if visible.is_empty() {
        return;
    }
    let next = (app.cursor as isize + delta).clamp(0, visible.len() as isize - 1) as usize;
    move_cursor_to(app, visible, next);
}

fn move_cursor_to(app: &mut App, visible: &[ProcRate], index: usize) {
    if visible.is_empty() {
        app.cursor = 0;
        app.home_pid = None;
        return;
    }
    let index = index.min(visible.len() - 1);
    app.cursor = index;
    app.home_pid = Some(visible[index].pid);
}

fn refresh(app: &mut App) -> Result<()> {
    if app.demo {
        let (rates, findings, processes, index) = session::demo_frame(app.demo_index)?;
        app.demo_index = if index + 1 >= session::demo_len() {
            1
        } else {
            index + 1
        };
        app.rates = Some(rates);
        app.findings = findings;
        app.processes = processes;
        app.status = format!("演示  帧 {index}");
        if app.screen == Screen::Logs {
            refresh_logs(app);
        }
        refresh_boards(app);
        return Ok(());
    }
    match collect::capture_live() {
        Ok(sample) => {
            let shot = procs::capture();
            if let Some(prev) = app.prev_procs.take() {
                app.processes = procs::diff_all(&prev, &shot);
            }
            app.prev_procs = Some(shot);
            app.previous = app.latest.take();
            if let Some(prev) = &app.previous {
                match crate::rate::between(prev, &sample) {
                    Ok(rates) => {
                        app.findings = crate::analyze::analyze(&rates);
                        app.rates = Some(rates);
                        app.status = "本机".into();
                    }
                    Err(err) => app.status = err.to_string(),
                }
            } else {
                app.status = "下一拍列出进程".into();
            }
            app.latest = Some(sample);
            if app.screen == Screen::Logs {
                refresh_logs(app);
            }
        }
        Err(err) => app.status = err.to_string(),
    }
    refresh_boards(app);
    Ok(())
}

fn refresh_logs(app: &mut App) {
    let Some(pid) = app.focus_pid else {
        app.log_note = "没有选中的进程".into();
        app.log_lines.clear();
        return;
    };
    let proc = app.processes.iter().find(|item| item.pid == pid);
    if app.demo {
        let unit = proc
            .and_then(|item| demo_unit(item))
            .unwrap_or_else(|| "无服务".into());
        if unit == "无服务" {
            app.log_note = "这个进程不在 systemd 服务里，没有可尾随的日志。".into();
            app.log_lines.clear();
            return;
        }
        app.log_note = format!("{unit}  演示日志");
        app.log_lines = demo_log_lines(proc);
        return;
    }
    let extra = procs::extra(pid);
    match procs::systemd_unit(&extra.cgroup) {
        Some(unit) => match journal_tail(&unit) {
            Ok(lines) => {
                app.log_note = unit;
                app.log_lines = lines;
            }
            Err(err) => {
                app.log_note = unit;
                app.log_lines = vec![err];
            }
        },
        None => {
            app.log_note = "这个进程不在 systemd 服务里，没有可尾随的日志。".into();
            app.log_lines.clear();
        }
    }
}

fn demo_unit(proc: &ProcRate) -> Option<String> {
    match proc.comm.as_str() {
        "fio" => Some("fio.service".into()),
        "nginx" => Some("nginx.service".into()),
        "postgres" => Some("postgresql.service".into()),
        _ => None,
    }
}

fn demo_log_lines(proc: Option<&ProcRate>) -> Vec<String> {
    let Some(proc) = proc else {
        return vec!["进程已经退出".into()];
    };
    vec![
        format!(
            "状态 {}  等待 {}",
            procs::state_label(&proc.state),
            if proc.wchan.is_empty() {
                "没有"
            } else {
                proc.wchan.as_str()
            }
        ),
        format!(
            "CPU {}  RSS {}  读 {}  写 {}",
            procs::cpu_percent(proc.cpu_ratio),
            procs::human_kb(proc.rss_kb),
            procs::human_bps(proc.read_bps),
            procs::human_bps(proc.write_bps)
        ),
        format!("命令  {}", procs::display_cmd(proc, 100)),
    ]
}

fn journal_tail(unit: &str) -> std::result::Result<Vec<String>, String> {
    let output = Command::new("journalctl")
        .args([
            "-u",
            unit,
            "-n",
            "200",
            "--no-pager",
            "-o",
            "short-iso",
            "--quiet",
        ])
        .env("SYSTEMD_COLORS", "0")
        .env("TERM", "dumb")
        .output()
        .map_err(|err| format!("无法运行 journalctl: {err}"))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        let err = err.trim();
        if err.is_empty() {
            return Err(format!("journalctl 退出码 {}", output.status));
        }
        return Err(err.to_string());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<_> = text.lines().map(board::plain_line).filter(|line| !line.is_empty()).collect();
    if lines.is_empty() {
        return Err(format!("{unit} 暂时没有日志"));
    }
    Ok(lines)
}

fn open_section(app: &mut App, screen: Screen) {
    stop_capture(app);
    app.bench.stop();
    app.full_clear = true;
    app.net_focus = NetFocus::Config;
    app.board_scroll = 0;
    app.board_cursor = 0;
    app.box_output = false;
    app.screen = screen;
    prepare_screen(app);
}

fn prepare_screen(app: &mut App) {
    match app.screen {
        Screen::Containers => {
            app.inventory = if app.demo {
                containers::demo()
            } else {
                containers::load()
            };
            app.container_place = true;
            app.box_output = false;
            app.box_action = None;
            app.box_pick = None;
        }
        Screen::Firewall => {
            app.firewall = if app.demo {
                board::demo_firewall()
            } else {
                board::load_firewall()
            };
        }
        Screen::Network => {
            app.net = if app.demo {
                board::demo_net()
            } else {
                board::load_net()
            };
        }
        Screen::Syslog => load_syslog(app, true),
        _ => {}
    }
}

fn return_to_procs(app: &mut App) {
    stop_capture(app);
    app.bench.stop();
    app.full_clear = true;
    app.net_focus = NetFocus::Config;
    app.screen = Screen::Procs;
    app.board_scroll = 0;
}

fn on_scroll_key(app: &mut App, key: KeyEvent) -> bool {
    let page = app.page_rows.max(1);
    let last = app.board_rows.len().saturating_sub(1);
    match key.code {
        KeyCode::Char('q') => true,
        KeyCode::Esc => {
            return_to_procs(app);
            false
        }
        KeyCode::Char('j') | KeyCode::Down => {
            app.board_cursor = (app.board_cursor + 1).min(last);
            false
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.board_cursor = app.board_cursor.saturating_sub(1);
            false
        }
        KeyCode::PageDown => {
            app.board_cursor = (app.board_cursor + page).min(last);
            false
        }
        KeyCode::PageUp => {
            app.board_cursor = app.board_cursor.saturating_sub(page);
            false
        }
        KeyCode::Char('g') => {
            app.board_cursor = 0;
            false
        }
        KeyCode::Char('G') => {
            app.board_cursor = last;
            false
        }
        _ => false,
    }
}

fn on_container_key(app: &mut App, key: KeyEvent) -> bool {
    if app.box_output {
        return match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Esc => {
                app.box_output = false;
                app.box_action = None;
                false
            }
            KeyCode::Char('G') => {
                app.log_follow = true;
                app.box_cursor = usize::MAX;
                false
            }
            KeyCode::Char('g') => {
                app.log_follow = false;
                app.box_cursor = 0;
                false
            }
            _ => {
                let page = app.page_rows.max(1);
                let last = app.board_rows.len().saturating_sub(1);
                nudge_cursor(&mut app.box_cursor, &key, last, page);
                if app.box_action == Some(ContainerAction::Logs) {
                    app.log_follow = app.box_cursor >= last;
                }
                false
            }
        };
    }
    match key.code {
        KeyCode::Char('q') => true,
        KeyCode::Esc => {
            return_to_procs(app);
            false
        }
        KeyCode::Char('l') => {
            run_container_action(app, ContainerAction::Logs);
            false
        }
        KeyCode::Char('i') | KeyCode::Enter => {
            run_container_action(app, ContainerAction::Inspect);
            false
        }
        KeyCode::Char('t') => {
            run_container_action(app, ContainerAction::Top);
            false
        }
        KeyCode::Char('s') => {
            run_container_action(app, ContainerAction::Stats);
            false
        }
        KeyCode::Char('e') => {
            app.box_exec = true;
            false
        }
        _ => on_scroll_key_stay(app, key),
    }
}

fn on_scroll_key_stay(app: &mut App, key: KeyEvent) -> bool {
    let page = app.page_rows.max(1);
    let last = app.board_rows.len().saturating_sub(1);
    nudge_cursor(&mut app.board_cursor, &key, last, page);
    false
}

fn nudge_cursor(cursor: &mut usize, key: &KeyEvent, last: usize, page: usize) {
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => *cursor = (*cursor + 1).min(last),
        KeyCode::Char('k') | KeyCode::Up => *cursor = cursor.saturating_sub(1),
        KeyCode::PageDown => *cursor = (*cursor + page).min(last),
        KeyCode::PageUp => *cursor = cursor.saturating_sub(page),
        KeyCode::Char('g') => *cursor = 0,
        KeyCode::Char('G') => *cursor = last,
        _ => {}
    }
}

fn on_net_key(app: &mut App, key: KeyEvent) -> bool {
    if app.net_focus == NetFocus::Ssh {
        return on_ssh_key(app, key);
    }
    if app.net_focus == NetFocus::Bench {
        return on_bench_key(app, key);
    }
    match key.code {
        KeyCode::Char('1') => {
            stop_capture(app);
            app.bench.stop();
            app.capture_from_ifaces = false;
            app.net_focus = NetFocus::Config;
            app.board_scroll = 0;
            return false;
        }
        KeyCode::Char('2') => {
            stop_capture(app);
            app.bench.stop();
            app.net_focus = NetFocus::Ifaces;
            app.iface_cursor = 0;
            if app.net.nics.is_empty() {
                prepare_screen(app);
            }
            return false;
        }
        KeyCode::Char('3') => {
            stop_capture(app);
            app.bench.stop();
            app.net_focus = NetFocus::Ssh;
            app.ssh_error.clear();
            return false;
        }
        KeyCode::Char('4') => {
            stop_capture(app);
            app.net_focus = NetFocus::Bench;
            return false;
        }
        _ => {}
    }
    match app.net_focus {
        NetFocus::Config => on_scroll_key(app, key),
        NetFocus::Ifaces => on_iface_key(app, key),
        NetFocus::Capture => on_capture_key(app, key),
        NetFocus::Ssh | NetFocus::Bench => false,
    }
}

fn on_bench_key(app: &mut App, key: KeyEvent) -> bool {
    let running = app.bench.snap().running;
    match key.code {
        KeyCode::Char('q') => true,
        KeyCode::Esc => {
            let was_running = app.bench.snap().running;
            app.bench.stop();
            if !was_running {
                app.net_focus = NetFocus::Config;
            }
            false
        }
        KeyCode::Char('1') => {
            app.bench.stop();
            app.net_focus = NetFocus::Config;
            false
        }
        KeyCode::Char('2') => {
            app.bench.stop();
            app.net_focus = NetFocus::Ifaces;
            app.iface_cursor = 0;
            false
        }
        KeyCode::Char('3') => {
            app.bench.stop();
            app.net_focus = NetFocus::Ssh;
            false
        }
        KeyCode::Char('t') if !running => {
            app.bench_proto = bench::Proto::Tcp;
            false
        }
        KeyCode::Char('u') if !running => {
            app.bench_proto = bench::Proto::Udp;
            false
        }
        KeyCode::Char('l') if !running => {
            app.bench_listen = !app.bench_listen;
            false
        }
        KeyCode::Tab | KeyCode::Down | KeyCode::Up if !running && !app.bench_listen => {
            app.bench_field = if app.bench_field == 0 { 1 } else { 0 };
            false
        }
        KeyCode::Backspace if !running && !app.bench_listen => {
            if app.bench_field == 0 {
                app.bench_host.pop();
            } else {
                app.bench_port.pop();
            }
            false
        }
        KeyCode::Enter if !running => {
            start_bench(app);
            false
        }
        KeyCode::Char(ch) if !running && !app.bench_listen && !ch.is_control() => {
            if app.bench_field == 0 && app.bench_host.len() < 253 && !ch.is_whitespace() {
                app.bench_host.push(ch);
            } else if app.bench_field == 1 && ch.is_ascii_digit() && app.bench_port.len() < 5 {
                app.bench_port.push(ch);
            }
            false
        }
        _ => false,
    }
}

fn start_bench(app: &mut App) {
    if app.demo {
        app.bench.start_preview();
        return;
    }
    let Ok(port) = app.bench_port.parse::<u16>() else {
        app.bench.note_error("端口要在 1 到 65535".into());
        return;
    };
    if port == 0 {
        app.bench.note_error("端口要在 1 到 65535".into());
        return;
    }
    let result = if app.bench_listen {
        app.bench.start_server(port, app.bench_proto)
    } else {
        app.bench.start_client(&app.bench_host, port, app.bench_proto, 10)
    };
    if let Err(err) = result {
        app.bench.note_error(err);
    }
}

fn on_iface_key(app: &mut App, key: KeyEvent) -> bool {
    let len = app.net.nics.len() + 1;
    match key.code {
        KeyCode::Char('q') => true,
        KeyCode::Esc => {
            app.net_focus = NetFocus::Config;
            false
        }
        KeyCode::Char('a') => {
            app.capture_from_ifaces = true;
            start_capture(app, None);
            false
        }
        KeyCode::Enter => {
            let name = if app.iface_cursor == 0 {
                None
            } else {
                app.net.nics.get(app.iface_cursor - 1).map(|nic| nic.name.clone())
            };
            app.capture_from_ifaces = true;
            start_capture(app, name);
            false
        }
        KeyCode::Char('j') | KeyCode::Down => {
            app.iface_cursor = (app.iface_cursor + 1).min(len.saturating_sub(1));
            false
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.iface_cursor = app.iface_cursor.saturating_sub(1);
            false
        }
        _ => false,
    }
}

fn on_capture_key(app: &mut App, key: KeyEvent) -> bool {
    if app.cap_filtering {
        return on_cap_filter_key(app, key);
    }
    let page = app.page_rows.max(1);
    match key.code {
        KeyCode::Char('q') => true,
        KeyCode::Esc => {
            if app.cap_detail {
                app.cap_detail = false;
                app.packet_follow = false;
                return false;
            }
            stop_capture(app);
            if app.capture_from_ifaces {
                app.capture_from_ifaces = false;
                app.net_focus = NetFocus::Ifaces;
            } else {
                app.net_focus = NetFocus::Config;
            }
            false
        }
        KeyCode::Char('/') => {
            app.cap_filtering = true;
            app.packet_follow = false;
            false
        }
        KeyCode::Char('x') => {
            app.cap_abnormal = !app.cap_abnormal;
            app.packet_follow = false;
            app.packet_cursor = 0;
            false
        }
        KeyCode::Char('n') => {
            jump_abnormal(app, 1);
            false
        }
        KeyCode::Enter => {
            if !visible_packets(app).is_empty() {
                app.cap_detail = true;
                app.packet_follow = false;
            }
            false
        }
        KeyCode::Char('t') => {
            app.cap_filter = sniff::KindFilter::Tcp;
            false
        }
        KeyCode::Char('u') => {
            app.cap_filter = sniff::KindFilter::Udp;
            false
        }
        KeyCode::Char('i') => {
            app.cap_filter = sniff::KindFilter::Icmp;
            false
        }
        KeyCode::Char('a') => {
            app.cap_filter = sniff::KindFilter::All;
            false
        }
        KeyCode::Char('p') | KeyCode::Char(' ') => {
            toggle_pause(app);
            false
        }
        KeyCode::Char('j') | KeyCode::Down => {
            let last = filtered_packet_len(app).saturating_sub(1);
            app.packet_cursor = (app.packet_cursor + 1).min(last);
            app.packet_follow = app.packet_cursor + 1 >= filtered_packet_len(app);
            false
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.packet_cursor = app.packet_cursor.saturating_sub(1);
            app.packet_follow = false;
            false
        }
        KeyCode::Char('G') => {
            app.packet_follow = true;
            app.packet_cursor = filtered_packet_len(app).saturating_sub(1);
            false
        }
        KeyCode::Char('g') => {
            app.packet_follow = false;
            app.packet_cursor = 0;
            false
        }
        KeyCode::PageDown => {
            let last = filtered_packet_len(app).saturating_sub(1);
            app.packet_cursor = (app.packet_cursor + page).min(last);
            app.packet_follow = app.packet_cursor + 1 >= filtered_packet_len(app);
            false
        }
        KeyCode::PageUp => {
            app.packet_cursor = app.packet_cursor.saturating_sub(page);
            app.packet_follow = false;
            false
        }
        _ => false,
    }
}

fn on_cap_filter_key(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => {
            app.cap_filtering = false;
            app.cap_query.clear();
            app.packet_cursor = 0;
        }
        KeyCode::Enter => app.cap_filtering = false,
        KeyCode::Backspace => {
            app.cap_query.pop();
            app.packet_cursor = 0;
        }
        KeyCode::Char(ch) if !ch.is_control() && !key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.cap_query.push(ch);
            app.packet_cursor = 0;
            app.packet_follow = false;
        }
        _ => {}
    }
    false
}

fn jump_abnormal(app: &mut App, step: isize) {
    let visible = select_packets(&app.packets, app.cap_filter, app.cap_abnormal, &app.cap_query);
    if visible.is_empty() {
        return;
    }
    let mut index = app.packet_cursor.min(visible.len() - 1);
    for _ in 0..visible.len() {
        index = if step >= 0 {
            (index + 1) % visible.len()
        } else if index == 0 {
            visible.len() - 1
        } else {
            index - 1
        };
        if visible[index].abnormal {
            app.packet_cursor = index;
            app.packet_follow = false;
            return;
        }
    }
}

fn on_ssh_key(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => {
            app.net_focus = NetFocus::Config;
            false
        }
        KeyCode::Tab | KeyCode::Up | KeyCode::Down => {
            app.ssh_field = if app.ssh_field == 0 { 1 } else { 0 };
            false
        }
        KeyCode::Backspace => {
            if app.ssh_field == 0 {
                app.ssh_host.pop();
            } else {
                app.ssh_port.pop();
            }
            false
        }
        KeyCode::Enter => {
            if app.ssh_field == 0 {
                app.ssh_field = 1;
            } else {
                app.ssh_launch = true;
            }
            false
        }
        KeyCode::Char(ch) if !ch.is_control() => {
            if app.ssh_field == 0 && app.ssh_host.len() < 253 {
                app.ssh_host.push(ch);
            } else if app.ssh_field == 1 && ch.is_ascii_digit() && app.ssh_port.len() < 5 {
                app.ssh_port.push(ch);
            }
            false
        }
        _ => false,
    }
}

fn start_capture(app: &mut App, iface: Option<String>) {
    stop_capture(app);
    app.packets.clear();
    app.packet_from_bottom = 0;
    app.packet_cursor = 0;
    app.packet_follow = true;
    app.packet_scroll = 0;
    app.cap_paused = false;
    app.cap_filter = sniff::KindFilter::All;
    app.cap_query.clear();
    app.cap_filtering = false;
    app.cap_abnormal = false;
    app.cap_detail = false;
    app.cap_iface = iface.clone();
    let label = iface.clone().unwrap_or_else(|| "全部网卡".into());
    if app.demo {
        app.packets = sniff::demo_packets()
            .into_iter()
            .map(|(text, view)| shown_packet(text, view))
            .collect();
        app.cap_note = format!("{label}  演示数据，没有打开网卡");
        app.net_focus = NetFocus::Capture;
        return;
    }
    match sniff::Capture::open(iface.as_deref()) {
        Ok(capture) => {
            app.cap_note = format!("{}  拆开报文头，不展示载荷", capture.label());
            app.capture = capture;
            app.net_focus = NetFocus::Capture;
        }
        Err(err) => {
            app.cap_note = err;
            app.net_focus = NetFocus::Capture;
        }
    }
}

fn stop_capture(app: &mut App) {
    app.capture = sniff::Capture::closed();
    app.cap_paused = false;
}

fn toggle_pause(app: &mut App) {
    app.cap_paused = !app.cap_paused;
    if app.cap_paused {
        app.capture = sniff::Capture::closed();
        return;
    }
    if app.demo {
        return;
    }
    match sniff::Capture::open(app.cap_iface.as_deref()) {
        Ok(capture) => {
            app.cap_note = format!("{}  拆开报文头，不展示载荷", capture.label());
            app.capture = capture;
        }
        Err(err) => {
            app.cap_paused = true;
            app.cap_note = err;
        }
    }
}

fn filtered_packet_len(app: &App) -> usize {
    visible_packets(app).len()
}

fn visible_packets(app: &App) -> Vec<&ShownPacket> {
    select_packets(&app.packets, app.cap_filter, app.cap_abnormal, &app.cap_query)
}

fn select_packets<'a>(
    packets: &'a [ShownPacket],
    filter: sniff::KindFilter,
    abnormal_only: bool,
    query: &str,
) -> Vec<&'a ShownPacket> {
    packets
        .iter()
        .filter(|item| packet_visible(item, filter, abnormal_only, query))
        .collect()
}

fn packet_visible(item: &ShownPacket, filter: sniff::KindFilter, abnormal_only: bool, query: &str) -> bool {
    if !filter.allows(item.kind) || (abnormal_only && !item.abnormal) {
        return false;
    }
    let mut haystack = item.text.clone();
    if !item.reason.is_empty() {
        haystack.push(' ');
        haystack.push_str(&item.reason);
    }
    for layer in &item.layers {
        haystack.push(' ');
        haystack.push_str(layer);
    }
    sniff::query_match(&haystack, query)
}

fn shown_packet(text: String, view: sniff::PacketView) -> ShownPacket {
    let text = if view.reason.is_empty() || text.contains(&view.reason) {
        text
    } else {
        format!("{text}  〔{}〕", view.reason)
    };
    ShownPacket {
        kind: view.kind,
        text,
        layers: view.layers,
        abnormal: view.abnormal,
        reason: view.reason,
    }
}

fn refresh_boards(app: &mut App) {
    match app.screen {
        Screen::Containers => {
            app.inventory = if app.demo {
                containers::demo()
            } else {
                containers::load()
            };
            refresh_container_logs(app);
        }
        Screen::Firewall => {
            app.firewall = if app.demo {
                board::demo_firewall()
            } else {
                board::load_firewall()
            };
        }
        Screen::Network if app.net_focus == NetFocus::Config => {
            app.net = if app.demo {
                board::demo_net()
            } else {
                board::load_net()
            };
        }
        Screen::Syslog => load_syslog(app, false),
        _ => {}
    }
}

fn load_syslog(app: &mut App, place: bool) {
    let kind = syslog::LogKind::from_index(app.syslog_kind);
    let view = if !app.syslog_unit.is_empty() {
        if app.demo {
            syslog::demo_unit(&app.syslog_unit)
        } else {
            syslog::load_unit(&app.syslog_unit)
        }
    } else if app.demo {
        syslog::demo(kind)
    } else {
        syslog::load(kind)
    };
    app.syslog_source = view.source;
    app.syslog_lines = view.lines;
    if place {
        if syslog_stream(app) {
            app.log_follow = true;
            app.board_cursor = usize::MAX;
        } else {
            app.board_cursor = 2;
            app.board_scroll = 0;
        }
    }
}

fn syslog_stream(app: &App) -> bool {
    if !app.syslog_unit.is_empty() {
        return true;
    }
    matches!(
        syslog::LogKind::from_index(app.syslog_kind),
        syslog::LogKind::Audit
            | syslog::LogKind::Kernel
            | syslog::LogKind::System
            | syslog::LogKind::Auth
            | syslog::LogKind::Service
            | syslog::LogKind::Cron
    )
}

fn drain_capture(app: &mut App) {
    if app.cap_paused || !app.capture.is_open() {
        return;
    }
    if app.packets.len() >= 20_000 {
        app.cap_note = format!("{}  缓冲已满，不再追加，已有报文保留", app.capture.label());
        return;
    }
    for _ in 0..64 {
        let Some((text, view)) = app.capture.recv() else {
            break;
        };
        app.packets.push(shown_packet(text, view));
        if app.packets.len() >= 20_000 {
            break;
        }
    }
}

fn launch_ssh(terminal: &mut Terminal<CrosstermBackend<Stdout>>, app: &mut App) -> Result<()> {
    let (host, port) = match ssh_target(&app.ssh_host, &app.ssh_port) {
        Ok(target) => target,
        Err(err) => {
            app.ssh_error = err;
            return Ok(());
        }
    };
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    let status = Command::new("ssh").arg("-p").arg(&port).arg(&host).status();
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    terminal.clear()?;
    app.ssh_error = match status {
        Ok(status) if status.success() => String::new(),
        Ok(status) => format!("ssh 退出码 {}", status.code().unwrap_or(-1)),
        Err(err) => format!("无法启动 ssh: {err}"),
    };
    Ok(())
}

fn ssh_target(host: &str, port: &str) -> std::result::Result<(String, String), String> {
    let host = host.trim();
    if host.is_empty() || host.chars().any(|ch| ch.is_whitespace()) || host.starts_with('-') {
        return Err("主机不能为空，不能含空格，也不能以 - 开头".into());
    }
    let port_num: u16 = port
        .trim()
        .parse()
        .map_err(|_| "端口要是 1 到 65535".to_string())?;
    if port_num == 0 {
        return Err("端口要是 1 到 65535".into());
    }
    Ok((host.to_string(), port_num.to_string()))
}

fn run_container_action(app: &mut App, action: ContainerAction) {
    let Some(pick) = selected_pick(app).cloned() else {
        app.box_title = "容器".into();
        app.box_lines = vec!["没有选中这一行".into()];
        app.box_output = true;
        app.box_action = None;
        reset_box_view(app);
        return;
    };
    if !action_applies(&pick, action) {
        app.box_title = action_name(action).into();
        app.box_lines = vec![action_reject(&pick, action)];
        app.box_output = true;
        app.box_action = None;
        reset_box_view(app);
        return;
    }
    reset_box_view(app);
    app.box_output = true;
    app.box_action = Some(action);
    app.box_pick = Some(pick.clone());
    if action == ContainerAction::Logs {
        app.log_follow = true;
    }
    if app.demo {
        app.box_title = format!("{} {}", action_name(action), pick_label(&pick));
        app.box_lines = vec![format!("演示：{} {}", action_name(action), pick_label(&pick))];
        return;
    }
    match container_output(&app.inventory.tool, &pick, action) {
        Ok((title, lines)) => {
            app.box_title = title;
            app.box_lines = lines;
        }
        Err(err) => {
            app.box_title = pick_label(&pick);
            app.box_lines = vec![err];
        }
    }
}

fn refresh_container_logs(app: &mut App) {
    if !app.box_output || app.box_action != Some(ContainerAction::Logs) {
        return;
    }
    let Some(pick) = app.box_pick.clone() else {
        return;
    };
    if app.demo {
        app.box_lines.push(format!("演示  跟踪  {}", app.demo_index));
        if app.box_lines.len() > 200 {
            let extra = app.box_lines.len() - 200;
            app.box_lines.drain(0..extra);
        }
        return;
    }
    match container_output(&app.inventory.tool, &pick, ContainerAction::Logs) {
        Ok((title, lines)) => {
            app.box_title = title;
            app.box_lines = lines;
        }
        Err(err) => app.box_lines = vec![err],
    }
}

fn action_applies(pick: &containers::Pick, action: ContainerAction) -> bool {
    match pick {
        containers::Pick::Container { .. } => true,
        _ => action == ContainerAction::Inspect,
    }
}

fn action_reject(pick: &containers::Pick, action: ContainerAction) -> String {
    let kind = match pick {
        containers::Pick::Volume { .. } => "存储卷",
        containers::Pick::Network { .. } => "网络",
        containers::Pick::Image { .. } => "镜像",
        containers::Pick::Container { .. } => "容器",
    };
    format!("{kind}不能{}", action_name(action))
}

fn pick_label(pick: &containers::Pick) -> String {
    match pick {
        containers::Pick::Container { id } => id.clone(),
        containers::Pick::Volume { name }
        | containers::Pick::Network { name }
        | containers::Pick::Image { name } => name.clone(),
    }
}

fn reset_box_view(app: &mut App) {
    app.box_cursor = 0;
    app.box_scroll = 0;
}

fn selected_pick(app: &App) -> Option<&containers::Pick> {
    app.container_picks.get(app.board_cursor)?.as_ref()
}

fn launch_container_exec(terminal: &mut Terminal<CrosstermBackend<Stdout>>, app: &mut App) -> Result<()> {
    let Some(pick) = selected_pick(app).cloned() else {
        app.box_title = "进入".into();
        app.box_lines = vec!["没有选中容器".into()];
        app.box_output = true;
        return Ok(());
    };
    let containers::Pick::Container { id } = &pick else {
        app.box_title = "进入".into();
        app.box_lines = vec!["只有容器可以进入".into()];
        app.box_output = true;
        reset_box_view(app);
        return Ok(());
    };
    let id = id.clone();
    if app.demo {
        app.box_title = "进入".into();
        app.box_lines = vec!["演示模式不会进入容器。".into()];
        app.box_output = true;
        reset_box_view(app);
        return Ok(());
    }
    let (bin, args) = match exec_args(&app.inventory.tool, &id) {
        Ok(cmd) => cmd,
        Err(err) => {
            app.box_title = "进入".into();
            app.box_lines = vec![err];
            app.box_output = true;
            reset_box_view(app);
            return Ok(());
        }
    };
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    let status = Command::new(bin).args(args).status();
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    terminal.clear()?;
    app.box_output = true;
    reset_box_view(app);
    app.box_title = format!("进入 {id}");
    app.box_lines = vec![match status {
        Ok(status) if status.success() => "已经从容器里返回".into(),
        Ok(status) => format!("退出码 {}", status.code().unwrap_or(-1)),
        Err(err) => format!("无法启动: {err}"),
    }];
    Ok(())
}

fn container_output(
    tool: &str,
    pick: &containers::Pick,
    action: ContainerAction,
) -> std::result::Result<(String, Vec<String>), String> {
    if tool.is_empty() {
        return Err("没有容器命令，不能执行这一步".into());
    }
    let args = action_args(tool, pick, action)?;
    let title = format!("{tool} {} {}", action_name(action), pick_label(pick));
    let output = Command::new(tool)
        .args(&args)
        .output()
        .map_err(|err| format!("无法运行 {tool}: {err}"))?;
    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    if text.trim().is_empty() {
        text = String::from_utf8_lossy(&output.stderr).to_string();
    }
    if matches!(action, ContainerAction::Inspect) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
            text = serde_json::to_string_pretty(&value).unwrap_or(text);
        }
    }
    let mut lines: Vec<String> = text.lines().map(board::plain_line).filter(|line| !line.is_empty()).collect();
    if lines.is_empty() {
        lines.push("命令没有输出".into());
    }
    if matches!(action, ContainerAction::Logs) {
        lines = keep_tail(lines, 200);
    } else if lines.len() > 400 {
        let extra = lines.len() - 400;
        lines.truncate(400);
        lines.push(format!("还有 {extra} 行没有放进这一页"));
    }
    Ok((title, lines))
}

fn action_args(
    tool: &str,
    pick: &containers::Pick,
    action: ContainerAction,
) -> std::result::Result<Vec<String>, String> {
    let label = pick_label(pick);
    if !containers::safe_ref(&label) {
        return Err("这个名字不能交给命令行".into());
    }
    if tool == "crictl" {
        return match (pick, action) {
            (containers::Pick::Container { id }, ContainerAction::Logs) => {
                Ok(vec!["logs".into(), "--tail".into(), "200".into(), id.clone()])
            }
            (containers::Pick::Container { id }, ContainerAction::Inspect) => Ok(vec!["inspect".into(), id.clone()]),
            (containers::Pick::Container { .. }, ContainerAction::Top) => Err("crictl 没有 top".into()),
            (containers::Pick::Container { id }, ContainerAction::Stats) => Ok(vec!["stats".into(), id.clone()]),
            (containers::Pick::Image { name }, ContainerAction::Inspect) => Ok(vec!["inspecti".into(), name.clone()]),
            _ => Err("crictl 不能对这一项做这个操作".into()),
        };
    }
    match (pick, action) {
        (containers::Pick::Container { id }, ContainerAction::Logs) => {
            Ok(vec!["logs".into(), "--tail".into(), "200".into(), id.clone()])
        }
        (containers::Pick::Container { id }, ContainerAction::Inspect) => Ok(vec!["inspect".into(), id.clone()]),
        (containers::Pick::Container { id }, ContainerAction::Top) => Ok(vec!["top".into(), id.clone()]),
        (containers::Pick::Container { id }, ContainerAction::Stats) => {
            Ok(vec!["stats".into(), "--no-stream".into(), id.clone()])
        }
        (containers::Pick::Volume { name }, ContainerAction::Inspect) => {
            Ok(vec!["volume".into(), "inspect".into(), name.clone()])
        }
        (containers::Pick::Network { name }, ContainerAction::Inspect) => {
            Ok(vec!["network".into(), "inspect".into(), name.clone()])
        }
        (containers::Pick::Image { name }, ContainerAction::Inspect) => {
            Ok(vec!["image".into(), "inspect".into(), name.clone()])
        }
        _ => Err("这一项不能做这个操作".into()),
    }
}

fn keep_tail(mut lines: Vec<String>, max: usize) -> Vec<String> {
    if lines.len() <= max {
        return lines;
    }
    let extra = lines.len() - max;
    lines.drain(0..extra);
    lines.insert(0, format!("前面还有 {extra} 行"));
    lines
}

fn exec_args(tool: &str, id: &str) -> std::result::Result<(String, Vec<String>), String> {
    if tool.is_empty() {
        return Err("没有容器命令，不能进入".into());
    }
    if !containers::safe_ref(id) {
        return Err("容器 ID 不能交给命令行".into());
    }
    Ok((tool.to_string(), vec!["exec".into(), "-it".into(), id.to_string(), "sh".into()]))
}

fn action_name(action: ContainerAction) -> &'static str {
    match action {
        ContainerAction::Logs => "日志",
        ContainerAction::Inspect => "查看",
        ContainerAction::Top => "进程",
        ContainerAction::Stats => "资源",
    }
}

struct Paint {
    text: String,
    color: Color,
}

enum ScrollSlot {
    Board,
    Box,
}

fn draw_scroll(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    title: &str,
    rows: Vec<Paint>,
    tail: bool,
    slot: ScrollSlot,
) {
    let rows = wrap_paints(rows, area.width.saturating_sub(2) as usize);
    let (mut cursor, mut scroll) = match slot {
        ScrollSlot::Board => (app.board_cursor, app.board_scroll),
        ScrollSlot::Box => (app.box_cursor, app.box_scroll),
    };
    if tail {
        cursor = rows.len().saturating_sub(1);
    }
    let viewport = area.height.saturating_sub(2) as usize;
    app.board_rows = rows.iter().map(|row| row.text.clone()).collect();
    let last = app.board_rows.len().saturating_sub(1);
    cursor = cursor.min(last);
    if cursor < scroll {
        scroll = cursor;
    }
    let view = viewport.max(1);
    if cursor >= scroll + view {
        scroll = cursor + 1 - view;
    }
    let max_scroll = rows.len().saturating_sub(view);
    scroll = scroll.min(max_scroll);
    match slot {
        ScrollSlot::Board => {
            app.board_cursor = cursor;
            app.board_scroll = scroll;
        }
        ScrollSlot::Box => {
            app.box_cursor = cursor;
            app.box_scroll = scroll;
        }
    }
    let title = if rows.len() > view {
        format!(" {title}  {}/{} ", cursor + 1, rows.len())
    } else {
        format!(" {title} ")
    };
    let title = plain_fit(&title, area.width.saturating_sub(2) as usize);
    let lines: Vec<Line> = rows
        .into_iter()
        .enumerate()
        .map(|(index, row)| {
            let style = if index == cursor {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(row.color)
            };
            Line::from(Span::styled(row.text, style))
        })
        .collect();
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((scroll as u16, 0))
            .block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

fn wrap_paints(rows: Vec<Paint>, width: usize) -> Vec<Paint> {
    let width = width.max(4);
    let mut out = Vec::new();
    for row in rows {
        let text = board::plain_line(&row.text);
        for part in wrap_text(&text, width) {
            out.push(Paint {
                text: part,
                color: row.color,
            });
        }
    }
    out
}

fn on_syslog_key(app: &mut App, key: KeyEvent) -> bool {
    if app.syslog_filtering {
        return on_syslog_filter_key(app, key);
    }
    match key.code {
        KeyCode::Char('q') => true,
        KeyCode::Esc => {
            if !app.syslog_unit.is_empty() {
                close_syslog_unit(app);
                false
            } else if !app.syslog_query.is_empty() {
                app.syslog_query.clear();
                app.board_cursor = 1;
                false
            } else {
                return_to_procs(app);
                false
            }
        }
        KeyCode::Enter => {
            open_syslog_unit(app);
            false
        }
        KeyCode::Char('/') => {
            app.syslog_filtering = true;
            false
        }
        KeyCode::Char(ch @ '1'..='8') => {
            app.syslog_kind = (ch as u8 - b'1') as usize;
            app.syslog_unit.clear();
            app.syslog_anchor = None;
            app.board_cursor = 0;
            app.board_scroll = 0;
            app.full_clear = true;
            load_syslog(app, true);
            false
        }
        _ => {
            let quit = on_scroll_key(app, key);
            if syslog_stream(app) {
                match key.code {
                    KeyCode::Char('G') => app.log_follow = true,
                    KeyCode::Char('g') | KeyCode::Char('k') | KeyCode::Up | KeyCode::PageUp => {
                        app.log_follow = false
                    }
                    KeyCode::Char('j') | KeyCode::Down | KeyCode::PageDown => {
                        let last = app.board_rows.len().saturating_sub(1);
                        app.log_follow = app.board_cursor >= last;
                    }
                    _ => {}
                }
            }
            quit
        }
    }
}

fn open_syslog_unit(app: &mut App) {
    if !app.syslog_unit.is_empty() {
        return;
    }
    let Some(line) = app.board_rows.get(app.board_cursor).cloned() else {
        return;
    };
    let Some(unit) = syslog::unit_name(&line) else {
        return;
    };
    app.syslog_anchor = Some(app.board_cursor);
    app.syslog_unit = unit;
    app.full_clear = true;
    load_syslog(app, true);
}

fn close_syslog_unit(app: &mut App) {
    let unit = app.syslog_unit.clone();
    let fallback = app.syslog_anchor.take();
    app.syslog_unit.clear();
    app.full_clear = true;
    load_syslog(app, false);
    if let Some(cursor) = syslog_row_for(app, &unit) {
        app.board_cursor = cursor;
    } else if let Some(cursor) = fallback {
        app.board_cursor = cursor;
    }
}

fn syslog_row_for(app: &App, unit: &str) -> Option<usize> {
    let matched: Vec<&String> = app
        .syslog_lines
        .iter()
        .filter(|line| sniff::query_match(line, &app.syslog_query))
        .collect();
    let pos = matched
        .iter()
        .position(|line| syslog::unit_name(line).as_deref() == Some(unit))?;
    Some(pos + 2)
}

fn on_syslog_filter_key(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => {
            app.syslog_filtering = false;
            app.syslog_query.clear();
            app.board_cursor = 1;
        }
        KeyCode::Enter => app.syslog_filtering = false,
        KeyCode::Backspace => {
            app.syslog_query.pop();
            app.board_cursor = 1;
        }
        KeyCode::Char(ch) if !ch.is_control() && !key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.syslog_query.push(ch);
            app.board_cursor = 1;
        }
        _ => {}
    }
    false
}

fn syslog_paints(app: &App, width: u16) -> Vec<Paint> {
    let width = width.saturating_sub(2) as usize;
    let kind = syslog::LogKind::from_index(app.syslog_kind);
    let mut rows = Vec::new();
    paint_section(&mut rows, kind.label(), width);
    rows.push(Paint {
        text: app.syslog_source.clone(),
        color: Color::DarkGray,
    });
    let matched: Vec<&String> = app
        .syslog_lines
        .iter()
        .filter(|line| sniff::query_match(line, &app.syslog_query))
        .collect();
    if matched.is_empty() {
        rows.push(Paint {
            text: if app.syslog_query.is_empty() {
                "这一类没有日志".into()
            } else {
                format!("没有符合 /{} 的日志", app.syslog_query)
            },
            color: Color::Yellow,
        });
        return rows;
    }
    for line in matched {
        rows.push(Paint {
            text: line.clone(),
            color: log_color(line),
        });
    }
    rows
}

fn log_color(line: &str) -> Color {
    if matches!(line, "失败的服务" | "最近的错误" | "审计拒绝") {
        return Color::Yellow;
    }
    if line.starts_with("没有") {
        return Color::DarkGray;
    }
    let lower = line.to_ascii_lowercase();
    if lower.contains("error")
        || lower.contains("fail")
        || lower.contains("crit")
        || lower.contains("emerg")
        || line.contains("错误")
        || line.contains("失败")
    {
        Color::Red
    } else if lower.contains("warn") || line.contains("警告") {
        Color::Yellow
    } else {
        Color::Cyan
    }
}

fn container_lines(app: &mut App, width: u16) -> Vec<Paint> {
    let width = width.saturating_sub(2) as usize;
    let inventory = app.inventory.clone();
    let mut rows = Vec::new();
    let mut picks = Vec::new();
    if !inventory.note.is_empty() {
        push_pick(&mut rows, &mut picks, inventory.note.clone(), Color::Yellow, None, width);
    } else if !inventory.tool.is_empty() {
        push_pick(
            &mut rows,
            &mut picks,
            format!("工具  {}", inventory.tool),
            Color::DarkGray,
            None,
            width,
        );
    }
    push_kind(
        &mut rows,
        &mut picks,
        "容器",
        &inventory.containers.iter().map(|item| item.state.clone()).collect::<Vec<_>>(),
        inventory.containers.is_empty(),
        if inventory.containers.is_empty() {
            "没有容器".into()
        } else {
            String::new()
        },
        width,
    );
    if !inventory.containers.is_empty() {
        push_pick(
            &mut rows,
            &mut picks,
            table_row(&[("状态", 12), ("名称", 18), ("镜像", 18), ("命令", 12)]),
            Color::DarkGray,
            None,
            width,
        );
        for item in &inventory.containers {
            let name = if item.name.is_empty() { item.id.as_str() } else { item.name.as_str() };
            let command = if item.command.is_empty() { "—" } else { item.command.as_str() };
            push_pick(
                &mut rows,
                &mut picks,
                table_row(&[
                    (item.state.as_str(), 12),
                    (name, 18),
                    (item.image.as_str(), 18),
                    (command, 12),
                ]),
                asset_color(&item.state),
                Some(containers::Pick::Container { id: item.id.clone() }),
                width,
            );
        }
    }
    push_asset_section(
        &mut rows,
        &mut picks,
        "存储卷",
        &inventory.volumes,
        &inventory.volume_note,
        "没有存储卷",
        width,
        |item| containers::Pick::Volume { name: item.name.clone() },
    );
    push_asset_section(
        &mut rows,
        &mut picks,
        "网络",
        &inventory.networks,
        &inventory.network_note,
        "没有网络",
        width,
        |item| containers::Pick::Network { name: item.name.clone() },
    );
    push_asset_section(
        &mut rows,
        &mut picks,
        "镜像",
        &inventory.images,
        &inventory.image_note,
        "没有镜像",
        width,
        |item| containers::Pick::Image { name: item.name.clone() },
    );
    if app.container_place {
        if let Some(index) = picks.iter().position(|pick| pick.is_some()) {
            app.board_cursor = index;
        }
        app.container_place = false;
    }
    app.container_picks = picks;
    rows
}

fn push_kind(
    rows: &mut Vec<Paint>,
    picks: &mut Vec<Option<containers::Pick>>,
    label: &str,
    states: &[String],
    empty: bool,
    empty_text: String,
    width: usize,
) {
    paint_section(rows, &containers::count_text(label, states), width);
    if let Some(last) = rows.last_mut() {
        last.text = fit_cols(&last.text, width.max(1));
    }
    picks.push(None);
    if empty && !empty_text.is_empty() {
        push_pick(rows, picks, empty_text, Color::Gray, None, width);
    }
}

fn push_asset_section(
    rows: &mut Vec<Paint>,
    picks: &mut Vec<Option<containers::Pick>>,
    label: &str,
    items: &[containers::Asset],
    note: &str,
    empty_text: &str,
    width: usize,
    pick: impl Fn(&containers::Asset) -> containers::Pick,
) {
    let states: Vec<String> = items.iter().map(|item| item.state.clone()).collect();
    push_kind(rows, picks, label, &states, items.is_empty(), String::new(), width);
    if items.is_empty() {
        let text = if note.is_empty() { empty_text.to_string() } else { note.to_string() };
        push_pick(rows, picks, text, Color::Gray, None, width);
        return;
    }
    push_pick(
        rows,
        picks,
        table_row(&[("状态", 12), ("名称", 24), ("信息", 12)]),
        Color::DarkGray,
        None,
        width,
    );
    for item in items {
        push_pick(
            rows,
            picks,
            table_row(&[
                (item.state.as_str(), 12),
                (item.name.as_str(), 24),
                (item.detail.as_str(), 12),
            ]),
            asset_color(&item.state),
            Some(pick(item)),
            width,
        );
    }
}

fn push_pick(
    rows: &mut Vec<Paint>,
    picks: &mut Vec<Option<containers::Pick>>,
    text: String,
    color: Color,
    pick: Option<containers::Pick>,
    width: usize,
) {
    rows.push(Paint {
        text: fit_cols(&board::plain_line(&text), width.max(1)),
        color,
    });
    picks.push(pick);
}

fn asset_color(state: &str) -> Color {
    match state {
        "running" | "in-use" | "active" => Color::Green,
        "exited" | "unused" | "idle" | "dangling" => Color::DarkGray,
        "paused" | "restarting" | "dead" => Color::Yellow,
        _ => Color::Cyan,
    }
}

fn firewall_lines(app: &App, width: u16) -> Vec<Paint> {
    let width = width.saturating_sub(2) as usize;
    let mut rows = Vec::new();
    paint_section(&mut rows, "概要", width);
    if app.firewall.lines.is_empty() {
        paint_field(&mut rows, "防火墙", "还没有读到", Color::Gray, width);
    } else {
        let pairs: Vec<(String, String, Color)> = app
            .firewall
            .lines
            .iter()
            .map(|(label, value)| (label.clone(), value.clone(), Color::Cyan))
            .collect();
        paint_pairs(&mut rows, &pairs, width);
    }
    paint_section(&mut rows, "规则", width);
    if app.firewall.rules.is_empty() {
        rows.push(Paint {
            text: app.firewall.rules_note.clone(),
            color: Color::Yellow,
        });
    } else {
        for rule in &app.firewall.rules {
            rows.push(Paint {
                text: rule.clone(),
                color: Color::Cyan,
            });
        }
    }
    rows
}

fn draw_network(frame: &mut Frame, app: &mut App, area: Rect) {
    match app.net_focus {
        NetFocus::Config => {
            draw_scroll(frame, app, area, "网络  配置", net_config_lines(app, area.width), false, ScrollSlot::Board)
        }
        NetFocus::Ifaces => draw_ifaces(frame, app, area),
        NetFocus::Capture => draw_capture(frame, app, area),
        NetFocus::Ssh => draw_ssh(frame, app, area),
        NetFocus::Bench => draw_bench(frame, app, area),
    }
}

fn net_config_lines(app: &App, width: u16) -> Vec<Paint> {
    let width = width.saturating_sub(2) as usize;
    let mut rows = Vec::new();
    paint_section(&mut rows, "路由", width);
    rows.push(Paint {
        text: table_row(&[("网卡", 18), ("目标", 22), ("经由", 16), ("跃点", 6)]),
        color: Color::DarkGray,
    });
    if app.net.routes.is_empty() && app.net.routes6.is_empty() {
        rows.push(Paint {
            text: "没有路由".into(),
            color: Color::Gray,
        });
    }
    for route in &app.net.routes {
        let metric = route.metric.to_string();
        rows.push(Paint {
            text: table_row(&[
                (route.iface.as_str(), 18),
                (route.destination.as_str(), 22),
                (route.gateway.as_str(), 16),
                (metric.as_str(), 6),
            ]),
            color: Color::Cyan,
        });
    }
    if !app.net.routes6.is_empty() {
        paint_section(&mut rows, "IPv6 路由", width);
        let via_w = if width >= 100 { 42 } else { 20 };
        rows.push(Paint {
            text: table_row(&[("网卡", 18), ("经由", via_w), ("IPv6 目标", 8)]),
            color: Color::DarkGray,
        });
        for route in &app.net.routes6 {
            rows.push(Paint {
                text: table_row(&[
                    (route.iface.as_str(), 18),
                    (route.gateway.as_str(), via_w),
                    (route.destination.as_str(), 8),
                ]),
                color: Color::Cyan,
            });
        }
    }
    nic_section(&mut rows, "物理网卡", &app.net, true, width);
    nic_section(&mut rows, "虚拟网卡", &app.net, false, width);
    paint_section(&mut rows, "内核参数", width);
    let pairs: Vec<(String, String, Color)> = app
        .net
        .sysctls
        .iter()
        .map(|item| (with_key(&item.label, &item.key), item.value.clone(), Color::Cyan))
        .collect();
    if pairs.is_empty() {
        paint_field(&mut rows, "参数", "读不到", Color::Gray, width);
    } else {
        paint_pairs(&mut rows, &pairs, width);
    }
    rows
}

fn nic_section(rows: &mut Vec<Paint>, title: &str, net: &board::NetConfig, physical: bool, width: usize) {
    paint_section(rows, title, width);
    rows.push(Paint {
        text: table_row(&[
            ("名称", 18),
            ("状态", 8),
            ("MAC", 18),
            ("MTU", 6),
            ("速率", 12),
            ("地址", 18),
        ]),
        color: Color::DarkGray,
    });
    let nics: Vec<_> = net.nics.iter().filter(|nic| nic.physical == physical).collect();
    if nics.is_empty() {
        rows.push(Paint {
            text: "没有".into(),
            color: Color::Gray,
        });
        return;
    }
    for nic in nics {
        let addrs: Vec<_> = net.addrs.iter().filter(|addr| addr.iface == nic.name).collect();
        let first = addrs
            .first()
            .map(|addr| format!("{} {}", addr.family, addr.addr))
            .unwrap_or_else(|| "没有地址".into());
        rows.push(Paint {
            text: table_row(&[
                (nic.name.as_str(), 18),
                (nic.state.as_str(), 8),
                (nic.mac.as_str(), 18),
                (nic.mtu.as_str(), 6),
                (nic.speed.as_str(), 12),
                (first.as_str(), 18),
            ]),
            color: Color::Cyan,
        });
        for addr in addrs.into_iter().skip(1) {
            let text = format!("{} {}", addr.family, addr.addr);
            rows.push(Paint {
                text: table_row(&[
                    ("", 18),
                    ("", 8),
                    ("", 18),
                    ("", 6),
                    ("", 12),
                    (text.as_str(), 18),
                ]),
                color: Color::Cyan,
            });
        }
    }
}

fn draw_ifaces(frame: &mut Frame, app: &mut App, area: Rect) {
    let mut lines = vec![Line::from("选择要看的网卡")];
    let labels: Vec<String> = std::iter::once("全部网卡".to_string())
        .chain(app.net.nics.iter().map(|nic| nic.name.clone()))
        .collect();
    let viewport = area.height.saturating_sub(3) as usize;
    let start = app.iface_cursor.saturating_sub(viewport / 2);
    let end = (start + viewport).min(labels.len());
    for (index, label) in labels.iter().enumerate().skip(start).take(end.saturating_sub(start)) {
        let style = if index == app.iface_cursor {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Cyan)
        };
        lines.push(Line::from(Span::styled(
            plain_fit(&format!("  {label}"), area.width.saturating_sub(2) as usize),
            style,
        )));
    }
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" 抓包 ")),
        area,
    );
}

fn draw_capture(frame: &mut Frame, app: &mut App, area: Rect) {
    if app.cap_detail {
        let item = select_packets(&app.packets, app.cap_filter, app.cap_abnormal, &app.cap_query)
            .get(app.packet_cursor)
            .map(|item| (*item).clone());
        draw_packet_detail(frame, app, area, item);
        return;
    }
    let packets = select_packets(&app.packets, app.cap_filter, app.cap_abnormal, &app.cap_query);
    let viewport = area.height.saturating_sub(2) as usize;
    let view = viewport.max(1);
    if app.packet_follow && !packets.is_empty() {
        app.packet_cursor = packets.len() - 1;
    }
    let last = packets.len().saturating_sub(1);
    app.packet_cursor = app.packet_cursor.min(last);
    if app.packet_cursor < app.packet_scroll {
        app.packet_scroll = app.packet_cursor;
    }
    if app.packet_cursor >= app.packet_scroll + view {
        app.packet_scroll = app.packet_cursor + 1 - view;
    }
    let max_scroll = packets.len().saturating_sub(view);
    app.packet_scroll = app.packet_scroll.min(max_scroll);
    let start = app.packet_scroll;
    let end = (start + view).min(packets.len());
    let mut lines = Vec::new();
    let inner = area.width.saturating_sub(2) as usize;
    if packets.is_empty() {
        push_wrapped(&mut lines, &app.cap_note, Style::default().fg(Color::Yellow), inner);
        push_wrapped(
            &mut lines,
            "等待报文。/ 筛选，x 只看异常，回车拆包。p 暂停后缓冲会留着。",
            Style::default(),
            inner,
        );
    } else {
        for (index, item) in packets.iter().enumerate().take(end).skip(start) {
            let style = if index == app.packet_cursor {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(packet_color(item))
            };
            lines.push(Line::from(Span::styled(plain_fit(&item.text, inner), style)));
        }
    }
    let state = if app.cap_paused { "已暂停" } else { "采集中" };
    let focus = if app.cap_abnormal { "只看异常" } else { app.cap_filter.label() };
    let query = if app.cap_query.is_empty() {
        String::new()
    } else {
        format!("  /{}", app.cap_query)
    };
    let title = plain_fit(
        &format!(
            " 抓包  {state}  {}  {focus}{query}  {} 条 ",
            app.cap_note,
            packets.len()
        ),
        area.width.saturating_sub(2) as usize,
    );
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

fn draw_packet_detail(frame: &mut Frame, _app: &mut App, area: Rect, item: Option<ShownPacket>) {
    let Some(item) = item else {
        frame.render_widget(
            Paragraph::new("没有符合条件的报文").block(Block::default().borders(Borders::ALL).title(" 拆包 ")),
            area,
        );
        return;
    };
    let width = area.width.saturating_sub(2) as usize;
    let mut lines = Vec::new();
    push_wrapped(
        &mut lines,
        &item.text,
        Style::default().fg(packet_color(&item)).add_modifier(Modifier::BOLD),
        width,
    );
    lines.push(Line::from(""));
    let state = if item.abnormal {
        format!("异常  {}", item.reason)
    } else {
        "正常".into()
    };
    push_wrapped(
        &mut lines,
        &state,
        Style::default().fg(if item.abnormal { Color::Red } else { Color::Green }),
        width,
    );
    lines.push(Line::from(""));
    if item.layers.is_empty() {
        lines.push(Line::from("没有拆出层次"));
    } else {
        for layer in &item.layers {
            push_wrapped(&mut lines, layer, Style::default().fg(Color::Cyan), width);
        }
    }
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" 拆包 ")),
        area,
    );
}

fn push_wrapped(lines: &mut Vec<Line<'static>>, text: &str, style: Style, width: usize) {
    let parts = safe_wrap(text, width);
    if parts.is_empty() {
        lines.push(Line::from(""));
        return;
    }
    for part in parts {
        lines.push(Line::from(Span::styled(part, style)));
    }
}

fn packet_color(item: &ShownPacket) -> Color {
    if item.abnormal {
        Color::Red
    } else if item.text.contains("SYN") {
        Color::Yellow
    } else {
        match item.kind {
            sniff::PacketKind::Tcp => Color::Cyan,
            sniff::PacketKind::Udp => Color::Blue,
            sniff::PacketKind::Icmp => Color::Magenta,
            sniff::PacketKind::Arp => Color::Gray,
            sniff::PacketKind::Other => Color::Gray,
        }
    }
}

fn draw_ssh(frame: &mut Frame, app: &App, area: Rect) {
    let host_style = if app.ssh_field == 0 {
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    };
    let port_style = if app.ssh_field == 1 {
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    };
    let host = if app.ssh_host.is_empty() {
        " ".into()
    } else {
        app.ssh_host.clone()
    };
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(format!("  主机  {host}"), host_style)),
        Line::from(""),
        Line::from(Span::styled(format!("  端口  {}", app.ssh_port), port_style)),
        Line::from(""),
        Line::from("  回车后交给系统 ssh。认证和主机密钥由 ssh 处理，这里不保存密码。"),
    ];
    if !app.ssh_error.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {}", app.ssh_error),
            Style::default().fg(Color::Red),
        )));
    }
    let width = area.width.saturating_sub(2) as usize;
    let lines = lines
        .into_iter()
        .flat_map(|line| {
            let text: String = line.spans.iter().map(|span| span.content.to_string()).collect();
            let style = line.spans.first().map(|span| span.style).unwrap_or_default();
            safe_wrap(&text, width)
                .into_iter()
                .map(move |part| Line::from(Span::styled(part, style)))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" SSH ")),
        area,
    );
}

fn draw_bench(frame: &mut Frame, app: &mut App, area: Rect) {
    let snap = app.bench.snap();
    let host_style = field_style(app.bench_field == 0 && !app.bench_listen);
    let port_style = field_style(app.bench_field == 1 || app.bench_listen);
    let sent_mib = bench::mebibytes_per_sec(snap.sent, snap.elapsed);
    let sent_mbps = bench::megabits_per_sec(snap.sent, snap.elapsed);
    let recv_mib = bench::mebibytes_per_sec(snap.recv, snap.elapsed);
    let recv_mbps = bench::megabits_per_sec(snap.recv, snap.elapsed);
    let role = if app.bench_listen { "监听" } else { "发起" };
    let host = if app.bench_host.is_empty() {
        " ".to_string()
    } else {
        app.bench_host.clone()
    };
    let mut lines = vec![
        Line::from(""),
        Line::from(format!("  协议    {}", app.bench_proto.label())),
        Line::from(format!("  角色    {role}")),
        Line::from(Span::styled(format!("  主机    {host}"), host_style)),
        Line::from(Span::styled(format!("  端口    {}", app.bench_port), port_style)),
        Line::from("  时长    10 秒"),
        Line::from(""),
        Line::from(Span::styled(
            format!("  发送吞吐    {sent_mib:.1} MiB/s"),
            Style::default().fg(Color::Cyan),
        )),
        Line::from(Span::styled(
            format!("  发送带宽    {sent_mbps:.1} Mbps"),
            Style::default().fg(Color::Yellow),
        )),
        Line::from(Span::styled(
            format!("  接收吞吐    {recv_mib:.1} MiB/s"),
            Style::default().fg(Color::Cyan),
        )),
        Line::from(Span::styled(
            format!("  接收带宽    {recv_mbps:.1} Mbps"),
            Style::default().fg(Color::Yellow),
        )),
        Line::from(format!(
            "  报文      发送 {}    接收 {}    丢包 {}",
            snap.sent_pkts, snap.recv_pkts, snap.lost
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("  状态    {}", snap.phase),
            Style::default().fg(if snap.error.is_empty() {
                Color::Green
            } else {
                Color::Red
            }),
        )),
        Line::from(""),
        Line::from("  对端要在同一端口选择监听。没有握手成功就不会发送测试数据。"),
    ];
    if app.bench_listen {
        lines[3] = Line::from(Span::styled("  主机    本机所有地址", Style::default().fg(Color::Gray)));
    }
    let width = area.width.saturating_sub(2) as usize;
    let lines = lines
        .into_iter()
        .flat_map(|line| {
            let text: String = line.spans.iter().map(|span| span.content.to_string()).collect();
            let style = line.spans.first().map(|span| span.style).unwrap_or_default();
            safe_wrap(&text, width)
                .into_iter()
                .map(move |part| Line::from(Span::styled(part, style)))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" 吞吐 ")),
        area,
    );
}

fn field_style(active: bool) -> Style {
    if active {
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    }
}

fn net_crumb(app: &App) -> &'static str {
    match app.net_focus {
        NetFocus::Config => "配置",
        NetFocus::Ifaces => "选择网卡",
        NetFocus::Capture => "抓包",
        NetFocus::Ssh => "SSH",
        NetFocus::Bench => "吞吐",
    }
}

fn net_footer(app: &App) -> String {
    match app.net_focus {
        NetFocus::Config => "1 配置  2 抓包  3 SSH  4 吞吐    j/k 选择  Esc 返回  q 退出".into(),
        NetFocus::Ifaces => "j/k 选择网卡  回车开始  a 全部  Esc 返回  q 退出".into(),
        NetFocus::Capture if app.cap_filtering => "筛选报文，多个词用空格隔开，回车确认，Esc 取消".into(),
        NetFocus::Capture if app.cap_detail => "j/k 上一条下一条  Esc 返回列表  q 退出".into(),
        NetFocus::Capture => "/ 模糊筛选  x 只看异常  回车拆包  n 下一个异常  p 暂停  t TCP  u UDP  i ICMP  a 全部".into(),
        NetFocus::Ssh => "输入主机和端口  Tab 切换  回车连接  Esc 返回".into(),
        NetFocus::Bench => "t TCP  u UDP  l 监听/发起  Tab 切换  回车开始  Esc 停止或返回".into(),
    }
}

fn draw(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    if area.height < 8 || area.width < 40 {
        frame.render_widget(Paragraph::new("终端至少需要 40 列、8 行"), area);
        return;
    }
        let head = if app.screen == Screen::Procs { 4 } else { 1 };
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(head),
            Constraint::Min(4),
            Constraint::Length(1),
        ])
        .split(area);
    app.page_rows = rows[2].height.saturating_sub(3) as usize;
    draw_status(frame, app, rows[0]);
    if app.screen == Screen::Procs {
        draw_proc_head(frame, app, rows[1]);
    } else {
        draw_crumb(frame, app, rows[1]);
    }
    match app.screen {
        Screen::Procs => draw_home(frame, app, rows[2]),
        Screen::Process => draw_process(frame, app, rows[2]),
        Screen::Logs => draw_logs(frame, app, rows[2]),
        Screen::Containers => {
            if app.box_output {
                let follow = app.box_action == Some(ContainerAction::Logs) && app.log_follow;
                let title = if follow {
                    format!("{}  跟踪", app.box_title)
                } else {
                    app.box_title.clone()
                };
                draw_scroll(
                    frame,
                    app,
                    rows[2],
                    &title,
                    plain_paints(&app.box_lines.clone()),
                    follow,
                    ScrollSlot::Box,
                );
            } else {
                let lines = container_lines(app, rows[2].width);
                draw_scroll(frame, app, rows[2], "容器", lines, false, ScrollSlot::Board);
            }
        }
        Screen::Firewall => {
            draw_scroll(frame, app, rows[2], "防火墙", firewall_lines(app, rows[2].width), false, ScrollSlot::Board)
        }
        Screen::Network => draw_network(frame, app, rows[2]),
        Screen::Syslog => {
            let follow = syslog_stream(app) && app.log_follow;
            let title = if follow { "日志  跟踪" } else { "日志" };
            let lines = syslog_paints(app, rows[2].width);
            draw_scroll(frame, app, rows[2], title, lines, follow, ScrollSlot::Board);
        }
    }
    draw_footer(frame, app, rows[3]);
    if app.help {
        draw_help(frame, area);
    }
}

fn draw_proc_head(frame: &mut Frame, app: &App, area: Rect) {
    let brief = hardware_brief(app);
    if area.width < 72 {
        let lines = brief
            .into_iter()
            .take(area.height as usize)
            .map(|row| hw_line(&row.0, &row.1, row.2, area.width as usize))
            .collect::<Vec<_>>();
        frame.render_widget(Paragraph::new(lines), area);
        return;
    }
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(36), Constraint::Length(42)])
        .split(area);
    let left = brief
        .into_iter()
        .take(columns[0].height as usize)
        .map(|row| hw_line(&row.0, &row.1, row.2, columns[0].width as usize))
        .collect::<Vec<_>>();
    let right = shortcut_lines(columns[1].height as usize, columns[1].width as usize);
    frame.render_widget(Paragraph::new(left), columns[0]);
    frame.render_widget(Paragraph::new(right), columns[1]);
}

fn hardware_brief(app: &App) -> Vec<(String, String, Color)> {
    let hw = &app.hardware;
    let host = format!("{}  {}", shown(&hw.product), shown(&hw.vendor));
    let serial = if hw.serial.trim().is_empty() {
        String::new()
    } else {
        format!("  SN {}", hw.serial.trim())
    };
    let mut rows = vec![
        ("主机".into(), format!("{host}{serial}"), Color::Cyan),
        ("CPU".into(), shown(&hw.cpu), Color::Cyan),
        ("磁盘".into(), disk_line(&hw.disks), Color::Cyan),
    ];
    rows.insert(0, verdict_brief(app));
    rows
}

fn disk_line(disks: &[board::HwDisk]) -> String {
    if disks.is_empty() {
        return "没有磁盘".into();
    }
    let total: u64 = disks.iter().map(|disk| disk.bytes).sum();
    let parts = disks
        .iter()
        .map(|disk| format!("{} {}", disk.name, capacity_text(disk.bytes)))
        .collect::<Vec<_>>()
        .join("   ");
    format!("共{} [ {} ]", capacity_text(total), parts)
}

fn capacity_text(bytes: u64) -> String {
    let gib = bytes as f64 / 1024.0 / 1024.0 / 1024.0;
    if gib >= 1.0 {
        format!("{gib:.1}GiB")
    } else if bytes >= 1024 * 1024 {
        format!("{:.0}MiB", bytes as f64 / 1024.0 / 1024.0)
    } else {
        format!("{bytes}B")
    }
}

fn verdict_brief(app: &App) -> (String, String, Color) {
    let Some(finding) = app.findings.first() else {
        return ("结论".into(), app.status.clone(), Color::Gray);
    };
    let action = advise::action(finding, &app.processes);
    let mut text = if matches!(finding.severity, Severity::Warning | Severity::Critical) {
        format!("{}  {}", finding.severity.label(), finding.title)
    } else {
        finding.title.clone()
    };
    if let Some(proc) = action.actors.first() {
        text.push_str(&format!("  {} {}", proc.comm, proc.pid));
    }
    if !app.filter.is_empty() {
        text.push_str(&format!("  /{}", app.filter));
    }
    ("结论".into(), text, severity_color(finding.severity))
}

fn hw_line(label: &str, value: &str, color: Color, width: usize) -> Line<'static> {
    Line::from(fit_spans(
        vec![
            Span::styled(
                format!("{}  ", pad_cols(label, 4)),
                Style::default().fg(Color::Gray),
            ),
            Span::styled(value.to_string(), Style::default().fg(color).add_modifier(Modifier::BOLD)),
        ],
        width,
    ))
}

fn shortcut_lines(rows: usize, width: usize) -> Vec<Line<'static>> {
    const GRID: &[&[(&str, &str)]] = &[
        &[("1", "容器"), ("/", "筛选")],
        &[("2", "防火墙"), ("回车", "下钻")],
        &[("3", "网络")],
        &[("4", "日志")],
    ];
    if rows == 0 {
        return Vec::new();
    }
    if rows == 1 {
        return vec![hint_line(
            &[("1", "容器"), ("2", "防火墙"), ("3", "网络"), ("4", "日志")],
            width,
        )];
    }
    GRID.iter().take(rows).map(|pairs| hint_line(pairs, width)).collect()
}

fn hint_line(pairs: &[(&str, &str)], width: usize) -> Line<'static> {
    let mut spans = Vec::new();
    for (index, (key, label)) in pairs.iter().enumerate() {
        if index > 0 {
            spans.push(Span::raw(" "));
        }
        spans.push(Span::styled(
            key_cell(key),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(label_cell(label), Style::default().fg(Color::White)));
    }
    Line::from(fit_spans(spans, width))
}

fn key_cell(key: &str) -> String {
    let pad = 4usize.saturating_sub(display_cols(key));
    let left = pad / 2;
    format!("{}{key}{}", " ".repeat(left), " ".repeat(pad - left))
}

fn label_cell(label: &str) -> String {
    format!(" {}", pad_cols(label, 6))
}

fn draw_home(frame: &mut Frame, app: &mut App, area: Rect) {
    let visible = visible_procs(app);
    place_cursor(app, &visible);
    let header = Row::new(vec![
        col_title("PID", SortKey::Pid, app),
        col_title("CPU", SortKey::Cpu, app),
        col_title("内存", SortKey::Mem, app),
        col_title("读", SortKey::Read, app),
        col_title("写", SortKey::Write, app),
        Cell::from("状态"),
        col_title("命令", SortKey::Name, app),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));
    let rows: Vec<Row> = visible
        .iter()
        .map(|proc| {
            Row::new(vec![
                Cell::from(proc.pid.to_string()),
                metric_cell(
                    procs::cpu_percent(proc.cpu_ratio),
                    heat_color(proc.cpu_ratio, 0.50, 0.90),
                ),
                metric_cell(procs::human_kb(proc.rss_kb), mem_color(app, proc.rss_kb)),
                metric_cell(
                    procs::human_bps(proc.read_bps),
                    heat_color(proc.read_bps, 1_000_000.0, 50_000_000.0),
                ),
                metric_cell(
                    procs::human_bps(proc.write_bps),
                    heat_color(proc.write_bps, 1_000_000.0, 50_000_000.0),
                ),
                metric_cell(proc.state.clone(), state_color(&proc.state)),
                Cell::from(board::plain_line(&procs::display_cmd(proc, 80))),
            ])
        })
        .collect();
    let title = process_title(&visible, area.width);
    let sort_hint = sort_title(area.width, &title);
    let table = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(7),
            Constraint::Min(12),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .title(sort_hint),
    )
    .highlight_spacing(HighlightSpacing::Never)
    .row_highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    );
    let selected = if visible.is_empty() {
        None
    } else {
        Some(app.cursor.min(visible.len() - 1))
    };
    app.table_state.select(selected);
    frame.render_stateful_widget(table, area, &mut app.table_state);
}

fn process_title(procs: &[ProcRate], width: u16) -> String {
    let states: Vec<String> = procs
        .iter()
        .map(|proc| proc.state.clone())
        .filter(|state| !state.is_empty())
        .collect();
    let summary = containers::tally(&states);
    let title = if summary.is_empty() {
        format!(" 进程  {} ", procs.len())
    } else {
        format!(" 进程  {}  {summary} ", procs.len())
    };
    let room = (width as usize).saturating_sub(36).max(18);
    fit_cols(&title, room)
}

fn sort_title(width: u16, left_title: &str) -> Line<'static> {
    let hint = " c CPU  m 内存  r 读  w 写  p PID  n 名字 ";
    let room = (width as usize).saturating_sub(display_cols(left_title) + 4);
    Line::from(Span::styled(
        fit_cols(hint, room),
        Style::default().fg(Color::DarkGray),
    ))
    .alignment(Alignment::Right)
}

fn draw_process(frame: &mut Frame, app: &mut App, area: Rect) {
    let Some(pid) = app.focus_pid else {
        frame.render_widget(Paragraph::new("没有选中的进程"), area);
        return;
    };
    let proc = app.processes.iter().find(|item| item.pid == pid).cloned();
    let Some(proc) = proc else {
        frame.render_widget(
            Paragraph::new(format!("pid {pid} 已经退出"))
                .block(Block::default().borders(Borders::ALL).title(" 进程 ")),
            area,
        );
        return;
    };
    let extra = focus_extra(app, &proc);
    let suggestion = advise::for_process(&proc, Some(&extra));
    let width = area.width.saturating_sub(2) as usize;
    let iface_lines = iface_view(app, pid, &extra);
    let mut text = Vec::new();
    push_section(&mut text, "身份", width);
    let runtime_color = if extra.runtime.starts_with("容器") {
        Color::Yellow
    } else {
        Color::Cyan
    };
    push_field(&mut text, "运行方式", &extra.runtime, runtime_color, width);
    push_field(&mut text, "命名空间", &extra.namespaces, Color::Cyan, width);
    let command = if proc.cmdline.is_empty() {
        format!("[{}]", proc.comm)
    } else {
        proc.cmdline.clone()
    };
    push_field(&mut text, "命令", &command, Color::White, width);
    push_field(&mut text, "进程", &proc.pid.to_string(), Color::Cyan, width);
    push_field(&mut text, "用户", &extra.user, Color::Cyan, width);
    push_field(&mut text, "父进程", &proc.ppid.to_string(), Color::Cyan, width);
    push_field(
        &mut text,
        "状态",
        &procs::state_label(&proc.state),
        state_color(&proc.state),
        width,
    );
    let wchan = if proc.wchan.is_empty() {
        "没有".to_string()
    } else {
        proc.wchan.clone()
    };
    push_field(&mut text, "等待", &wchan, state_color(&proc.state), width);
    push_section(&mut text, "CPU", width);
    push_field(
        &mut text,
        "CPU",
        &procs::cpu_percent(proc.cpu_ratio),
        heat_color(proc.cpu_ratio, 0.50, 0.90),
        width,
    );
    push_field(&mut text, "线程", &proc.threads.to_string(), Color::Cyan, width);
    push_field(
        &mut text,
        "自愿切换",
        &format!("{:.0}/s", proc.vol_ctxt_per_sec),
        Color::Cyan,
        width,
    );
    push_field(
        &mut text,
        "非自愿",
        &format!("{:.0}/s", proc.nonvol_ctxt_per_sec),
        Color::Cyan,
        width,
    );
    push_field(
        &mut text,
        "排队等待",
        &optional_ms(extra.runqueue_ms),
        Color::Cyan,
        width,
    );
    push_section(&mut text, "内存", width);
    push_field(
        &mut text,
        "RSS",
        &procs::human_kb(proc.rss_kb),
        mem_color(app, proc.rss_kb),
        width,
    );
    push_field(&mut text, "虚拟", &procs::human_kb(proc.vmsize_kb), Color::Cyan, width);
    push_field(&mut text, "峰值", &optional_kb(extra.vm_hwm_kb), Color::Cyan, width);
    push_field(&mut text, "匿名", &optional_kb(extra.rss_anon_kb), Color::Cyan, width);
    push_field(&mut text, "文件页", &optional_kb(extra.rss_file_kb), Color::Cyan, width);
    push_field(&mut text, "共享", &optional_kb(extra.rss_shmem_kb), Color::Cyan, width);
    push_field(&mut text, "数据段", &optional_kb(extra.vm_data_kb), Color::Cyan, width);
    push_field(&mut text, "页表", &optional_kb(extra.vm_pte_kb), Color::Cyan, width);
    push_field(
        &mut text,
        "换出",
        &procs::human_kb(proc.vmswap_kb),
        if proc.vmswap_kb > 0 { Color::Red } else { Color::Cyan },
        width,
    );
    push_section(&mut text, "磁盘", width);
    push_field(
        &mut text,
        "磁盘读",
        &procs::human_bps(proc.read_bps),
        heat_color(proc.read_bps, 1_000_000.0, 50_000_000.0),
        width,
    );
    push_field(
        &mut text,
        "磁盘写",
        &procs::human_bps(proc.write_bps),
        heat_color(proc.write_bps, 1_000_000.0, 50_000_000.0),
        width,
    );
    push_field(&mut text, "累计读", &optional_bytes(extra.read_bytes), Color::Cyan, width);
    push_field(&mut text, "累计写", &optional_bytes(extra.write_bytes), Color::Cyan, width);
    push_field(&mut text, "读调用", &optional_count(extra.syscr), Color::Cyan, width);
    push_field(&mut text, "写调用", &optional_count(extra.syscw), Color::Cyan, width);
    push_field(&mut text, "块等待", &optional_secs(extra.blkio_secs), Color::Cyan, width);
    push_section(&mut text, "网络", width);
    let net = &extra.net;
    push_field(
        &mut text,
        "套接字",
        &format!(
            "已建立 {}    监听 {}    等关闭 {}    时间等待 {}    握手 {}    UDP {}",
            net.established, net.listen, net.close_wait, net.time_wait, net.syn, net.udp
        ),
        if net.close_wait >= 5 { Color::Yellow } else { Color::Cyan },
        width,
    );
    push_field(
        &mut text,
        "重传",
        &net.retrans.to_string(),
        if net.retrans > 0 { Color::Yellow } else { Color::Cyan },
        width,
    );
    push_field(
        &mut text,
        "收队列",
        &procs::human_bytes(net.rx_queue),
        Color::Cyan,
        width,
    );
    push_field(
        &mut text,
        "发队列",
        &procs::human_bytes(net.tx_queue),
        Color::Cyan,
        width,
    );
    let nic_label = if extra.netns_private {
        "容器网卡"
    } else {
        "主机网卡"
    };
    if iface_lines.is_empty() {
        push_field(&mut text, nic_label, "读不到", Color::Gray, width);
    } else {
        for (index, line) in iface_lines.iter().enumerate() {
            let label = if index == 0 { nic_label } else { "" };
            let color = if packet_hot(line) {
                Color::Yellow
            } else {
                Color::Cyan
            };
            push_field(&mut text, label, line, color, width);
        }
        if iface_lines.iter().any(|line| packet_hot(line)) {
            push_field(
                &mut text,
                "",
                "数据包异常记在网卡上。溢出是队列满，帧错和载波是链路损坏，冲突少见。这和某个套接字的重传不是同一件事。",
                Color::Yellow,
                width,
            );
        }
        if !extra.netns_private {
            push_field(
                &mut text,
                "",
                "主机进程和整机共用这个网络命名空间，网卡计数不是这个进程独占的。下面的连接才只属于它。",
                Color::Gray,
                width,
            );
        }
    }
    if net.sockets.is_empty() {
        push_field(&mut text, "连接", "没有套接字", Color::Gray, width);
    } else {
        for (index, line) in net.sockets.iter().enumerate() {
            let label = if index == 0 { "连接" } else { "" };
            let color = if line.contains("等关闭") || line.contains("重传") && !line.contains("重传 0") {
                Color::Yellow
            } else {
                Color::Cyan
            };
            push_field(&mut text, label, line, color, width);
        }
        if net.hidden > 0 {
            push_field(
                &mut text,
                "",
                &format!("还有 {} 条连接，汇总数字已经包含它们", net.hidden),
                Color::Gray,
                width,
            );
        }
    }
    if !net.note.is_empty() {
        push_field(&mut text, "网络判断", &net.note, Color::Yellow, width);
    }
    push_section(&mut text, "限制", width);
    let fds = match (extra.fd_count, extra.nofile_soft) {
        (Some(count), Some(limit)) => format!(
            "{count} / 软限制 {limit}    文件 {}    套接字 {}    管道 {}",
            extra.fd_files, extra.fd_sockets, extra.fd_pipes
        ),
        (Some(count), None) => format!(
            "{count}    文件 {}    套接字 {}    管道 {}",
            extra.fd_files, extra.fd_sockets, extra.fd_pipes
        ),
        _ => "读不到".into(),
    };
    push_field(&mut text, "描述符", &fds, fd_color(&extra), width);
    let cgroup = if extra.cgroup.is_empty() {
        "没有".to_string()
    } else {
        extra.cgroup.clone()
    };
    push_field(&mut text, "cgroup", &cgroup, Color::Gray, width);
    match &extra.stack {
        Some(stack) => {
            for (index, line) in stack.lines().enumerate() {
                let label = if index == 0 { "内核栈" } else { "" };
                push_field(&mut text, label, line, Color::Cyan, width);
            }
        }
        None => push_field(
            &mut text,
            "内核栈",
            "读不到。需要 root 或 CAP_SYS_PTRACE 才能看 /proc/<pid>/stack",
            Color::Gray,
            width,
        ),
    }
    push_section(&mut text, "建议", width);
    push_field(&mut text, "建议", &suggestion, advice_color(&proc), width);
    let viewport = area.height.saturating_sub(2) as usize;
    let max_scroll = text.len().saturating_sub(viewport.max(1));
    app.process_scroll = app.process_scroll.min(max_scroll);
    let title = if text.len() > viewport {
        format!(" 实时  {}/{} ", app.process_scroll + 1, text.len())
    } else {
        " 实时 ".into()
    };
    frame.render_widget(
        Paragraph::new(text)
            .scroll((app.process_scroll as u16, 0))
            .block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

fn draw_logs(frame: &mut Frame, app: &mut App, area: Rect) {
    let inner_height = area.height.saturating_sub(2) as usize;
    let lines = log_window(&app.log_lines, inner_height, app.log_from_bottom);
    let width = area.width.saturating_sub(2) as usize;
    let body: Vec<Line> = if lines.is_empty() {
        safe_wrap(&app.log_note, width).into_iter().map(Line::from).collect()
    } else {
        lines
            .into_iter()
            .flat_map(|line| safe_wrap(&line, width).into_iter().map(Line::from))
            .collect()
    };
    let mark = if app.log_follow { "  跟踪" } else { "" };
    let title = plain_fit(&format!(" 日志  {}{mark} ", app.log_note), width);
    frame.render_widget(
        Paragraph::new(body).block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

fn log_window(lines: &[String], height: usize, from_bottom: usize) -> Vec<String> {
    if lines.is_empty() || height == 0 {
        return Vec::new();
    }
    let height = height.min(lines.len());
    let max_from_bottom = lines.len().saturating_sub(height);
    let from_bottom = from_bottom.min(max_from_bottom);
    let end = lines.len().saturating_sub(from_bottom);
    let start = end.saturating_sub(height);
    lines[start..end].to_vec()
}

fn draw_crumb(frame: &mut Frame, app: &App, area: Rect) {
    let line = match app.screen {
        Screen::Procs => verdict_line(app),
        Screen::Containers => {
            let tool = if app.inventory.tool.is_empty() {
                "无命令"
            } else {
                app.inventory.tool.as_str()
            };
            Line::from(format!(" 容器  {tool}"))
        }
        Screen::Firewall => Line::from(" 防火墙"),
        Screen::Network => Line::from(format!(" 网络  {}", net_crumb(app))),
        Screen::Syslog => {
            let label = if app.syslog_unit.is_empty() {
                syslog::LogKind::from_index(app.syslog_kind).label().to_string()
            } else {
                format!("{}  {}", syslog::LogKind::from_index(app.syslog_kind).label(), app.syslog_unit)
            };
            Line::from(format!(" 日志  {label}  {}", app.syslog_source))
        }
        Screen::Process => Line::from(format!(" {}", focus_title(app, "进程"))),
        Screen::Logs => Line::from(format!(" {}", focus_title(app, "日志"))),
    };
    let mut line = line;
    line.spans = fit_spans(line.spans, area.width as usize);
    frame.render_widget(Paragraph::new(line), area);
}

fn focus_title(app: &App, kind: &str) -> String {
    let Some(pid) = app.focus_pid else {
        return kind.into();
    };
    match app.processes.iter().find(|proc| proc.pid == pid) {
        Some(proc) => format!("{kind}  {}  {pid}", proc.comm),
        None => format!("{kind}  pid {pid}  已退出"),
    }
}

fn verdict_line(app: &App) -> Line<'static> {
    let Some(finding) = app.findings.first() else {
        return Line::from(format!(" {}", app.status));
    };
    let color = severity_color(finding.severity);
    let action = advise::action(finding, &app.processes);
    let mut spans = vec![
        Span::raw(" "),
        Span::styled(
            finding.severity.label(),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("  {}", finding.title), Style::default().fg(color)),
    ];
    if let Some(proc) = action.actors.first() {
        spans.push(Span::styled(
            format!("  {} {}", proc.comm, proc.pid),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
    }
    if !app.filter.is_empty() {
        spans.push(Span::styled(
            format!("  /{}", app.filter),
            Style::default().fg(Color::Cyan),
        ));
    }
    Line::from(spans)
}

fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let text = if app.filtering {
        "输入筛选，回车确认，Esc 清除".to_string()
    } else {
        match app.screen {
            Screen::Firewall => "j/k 选择  Esc 返回进程  q 退出".to_string(),
            Screen::Syslog if app.syslog_filtering => "筛选日志，多个词用空格隔开，回车确认，Esc 取消".to_string(),
            Screen::Syslog if syslog_stream(app) && app.log_follow => {
                "跟踪中  k 往上停住  G 继续跟踪  / 筛选  Esc 返回".to_string()
            }
            Screen::Syslog if syslog_stream(app) => "已停住跟踪  G 继续跟踪  / 筛选  Esc 返回".to_string(),
            Screen::Syslog => "1 快捷  2 审计  3 系统服务  4 内核  5 系统  6 认证  7 服务  8 定时  回车看服务日志  / 筛选".to_string(),
            Screen::Containers if app.box_output && app.box_action == Some(ContainerAction::Logs) && app.log_follow => {
                "跟踪中  k 往上停住  G 继续跟踪  Esc 返回  q 退出".to_string()
            }
            Screen::Containers if app.box_output && app.box_action == Some(ContainerAction::Logs) => {
                "已停住跟踪  G 继续跟踪  Esc 返回  q 退出".to_string()
            }
            Screen::Containers if app.box_output => "j/k 选择  Esc 返回列表  q 退出".to_string(),
            Screen::Containers => "j/k 选择  l 日志  i 查看  t 进程  s 资源  e 进入  Esc 返回  q 退出".to_string(),
            Screen::Procs => "j/k 移动  回车下钻  1 容器  2 防火墙  3 网络  4 日志  / 筛选  q 退出".to_string(),
            Screen::Process => "j/k 翻阅  l 日志  Esc 返回  q 退出".to_string(),
            Screen::Logs if app.log_follow => "跟踪中  k 往上停住  G 继续跟踪  Esc 返回  q 退出".to_string(),
            Screen::Logs => "已停住跟踪  G 继续跟踪  Esc 返回  q 退出".to_string(),
            Screen::Network => net_footer(app),
        }
    };
    let text = plain_fit(&format!(" {text}"), area.width as usize);
    frame.render_widget(
        Paragraph::new(text).style(Style::default().fg(Color::DarkGray)),
        area,
    );
}

fn draw_help(frame: &mut Frame, area: Rect) {
    let width = area.width.min(72);
    let height = area.height.min(16);
    let help_area = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    let inner = help_area.width.saturating_sub(2) as usize;
    let raw = [
        "打开就是进程页。左上角是硬件，右边是功能键",
        "1 容器  2 防火墙  3 网络  4 日志。Esc 回到进程",
        "j/k 移动，回车下钻，l 看这个进程的日志",
        "c m r w p n 排序。/ 筛选，空格表示都要出现",
        "顶部 load 依次是 1 分钟、5 分钟、15 分钟",
        "抓包：/ 筛选  x 异常  回车拆包  p 暂停。缓冲暂停后保留",
        "日志默认跟踪到最新，k 往上停住，G 继续跟踪。服务日志也一样",
        "容器用本机 docker、podman、nerdctl 或 crictl，含存储卷、网络和镜像",
        "容器：l 日志  i 查看  t 进程  s 资源  e 进入。卷、网络、镜像可以查看",
        "SSH 交给系统 ssh，这里不保存密码",
        "Esc 返回上一层，q 退出",
        "",
        "? 或 Esc 关闭",
    ];
    let text: Vec<Line> = raw
        .into_iter()
        .flat_map(|line| safe_wrap(line, inner).into_iter().map(Line::from))
        .collect();
    frame.render_widget(ratatui::widgets::Clear, help_area);
    frame.render_widget(
        Paragraph::new(text).block(Block::default().borders(Borders::ALL).title(" 帮助 ")),
        help_area,
    );
}

fn focus_extra(app: &App, proc: &ProcRate) -> ProcExtra {
    if app.demo {
        let cgroup = demo_unit(proc)
            .map(|unit| format!("/system.slice/{unit}"))
            .unwrap_or_else(|| "/user.slice/session.scope".into());
        let (runtime, namespaces) = procs::describe_runtime(&cgroup, &[]);
        return ProcExtra {
            user: if proc.uid == 0 {
                "root".into()
            } else {
                proc.uid.to_string()
            },
            cgroup,
            fd_count: Some(12),
            nofile_soft: Some(1024),
            stack: if proc.state.starts_with('D') {
                Some(format!("{}\nio_schedule", proc.wchan))
            } else {
                None
            },
            runtime,
            namespaces,
            netns_private: false,
            rss_anon_kb: Some(proc.rss_kb / 2),
            rss_file_kb: Some(proc.rss_kb / 2),
            rss_shmem_kb: Some(0),
            vm_hwm_kb: Some(proc.rss_kb),
            vm_data_kb: Some(proc.vmsize_kb / 4),
            vm_pte_kb: Some(128),
            read_bytes: Some(proc.read_bps as u64),
            write_bytes: Some(proc.write_bps as u64),
            syscr: Some(10),
            syscw: Some(4),
            blkio_secs: if proc.state.starts_with('D') { Some(1.2) } else { Some(0.0) },
            runqueue_ms: Some(3.0),
            fd_files: 4,
            fd_sockets: 6,
            fd_pipes: 2,
            net: demo_net(&proc.comm),
        };
    }
    procs::extra(proc.pid)
}

fn demo_net(comm: &str) -> procs::ProcNet {
    let mut net = procs::ProcNet::empty();
    match comm {
        "nginx" => {
            net.listen = 1;
            net.established = 2;
            net.sockets = vec![
                "0.0.0.0:80               监听      未取走 0B".into(),
                "10.0.0.8:80           ← 10.1.2.3:45211          已建立    重传 0  收 0B  发 0B".into(),
            ];
            net.ifaces = vec![procs::IfaceCount {
                name: "eth0".into(),
                rx_bytes: 8_000_000,
                tx_bytes: 2_000_000,
                drops: 0,
                errs: 0,
                fifo: 0,
                frame: 0,
                carrier: 0,
                colls: 0,
            }];
        }
        "postgres" => {
            net.listen = 1;
            net.sockets = vec!["0.0.0.0:5432             监听      未取走 0B".into()];
            net.ifaces = vec![procs::IfaceCount {
                name: "eth0".into(),
                rx_bytes: 1_000_000,
                tx_bytes: 1_000_000,
                drops: 0,
                errs: 0,
                fifo: 0,
                frame: 0,
                carrier: 0,
                colls: 0,
            }];
        }
        "sshd" => {
            net.listen = 1;
            net.established = 1;
            net.sockets = vec![
                "0.0.0.0:22               监听      未取走 0B".into(),
                "10.0.0.8:22           ← 10.1.2.9:60022          已建立    重传 0  收 0B  发 0B".into(),
            ];
        }
        _ => {}
    }
    net
}

fn visible_procs(app: &App) -> Vec<ProcRate> {
    let mut rows: Vec<_> = app
        .processes
        .iter()
        .filter(|proc| procs::matches(proc, &app.filter))
        .cloned()
        .collect();
    sort_rows(&mut rows, app.sort_key, app.descending);
    rows
}

fn place_cursor(app: &mut App, visible: &[ProcRate]) {
    if visible.is_empty() {
        app.cursor = 0;
        return;
    }
    if let Some(pid) = app.home_pid {
        if let Some(index) = visible.iter().position(|proc| proc.pid == pid) {
            app.cursor = index;
            return;
        }
    }
    app.cursor = 0;
    app.home_pid = Some(visible[0].pid);
}

fn sort_rows(rows: &mut [ProcRate], key: SortKey, descending: bool) {
    rows.sort_by(|left, right| {
        let ordering = match key {
            SortKey::Cpu => cmp_f64(left.cpu_ratio, right.cpu_ratio),
            SortKey::Mem => left.rss_kb.cmp(&right.rss_kb),
            SortKey::Read => cmp_f64(left.read_bps, right.read_bps),
            SortKey::Write => cmp_f64(left.write_bps, right.write_bps),
            SortKey::Pid => left.pid.cmp(&right.pid),
            SortKey::Name => left
                .comm
                .cmp(&right.comm)
                .then(left.pid.cmp(&right.pid)),
        };
        if descending {
            ordering.reverse()
        } else {
            ordering
        }
    });
}

fn cmp_f64(left: f64, right: f64) -> Ordering {
    left.partial_cmp(&right).unwrap_or(Ordering::Equal)
}

fn col_title(label: &str, key: SortKey, app: &App) -> Cell<'static> {
    if app.sort_key != key {
        return Cell::from(label.to_string());
    }
    let mark = if app.descending { "▼" } else { "▲" };
    Cell::from(format!("{label}{mark}")).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let cpu_ratio = app.rates.as_ref().map(|rates| rates.cpu.busy_ratio);
    let mem_ratio = mem_used(app);
    let io_ratio = app.rates.as_ref().map(|rates| {
        rates
            .disks
            .iter()
            .map(|disk| disk.util)
            .fold(0.0, f64::max)
            .clamp(0.0, 1.0)
    });
    let cpu = match app.rates.as_ref() {
        Some(rates) => {
            let ncpu = rates.cpu.ncpu.max(1);
            let used = rates.cpu.busy_ratio * ncpu as f64;
            format!("{:.0}%({used:.1}核/{ncpu}核)", rates.cpu.busy_ratio * 100.0)
        }
        None => "…".into(),
    };
    let mem = match mem_amounts(app) {
        Some((used, total)) => {
            let ratio = used as f64 / total.max(1) as f64;
            format!(
                "{:.0}%({}/{})",
                ratio * 100.0,
                capacity_text(used.saturating_mul(1024)),
                capacity_text(total.saturating_mul(1024))
            )
        }
        None => "…".into(),
    };
    let io = io_ratio
        .map(|ratio| format!("{:3.0}%", ratio * 100.0))
        .unwrap_or_else(|| "  …".into());
    let (down, up) = app
        .rates
        .as_ref()
        .map(|rates| {
            let rx: f64 = rates.nets.iter().map(|net| net.rx_bytes_per_sec).sum();
            let tx: f64 = rates.nets.iter().map(|net| net.tx_bytes_per_sec).sum();
            (procs::human_bps(rx), procs::human_bps(tx))
        })
        .unwrap_or_else(|| ("…".into(), "…".into()));
    let (load1, load5, load15, ncpu) = app
        .rates
        .as_ref()
        .map(|rates| (rates.load1, rates.load5, rates.load15, rates.cpu.ncpu.max(1) as f64))
        .unwrap_or((0.0, 0.0, 0.0, 1.0));
    let load_known = app.rates.is_some();
    let line = Line::from(fit_spans(
        vec![
            bar_span(" CPU ", Color::Cyan),
            bar_span(
                cpu,
                cpu_ratio
                    .map(|ratio| heat_into(ratio, 0.50, 0.80, Color::Green))
                    .unwrap_or(Color::Green),
            ),
            bar_span(" │ MEM ", Color::Magenta),
            bar_span(
                mem,
                mem_ratio
                    .map(|ratio| heat_into(ratio, 0.70, 0.90, Color::Blue))
                    .unwrap_or(Color::Blue),
            ),
            bar_span(" │ IO ", Color::Yellow),
            bar_span(
                io,
                io_ratio
                    .map(|ratio| heat_into(ratio, 0.50, 0.90, Color::Cyan))
                    .unwrap_or(Color::Cyan),
            ),
            bar_span(" │ ↓", Color::Green),
            bar_span(down, Color::Green),
            bar_span(" ↑", Color::Blue),
            bar_span(up, Color::Blue),
            bar_span(" │ load ", Color::White),
            bar_span(
                if load_known { format!("{load1:.2}") } else { "…".into() },
                heat_into(load1, ncpu * 0.70, ncpu, Color::White),
            ),
            bar_span(" ", Color::DarkGray),
            bar_span(
                if load_known { format!("{load5:.2}") } else { "…".into() },
                heat_into(load5, ncpu * 0.70, ncpu, Color::White),
            ),
            bar_span(" ", Color::DarkGray),
            bar_span(
                if load_known { format!("{load15:.2}") } else { "…".into() },
                heat_into(load15, ncpu * 0.70, ncpu, Color::White),
            ),
            bar_span(
                format!(" │ 开机 {} │ {} │ {} ", uptime_text(), local_clock(), app.host_line),
                Color::Gray,
            ),
        ],
        area.width as usize,
    ));
    frame.render_widget(
        Paragraph::new(line).style(Style::default().bg(Color::DarkGray)),
        area,
    );
}

fn bar_span(text: impl Into<String>, fg: Color) -> Span<'static> {
    Span::styled(text.into(), Style::default().fg(fg).bg(Color::DarkGray))
}

fn metric_cell(text: impl Into<String>, color: Color) -> Cell<'static> {
    Cell::from(text.into()).style(Style::default().fg(color))
}

fn push_field(lines: &mut Vec<Line<'static>>, label: &str, value: &str, color: Color, width: usize) {
    let value = board::plain_line(value);
    let value = value.as_str();
    let label = pad_cols(label, 10);
    let value_width = width.saturating_sub(10).max(8);
    let wrapped = wrap_text(value, value_width);
    let indent = " ".repeat(10);
    for (index, part) in wrapped.into_iter().enumerate() {
        let prefix = if index == 0 {
            label.clone()
        } else {
            indent.clone()
        };
        lines.push(Line::from(vec![
            Span::styled(prefix, Style::default().fg(Color::DarkGray)),
            Span::styled(part, Style::default().fg(color).add_modifier(Modifier::BOLD)),
        ]));
    }
}

fn with_key(label: &str, key: &str) -> String {
    format!("{label} ({key})")
}

fn section_bar(title: &str, width: usize) -> String {
    let label = format!(" {title} ");
    let used = display_cols(&label);
    let room = width.max(used + 8);
    let extra = room.saturating_sub(used);
    let left = 3.min(extra);
    format!("{}{label}{}", "━".repeat(left), "━".repeat(extra - left))
}

fn paint_section(rows: &mut Vec<Paint>, title: &str, width: usize) {
    rows.push(Paint {
        text: section_bar(title, width),
        color: Color::Yellow,
    });
}

fn push_section(lines: &mut Vec<Line<'static>>, title: &str, width: usize) {
    lines.push(Line::from(Span::styled(
        section_bar(title, width),
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )));
}

fn paint_pairs(rows: &mut Vec<Paint>, pairs: &[(String, String, Color)], width: usize) {
    let pad = pairs
        .iter()
        .map(|(label, _, _)| display_cols(label))
        .max()
        .unwrap_or(10);
    let value_width = width.saturating_sub(pad + 2).max(8);
    for (label, value, color) in pairs {
        let padded = pad_cols(label, pad);
        for (index, part) in wrap_text(value, value_width).into_iter().enumerate() {
            let prefix = if index == 0 {
                padded.clone()
            } else {
                " ".repeat(pad)
            };
            rows.push(Paint {
                text: format!("{prefix}  {part}"),
                color: *color,
            });
        }
    }
}

fn paint_field(rows: &mut Vec<Paint>, label: &str, value: &str, color: Color, width: usize) {
    let label = pad_cols(label, 10);
    let value_width = width.saturating_sub(12).max(8);
    for (index, part) in wrap_text(value, value_width).into_iter().enumerate() {
        let prefix = if index == 0 {
            label.clone()
        } else {
            " ".repeat(10)
        };
        rows.push(Paint {
            text: format!("{prefix}  {part}"),
            color,
        });
    }
}

fn table_row(cells: &[(&str, usize)]) -> String {
    let mut out = String::new();
    for (index, (text, width)) in cells.iter().enumerate() {
        if index > 0 {
            out.push_str("  ");
        }
        if index + 1 == cells.len() {
            out.push_str(text);
        } else {
            out.push_str(&pad_cols(&fit_cols(text, *width), *width));
        }
    }
    out
}

fn shown(text: &str) -> String {
    if text.trim().is_empty() {
        "读不到".into()
    } else {
        text.to_string()
    }
}

fn fit_cols(text: &str, cols: usize) -> String {
    if cols == 0 {
        return String::new();
    }
    let mut out = String::new();
    let mut used = 0usize;
    for ch in text.chars() {
        let width = char_cols(ch);
        if used + width > cols {
            break;
        }
        out.push(ch);
        used += width;
    }
    out
}

fn plain_paints(lines: &[String]) -> Vec<Paint> {
    if lines.is_empty() {
        return vec![Paint {
            text: "没有输出".into(),
            color: Color::Gray,
        }];
    }
    lines
        .iter()
        .map(|line| Paint {
            text: line.clone(),
            color: Color::Cyan,
        })
        .collect()
}

fn pad_cols(text: &str, cols: usize) -> String {
    let mut out = text.to_string();
    let mut width = display_cols(&out);
    while width < cols {
        out.push(' ');
        width += 1;
    }
    out
}

fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    if text.is_empty() {
        return vec![String::new()];
    }
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut cols = 0usize;
    for token in split_wrap_tokens(text) {
        let token_cols = display_cols(&token);
        if cols > 0 && cols + token_cols > width {
            lines.push(std::mem::take(&mut current));
            cols = 0;
        }
        if cols == 0 && token_cols > width {
            let mut buf = String::new();
            let mut used = 0usize;
            for ch in token.chars() {
                let ch_cols = char_cols(ch);
                if used + ch_cols > width && !buf.is_empty() {
                    lines.push(std::mem::take(&mut buf));
                    used = 0;
                }
                buf.push(ch);
                used += ch_cols;
            }
            current = buf;
            cols = used;
        } else {
            current.push_str(&token);
            cols += token_cols;
        }
    }
    if !current.is_empty() || lines.is_empty() {
        lines.push(current);
    }
    lines
}

fn split_wrap_tokens(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut buf = String::new();
    for ch in text.chars() {
        buf.push(ch);
        if ch == ' ' {
            tokens.push(std::mem::take(&mut buf));
        }
    }
    if !buf.is_empty() {
        tokens.push(buf);
    }
    tokens
}

fn display_cols(text: &str) -> usize {
    text.chars().map(char_cols).sum()
}

fn char_cols(ch: char) -> usize {
    let code = ch as u32;
    if code >= 0x2E80 || (0x1100..=0x115F).contains(&code) || (0xAC00..=0xD7A3).contains(&code) {
        2
    } else {
        1
    }
}

fn optional_kb(value: Option<u64>) -> String {
    value.map(procs::human_kb).unwrap_or_else(|| "读不到".into())
}

fn optional_bytes(value: Option<u64>) -> String {
    value.map(procs::human_bytes).unwrap_or_else(|| "读不到".into())
}

fn optional_count(value: Option<u64>) -> String {
    value.map(|count| count.to_string()).unwrap_or_else(|| "读不到".into())
}

fn optional_ms(value: Option<f64>) -> String {
    value
        .map(|ms| format!("累计 {ms:.0} ms"))
        .unwrap_or_else(|| "读不到".into())
}

fn optional_secs(value: Option<f64>) -> String {
    value
        .map(|secs| format!("累计 {secs:.2} s"))
        .unwrap_or_else(|| "读不到".into())
}

fn iface_view(app: &mut App, pid: i32, extra: &ProcExtra) -> Vec<String> {
    if app.demo {
        return extra
            .net
            .ifaces
            .iter()
            .map(|iface| {
                format!(
                    "{}  下行 {}/s  上行 {}/s  {}",
                    iface.name,
                    procs::human_bytes(iface.rx_bytes / 8),
                    procs::human_bytes(iface.tx_bytes / 8),
                    packet_fields(
                        iface.drops as f64,
                        iface.errs as f64,
                        iface.fifo as f64,
                        iface.frame as f64,
                        iface.carrier as f64,
                        iface.colls as f64,
                        true
                    )
                )
            })
            .collect();
    }
    let now = std::time::Instant::now();
    let current = extra.net.ifaces.clone();
    let lines = if let Some(prev) = app.iface_prev.as_ref().filter(|item| item.pid == pid) {
        let secs = now.duration_since(prev.at).as_secs_f64();
        if secs >= 0.4 {
            current
                .iter()
                .map(|iface| {
                    let old = prev.rows.iter().find(|item| item.name == iface.name);
                    match old {
                        Some(old) => format!(
                            "{}  下行 {}  上行 {}  {}",
                            iface.name,
                            procs::human_bps(per_sec(old.rx_bytes, iface.rx_bytes, secs)),
                            procs::human_bps(per_sec(old.tx_bytes, iface.tx_bytes, secs)),
                            packet_fields(
                                per_sec(old.drops, iface.drops, secs),
                                per_sec(old.errs, iface.errs, secs),
                                per_sec(old.fifo, iface.fifo, secs),
                                per_sec(old.frame, iface.frame, secs),
                                per_sec(old.carrier, iface.carrier, secs),
                                per_sec(old.colls, iface.colls, secs),
                                true
                            )
                        ),
                        None => format!(
                            "{}  累计下行 {}  累计上行 {}",
                            iface.name,
                            procs::human_bytes(iface.rx_bytes),
                            procs::human_bytes(iface.tx_bytes)
                        ),
                    }
                })
                .collect()
        } else {
            prev.lines.clone()
        }
    } else {
        current
            .iter()
            .map(|iface| {
                format!(
                    "{}  累计下行 {}  累计上行 {}  累计{}",
                    iface.name,
                    procs::human_bytes(iface.rx_bytes),
                    procs::human_bytes(iface.tx_bytes),
                    packet_fields(
                        iface.drops as f64,
                        iface.errs as f64,
                        iface.fifo as f64,
                        iface.frame as f64,
                        iface.carrier as f64,
                        iface.colls as f64,
                        false
                    )
                )
            })
            .collect()
    };
    let refresh_base = app
        .iface_prev
        .as_ref()
        .map(|prev| prev.pid == pid && now.duration_since(prev.at).as_secs_f64() >= 0.4)
        .unwrap_or(true);
    if refresh_base {
        app.iface_prev = Some(IfacePrev {
            pid,
            at: now,
            rows: current,
            lines: lines.clone(),
        });
    }
    lines
}

fn packet_fields(
    drops: f64,
    errs: f64,
    fifo: f64,
    frame: f64,
    carrier: f64,
    colls: f64,
    rate: bool,
) -> String {
    let one = |label: &str, value: f64| {
        if rate {
            format!("{label} {value:.0}/s")
        } else {
            format!("{label} {value:.0}")
        }
    };
    format!(
        "{}  {}  {}  {}  {}  {}",
        one("丢包", drops),
        one("错误", errs),
        one("溢出", fifo),
        one("帧错", frame),
        one("载波", carrier),
        one("冲突", colls)
    )
}

fn packet_hot(line: &str) -> bool {
    for label in ["丢包", "错误", "溢出", "帧错", "载波", "冲突"] {
        let Some(rest) = line.split(label).nth(1) else {
            continue;
        };
        let rest = rest.trim_start();
        if rest.starts_with(|ch: char| ch.is_ascii_digit()) && !rest.starts_with('0') {
            return true;
        }
    }
    false
}

fn per_sec(prev: u64, curr: u64, secs: f64) -> f64 {
    if secs <= 0.0 {
        0.0
    } else {
        curr.saturating_sub(prev) as f64 / secs
    }
}

fn heat_color(value: f64, warm: f64, hot: f64) -> Color {
    heat_into(value, warm, hot, Color::Cyan)
}

fn heat_into(value: f64, warm: f64, hot: f64, cool: Color) -> Color {
    if value >= hot {
        Color::Red
    } else if value >= warm {
        Color::Yellow
    } else {
        cool
    }
}

fn plain_fit(text: &str, cols: usize) -> String {
    fit_cols(&board::plain_line(text), cols)
}

fn safe_wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let plain = board::plain_line(text);
    if plain.is_empty() {
        return vec![String::new()];
    }
    wrap_text(&plain, width)
        .into_iter()
        .map(|line| fit_cols(&line, width))
        .collect()
}

fn fit_spans(spans: Vec<Span<'static>>, width: usize) -> Vec<Span<'static>> {
    if width == 0 {
        return Vec::new();
    }
    let mut used = 0usize;
    let mut out = Vec::new();
    for span in spans {
        if used >= width {
            break;
        }
        let cols = span_cols(&span);
        if used + cols <= width {
            used += cols;
            out.push(span);
        } else {
            let fitted = fit_cols(span.content.as_ref(), width - used);
            if !fitted.is_empty() {
                out.push(Span::styled(fitted, span.style));
            }
            break;
        }
    }
    out
}

fn span_cols(span: &Span<'_>) -> usize {
    display_cols(span.content.as_ref())
}

fn mem_color(app: &App, rss_kb: u64) -> Color {
    if let Some(total) = app
        .latest
        .as_ref()
        .map(|sample| sample.mem.total_kb)
        .filter(|total| *total > 0)
    {
        return heat_color(rss_kb as f64 / total as f64, 0.10, 0.30);
    }
    heat_color(rss_kb as f64, 256.0 * 1024.0, 1024.0 * 1024.0)
}

fn state_color(state: &str) -> Color {
    match state.chars().next() {
        Some('R') => Color::Green,
        Some('D') => Color::Yellow,
        Some('Z') | Some('T') | Some('t') => Color::Red,
        _ => Color::Gray,
    }
}

fn fd_color(extra: &ProcExtra) -> Color {
    match (extra.fd_count, extra.nofile_soft) {
        (Some(count), Some(limit)) if limit > 0 => {
            heat_color(count as f64 / limit as f64, 0.80, 0.95)
        }
        _ => Color::Cyan,
    }
}

fn advice_color(proc: &ProcRate) -> Color {
    if proc.state.starts_with('D') || proc.vmswap_kb > 0 {
        Color::Red
    } else if proc.cpu_ratio >= 0.90 || proc.read_bps + proc.write_bps >= 5_000_000.0 {
        Color::Yellow
    } else {
        Color::Cyan
    }
}

fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::Info => Color::Green,
        Severity::Watch => Color::Cyan,
        Severity::Warning => Color::Yellow,
        Severity::Critical => Color::Red,
    }
}

fn mem_amounts(app: &App) -> Option<(u64, u64)> {
    if let Some(rates) = &app.rates {
        let total = rates.mem_total_kb;
        let used = total.saturating_sub(rates.mem_available_kb);
        return Some((used, total));
    }
    let sample = app.latest.as_ref()?;
    let total = sample.mem.total_kb;
    Some((total.saturating_sub(sample.mem.available_kb), total))
}

fn mem_used(app: &App) -> Option<f64> {
    if let Some(rates) = &app.rates {
        return Some((1.0 - rates.mem_available_ratio).clamp(0.0, 1.0));
    }
    let sample = app.latest.as_ref()?;
    let total = sample.mem.total_kb.max(1) as f64;
    Some((1.0 - sample.mem.available_kb as f64 / total).clamp(0.0, 1.0))
}

fn uptime_text() -> String {
    let text = std::fs::read_to_string("/proc/uptime").unwrap_or_default();
    let secs = text
        .split_whitespace()
        .next()
        .and_then(|value| value.parse::<f64>().ok())
        .map(|value| value as u64)
        .unwrap_or(0);
    format_uptime(secs)
}

fn format_uptime(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    if days > 0 {
        format!("{days}天{hours}时{mins}分")
    } else if hours > 0 {
        format!("{hours}时{mins}分")
    } else {
        format!("{mins}分")
    }
}

fn local_clock() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as libc::time_t)
        .unwrap_or(0);
    unsafe {
        let mut tm = std::mem::zeroed();
        if libc::localtime_r(&secs, &mut tm).is_null() {
            return "--:--:--".into();
        }
        format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        close_syslog_unit, format_uptime, heat_color, log_window, move_cursor_to, place_cursor,
        process_title, sort_rows, toggle_sort, visible_procs, App, Screen,
        SortKey, TableState,
    };
    use ratatui::style::Color;

    use crate::procs::ProcRate;

    fn proc(pid: i32, comm: &str, cpu: f64, rss: u64, write: f64) -> ProcRate {
        ProcRate {
            pid,
            comm: comm.into(),
            cmdline: comm.into(),
            state: "S".into(),
            ppid: 1,
            uid: 0,
            cpu_ratio: cpu,
            rss_kb: rss,
            vmsize_kb: rss,
            vmswap_kb: 0,
            threads: 1,
            read_bps: 0.0,
            write_bps: write,
            vol_ctxt_per_sec: 0.0,
            nonvol_ctxt_per_sec: 0.0,
            wchan: String::new(),
        }
    }

    #[test]
    fn uptime_uses_days_hours_and_minutes() {
        assert_eq!(format_uptime(90), "1分");
        assert_eq!(format_uptime(3_600 + 120), "1时2分");
        assert_eq!(format_uptime(86_400 + 3_600 + 60), "1天1时1分");
    }

    #[test]
    fn sort_cpu_descending_puts_the_busy_process_first() {
        let mut rows = vec![
            proc(2, "nginx", 0.1, 10, 0.0),
            proc(1, "fio", 0.9, 20, 50.0),
        ];
        sort_rows(&mut rows, SortKey::Cpu, true);
        assert_eq!(rows[0].comm, "fio");
        sort_rows(&mut rows, SortKey::Name, false);
        assert_eq!(rows[0].comm, "fio");
        sort_rows(&mut rows, SortKey::Write, true);
        assert_eq!(rows[0].pid, 1);
    }

    #[test]
    fn process_title_counts_each_state() {
        let mut rows = vec![
            proc(1, "nginx", 0.1, 1, 0.0),
            proc(2, "sshd", 0.1, 1, 0.0),
            proc(3, "fio", 0.1, 1, 0.0),
        ];
        rows[0].state = "Ss+".into();
        rows[1].state = "Ss+".into();
        rows[2].state = "D".into();
        assert_eq!(process_title(&rows, 120), " 进程  3  Ss+ 2  D 1 ");
    }

    #[test]
    fn log_window_follows_the_tail() {
        let lines: Vec<_> = (0..10).map(|index| index.to_string()).collect();
        assert_eq!(log_window(&lines, 3, 0), vec!["7", "8", "9"]);
        assert_eq!(log_window(&lines, 3, 2), vec!["5", "6", "7"]);
    }

    #[test]
    fn disks_list_each_device_and_the_total() {
        let disks = vec![
            crate::board::HwDisk {
                name: "vda".into(),
                size: String::new(),
                bytes: 100 * 1024 * 1024 * 1024u64,
                model: String::new(),
                serial: String::new(),
                kind: String::new(),
            },
            crate::board::HwDisk {
                name: "vdb".into(),
                size: String::new(),
                bytes: 500 * 1024 * 1024 * 1024u64,
                model: String::new(),
                serial: String::new(),
                kind: String::new(),
            },
        ];
        let text = super::disk_line(&disks);
        assert_eq!(text, "共600.0GiB [ vda 100.0GiB   vdb 500.0GiB ]");
    }

    #[test]
    fn long_field_keeps_its_label() {
        let spans = super::fit_spans(
            vec![ratatui::text::Span::raw("内存  "), ratatui::text::Span::raw("x".repeat(80))],
            16,
        );
        let text: String = spans.iter().map(|span| span.content.to_string()).collect();
        assert!(text.starts_with("内存"));
        assert!(super::display_cols(&text) <= 16);
    }

    #[test]
    fn shortcut_columns_share_a_grid() {
        assert_eq!(super::display_cols(&super::key_cell("1")), 4);
        assert_eq!(super::display_cols(&super::key_cell("回车")), 4);
        assert_eq!(super::display_cols(&super::label_cell("防火墙")), 7);
        let top = super::hint_line(&[("1", "容器"), ("c", "CPU")], 40);
        let next = super::hint_line(&[("2", "防火墙"), ("r", "读")], 40);
        let second = |line: &ratatui::text::Line| {
            let mut used = 0usize;
            for span in &line.spans {
                let text = span.content.as_ref();
                if text.contains('c') || text.contains('r') {
                    return used;
                }
                used += super::display_cols(text);
            }
            used
        };
        assert_eq!(second(&top), second(&next));
    }

    #[test]
    fn colored_text_cannot_paint_past_the_edge() {
        let raw = format!("\u{1b}[31m{}\t{} \u{1b}[0m", "drop", "x".repeat(80));
        let parts = super::safe_wrap(&raw, 20);
        assert!(parts.len() > 1);
        assert!(parts.iter().all(|part| !part.contains('\u{1b}') && !part.contains('\t')));
        assert!(parts.iter().all(|part| super::display_cols(part) <= 20));
    }

    #[test]
    fn long_rule_lines_stay_inside_the_terminal() {
        let row = super::Paint {
            text: format!("policy drop {}", "x".repeat(200)),
            color: Color::Cyan,
        };
        let rows = super::wrap_paints(vec![row], 40);
        assert!(rows.len() > 1);
        assert!(rows.iter().all(|row| super::display_cols(&row.text) <= 40));
    }

    #[test]
    fn section_bar_spans_the_row() {
        let bar = super::section_bar("路由", 40);
        assert!(bar.contains("路由"));
        assert!(bar.starts_with('━'));
        assert_eq!(super::display_cols(&bar), 40);
    }

    #[test]
    fn kernel_keys_line_up_with_the_chinese_label() {
        let mut rows = Vec::new();
        super::paint_pairs(
            &mut rows,
            &[
                (
                    super::with_key("转发", "net.ipv4.ip_forward"),
                    "开启".into(),
                    Color::Cyan,
                ),
                (
                    super::with_key("反向路径", "net.ipv4.conf.all.rp_filter"),
                    "松散".into(),
                    Color::Cyan,
                ),
            ],
            120,
        );
        assert!(rows[0].text.contains("net.ipv4.ip_forward"));
        assert!(rows[1].text.contains("net.ipv4.conf.all.rp_filter"));
        let col = |text: &str, value: &str| {
            let at = text.rfind(value).unwrap();
            super::display_cols(&text[..at])
        };
        assert_eq!(col(&rows[0].text, "开启"), col(&rows[1].text, "松散"));
    }

    #[test]
    fn table_columns_share_the_same_width() {
        let left = super::table_row(&[("eth0", 8), ("up", 6), ("192.168.0.1", 12)]);
        let right = super::table_row(&[("docker0", 8), ("down", 6), ("172.17.0.1", 12)]);
        let left_via = left.find("up").unwrap();
        let right_via = right.find("down").unwrap();
        assert_eq!(left_via, right_via);
    }

    #[test]
    fn long_command_wraps_without_dropping_characters() {
        let command = "minio server --address :9000 --console-address :9001 /data/tenant/bucket";
        let lines = super::wrap_text(command, 24);
        let joined: String = lines.concat();
        assert!(lines.len() > 1);
        assert_eq!(joined.replace(' ', ""), command.replace(' ', ""));
    }

    #[test]
    fn pressure_colors_step_from_cyan_to_red() {
        assert_eq!(heat_color(0.1, 0.5, 0.8), Color::Cyan);
        assert_eq!(heat_color(0.5, 0.5, 0.8), Color::Yellow);
        assert_eq!(heat_color(0.9, 0.5, 0.8), Color::Red);
    }

    #[test]
    fn changing_sort_selects_the_first_row() {
        let mut app = App {
            demo: true,
            demo_index: 1,
            previous: None,
            latest: None,
            prev_procs: None,
            rates: None,
            findings: Vec::new(),
            processes: vec![
                proc(1, "fio", 0.2, 10, 1.0),
                proc(2, "nginx", 0.9, 90, 0.0),
            ],
            cursor: 1,
            home_pid: Some(1),
            focus_pid: None,
            table_state: TableState::default(),
            sort_key: SortKey::Pid,
            descending: true,
            filtering: false,
            filter: String::new(),
            screen: Screen::Procs,
            board_scroll: 0,
            inventory: crate::containers::Inventory::empty(""),
            container_picks: Vec::new(),
            container_place: false,
            firewall: crate::board::FirewallView::empty(),
            net: crate::board::NetConfig::empty(),
            net_focus: super::NetFocus::Config,
            capture: crate::sniff::Capture::closed(),
            packets: Vec::new(),
            packet_from_bottom: 0,
            cap_filter: crate::sniff::KindFilter::All,
            cap_query: String::new(),
            cap_filtering: false,
            cap_abnormal: false,
            cap_detail: false,
            cap_note: String::new(),
            cap_paused: false,
            cap_iface: None,
            packet_cursor: 0,
            packet_follow: true,
            packet_scroll: 0,
            board_cursor: 0,
            board_rows: Vec::new(),
            box_cursor: 0,
            box_scroll: 0,
            syslog_anchor: None,
            capture_from_ifaces: false,
            hardware: crate::board::HardwareInfo::empty(),
            box_output: false,
            box_exec: false,
            box_action: None,
            box_pick: None,
            box_title: String::new(),
            box_lines: Vec::new(),
            iface_cursor: 0,
            ssh_host: String::new(),
            ssh_port: "22".into(),
            ssh_field: 0,
            ssh_error: String::new(),
            ssh_launch: false,
            bench: crate::bench::Session::idle(),
            bench_host: "127.0.0.1".into(),
            bench_port: "5201".into(),
            bench_field: 0,
            bench_proto: crate::bench::Proto::Tcp,
            bench_listen: false,
            syslog_kind: 0,
            syslog_unit: String::new(),
            syslog_lines: Vec::new(),
            syslog_source: String::new(),
            syslog_query: String::new(),
            syslog_filtering: false,
            full_clear: false,
            last_refresh: std::time::Instant::now(),
            help: false,
            page_rows: 20,
            log_lines: Vec::new(),
            log_note: String::new(),
            log_from_bottom: 0,
            log_follow: true,
            process_scroll: 0,
            iface_prev: None,
            status: String::new(),
            host_line: String::new(),
        };
        toggle_sort(&mut app, SortKey::Cpu);
        let visible = super::visible_procs(&app);
        place_cursor(&mut app, &visible);
        assert_eq!(app.cursor, 0);
        assert_eq!(visible[app.cursor].comm, "nginx");

        let visible = visible_procs(&app);
        move_cursor_to(&mut app, &visible, 1);
        let pid = visible[1].pid;
        app.focus_pid = Some(pid);
        app.home_pid = None;
        app.home_pid = app.focus_pid.or(app.home_pid);
        let visible = visible_procs(&app);
        place_cursor(&mut app, &visible);
        assert_eq!(visible[app.cursor].pid, pid);

        app.syslog_kind = 2;
        app.syslog_unit = "ssh.service".into();
        app.syslog_anchor = Some(9);
        close_syslog_unit(&mut app);
        assert!(app.syslog_unit.is_empty());
        assert_eq!(app.board_cursor, 3);
    }
}
