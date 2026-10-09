use std::cmp::Ordering;
use std::io::{self, IsTerminal, Stdout, Write};
use std::process::Command;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, HighlightSpacing, Paragraph, Row, Table, TableState, Wrap,
};
use ratatui::{Frame, Terminal};

use crate::advise;
use crate::analyze::{Finding, Severity};
use crate::collect;
use crate::compat;
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
    Home,
    Process,
    Logs,
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
    help: bool,
    page_rows: usize,
    log_lines: Vec<String>,
    log_note: String,
    log_from_bottom: usize,
    status: String,
    host_line: String,
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
        screen: Screen::Home,
        help: false,
        page_rows: 20,
        log_lines: Vec::new(),
        log_note: String::new(),
        log_from_bottom: 0,
        status: if demo {
            "演示".into()
        } else {
            "正在采样".into()
        },
        host_line,
    };
    wait_for_second_frame(&mut app, interval_secs.max(1))?;
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;
    let result = event_loop(&mut terminal, &mut app, interval_secs.max(1));
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    result
}

fn wait_for_second_frame(app: &mut App, interval_secs: u64) -> Result<()> {
    if !app.demo {
        let mut stdout = io::stdout();
        writeln!(stdout, "正在采样，约 {interval_secs} 秒后打开")?;
        stdout.flush()?;
    }
    refresh(app)?;
    if app.demo || app.rates.is_some() {
        return Ok(());
    }
    std::thread::sleep(Duration::from_secs(interval_secs));
    refresh(app)
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    interval_secs: u64,
) -> Result<()> {
    loop {
        terminal.draw(|frame| draw(frame, app))?;
        if event::poll(Duration::from_secs(interval_secs))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Release {
                    continue;
                }
                if on_key(app, key) {
                    return Ok(());
                }
            }
        } else {
            refresh(app)?;
        }
    }
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
        Screen::Home => on_home_key(app, key),
        Screen::Process => on_process_key(app, key),
        Screen::Logs => on_log_key(app, key),
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
                app.focus_pid = Some(proc.pid);
                app.screen = Screen::Process;
            }
        }
        KeyCode::Esc => {
            if !app.filter.is_empty() {
                app.filter.clear();
                app.cursor = 0;
                app.home_pid = None;
            }
        }
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
    match key.code {
        KeyCode::Char('q') => true,
        KeyCode::Esc => {
            app.screen = Screen::Home;
            false
        }
        KeyCode::Char('l') => {
            app.screen = Screen::Logs;
            app.log_from_bottom = 0;
            refresh_logs(app);
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
            false
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.log_from_bottom = app.log_from_bottom.saturating_add(1);
            false
        }
        KeyCode::Char('g') => {
            app.log_from_bottom = usize::MAX / 4;
            false
        }
        KeyCode::Char('G') => {
            app.log_from_bottom = 0;
            false
        }
        KeyCode::PageDown => {
            app.log_from_bottom = app.log_from_bottom.saturating_sub(page);
            false
        }
        KeyCode::PageUp => {
            app.log_from_bottom = app.log_from_bottom.saturating_add(page);
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
    let lines: Vec<_> = text.lines().map(|line| line.to_string()).collect();
    if lines.is_empty() {
        return Err(format!("{unit} 暂时没有日志"));
    }
    Ok(lines)
}

fn draw(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    if area.height < 8 || area.width < 40 {
        frame.render_widget(Paragraph::new("终端至少需要 40 列、8 行"), area);
        return;
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(4),
            Constraint::Length(1),
        ])
        .split(area);
    app.page_rows = rows[2].height.saturating_sub(3) as usize;
    draw_status(frame, app, rows[0]);
    draw_crumb(frame, app, rows[1]);
    match app.screen {
        Screen::Home => draw_home(frame, app, rows[2]),
        Screen::Process => draw_process(frame, app, rows[2]),
        Screen::Logs => draw_logs(frame, app, rows[2]),
    }
    draw_footer(frame, app, rows[3]);
    if app.help {
        draw_help(frame, area);
    }
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
                metric_cell(procs::state_label(&proc.state), state_color(&proc.state)),
                Cell::from(procs::display_cmd(proc, 80)),
            ])
        })
        .collect();
    let title = format!(" 进程  {} ", visible.len());
    let table = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(6),
            Constraint::Min(12),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title))
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

fn draw_process(frame: &mut Frame, app: &App, area: Rect) {
    let Some(pid) = app.focus_pid else {
        frame.render_widget(Paragraph::new("没有选中的进程"), area);
        return;
    };
    let proc = app.processes.iter().find(|item| item.pid == pid);
    let Some(proc) = proc else {
        frame.render_widget(
            Paragraph::new(format!("pid {pid} 已经退出")).block(Block::default().borders(Borders::ALL).title(" 进程 ")),
            area,
        );
        return;
    };
    let extra = focus_extra(app, proc);
    let suggestion = advise::for_process(proc, Some(&extra));
    let wchan = if proc.wchan.is_empty() {
        "没有"
    } else {
        proc.wchan.as_str()
    };
    let fds = match (extra.fd_count, extra.nofile_soft) {
        (Some(count), Some(limit)) => format!("{count} / 软限制 {limit}"),
        (Some(count), None) => count.to_string(),
        _ => "读不到".into(),
    };
    let cgroup = if extra.cgroup.is_empty() {
        "没有".into()
    } else {
        extra.cgroup.clone()
    };
    let advice_color = advice_color(proc);
    let text = vec![
        Line::from(vec![
            Span::styled(
                proc.comm.clone(),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  pid {}  用户 {}  父进程 {}  ", proc.pid, extra.user, proc.ppid),
                Style::default().fg(Color::Gray),
            ),
            Span::styled(
                procs::state_label(&proc.state),
                Style::default()
                    .fg(state_color(&proc.state))
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        labeled("命令", &procs::display_cmd(proc, 120), Color::White),
        labeled("cgroup", &cgroup, Color::Gray),
        labeled("等待", wchan, state_color(&proc.state)),
        Line::from(vec![
            label_span("CPU "),
            value_span(
                procs::cpu_percent(proc.cpu_ratio),
                heat_color(proc.cpu_ratio, 0.50, 0.90),
            ),
            label_span("   线程 "),
            value_span(proc.threads.to_string(), Color::Cyan),
            label_span("   自愿切换 "),
            value_span(format!("{:.0}/s", proc.vol_ctxt_per_sec), Color::Cyan),
            label_span("   非自愿 "),
            value_span(format!("{:.0}/s", proc.nonvol_ctxt_per_sec), Color::Cyan),
        ]),
        Line::from(vec![
            label_span("内存  RSS "),
            value_span(procs::human_kb(proc.rss_kb), mem_color(app, proc.rss_kb)),
            label_span("   虚拟 "),
            value_span(procs::human_kb(proc.vmsize_kb), Color::Cyan),
            label_span("   换出 "),
            value_span(
                procs::human_kb(proc.vmswap_kb),
                if proc.vmswap_kb > 0 {
                    Color::Red
                } else {
                    Color::Cyan
                },
            ),
        ]),
        Line::from(vec![
            label_span("磁盘  读 "),
            value_span(
                procs::human_bps(proc.read_bps),
                heat_color(proc.read_bps, 1_000_000.0, 50_000_000.0),
            ),
            label_span("   写 "),
            value_span(
                procs::human_bps(proc.write_bps),
                heat_color(proc.write_bps, 1_000_000.0, 50_000_000.0),
            ),
        ]),
        labeled("描述符", &fds, fd_color(&extra)),
        Line::from(""),
        Line::from(Span::styled(
            format!("建议  {suggestion}"),
            Style::default()
                .fg(advice_color)
                .add_modifier(Modifier::BOLD),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(" 实时 ")),
        area,
    );
}

fn draw_logs(frame: &mut Frame, app: &App, area: Rect) {
    let inner_height = area.height.saturating_sub(2) as usize;
    let lines = log_window(&app.log_lines, inner_height, app.log_from_bottom);
    let body = if lines.is_empty() {
        vec![Line::from(app.log_note.clone())]
    } else {
        lines.into_iter().map(Line::from).collect()
    };
    frame.render_widget(
        Paragraph::new(body)
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" 日志  {} ", app.log_note)),
            ),
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
        Screen::Home => verdict_line(app),
        Screen::Process => Line::from(format!(" {}", focus_title(app, "进程"))),
        Screen::Logs => Line::from(format!(" {}", focus_title(app, "日志"))),
    };
    frame.render_widget(Paragraph::new(line), area);
}

fn focus_title(app: &App, kind: &str) -> String {
    let Some(pid) = app.focus_pid else {
        return kind.into();
    };
    match app.processes.iter().find(|proc| proc.pid == pid) {
        Some(proc) => format!("{kind}  {}  {pid}  {}", proc.comm, procs::display_cmd(proc, 60)),
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
        "输入筛选，回车确认，Esc 清除"
    } else {
        match app.screen {
            Screen::Home => "j/k 移动  回车进入  /筛选  cCPU m内存 r读 w写 pPID n名字  ?帮助  q退出",
            Screen::Process => "实时刷新  l 日志  Esc 返回  q 退出",
            Screen::Logs => "j/k 翻阅  G 跟到最新  Esc 返回  q 退出",
        }
    };
    frame.render_widget(
        Paragraph::new(format!(" {text}")).style(Style::default().fg(Color::DarkGray)),
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
    let text = vec![
        Line::from("首页是进程表。数字每个采样间隔刷新。"),
        Line::from("j/k 或方向键移动    g/G 顶/底    Ctrl-d / Ctrl-u 半页"),
        Line::from("回车 进入进程       Esc 返回上一层       q 退出"),
        Line::from("/ 按名字或命令行筛选，空格表示都要出现，Esc 清除"),
        Line::from("c m r w p n  按 CPU、内存、读、写、PID、名字排序，光标回到第一行"),
        Line::from("再按一次同一个键，切换升序和降序"),
        Line::from("进程页里 l 打开日志。只有 systemd 服务才有 journal"),
        Line::from("顶栏数字和下面一行是整机结论，黄和红表示压力高"),
        Line::from(""),
        Line::from("? 或 Esc 关闭"),
    ];
    frame.render_widget(ratatui::widgets::Clear, help_area);
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL).title(" 帮助 "))
            .wrap(Wrap { trim: true }),
        help_area,
    );
}

fn focus_extra(app: &App, proc: &ProcRate) -> ProcExtra {
    if app.demo {
        return ProcExtra {
            user: if proc.uid == 0 {
                "root".into()
            } else {
                proc.uid.to_string()
            },
            cgroup: demo_unit(proc)
                .map(|unit| format!("/system.slice/{unit}"))
                .unwrap_or_else(|| "/user.slice/session.scope".into()),
            fd_count: Some(12),
            nofile_soft: Some(1024),
            stack: if proc.state == "D" {
                Some(format!("{}\nio_schedule", proc.wchan))
            } else {
                None
            },
        };
    }
    procs::extra(proc.pid)
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
    let cpu = cpu_ratio
        .map(|ratio| format!("{:3.0}%", ratio * 100.0))
        .unwrap_or_else(|| "  …".into());
    let mem = mem_ratio
        .map(|ratio| format!("{:3.0}%", ratio * 100.0))
        .unwrap_or_else(|| "  …".into());
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
    let (load, load_color) = app
        .rates
        .as_ref()
        .map(|rates| {
            let hot = rates.cpu.ncpu.max(1) as f64;
            (
                format!("{:.2}", rates.load1),
                heat_color(rates.load1, hot * 0.70, hot),
            )
        })
        .unwrap_or_else(|| ("…".into(), Color::Cyan));
    let line = Line::from(vec![
        bar_span(" CPU ", Color::Gray),
        bar_span(cpu, cpu_ratio.map(|ratio| heat_color(ratio, 0.50, 0.80)).unwrap_or(Color::Cyan)),
        bar_span(" │ MEM ", Color::Gray),
        bar_span(mem, mem_ratio.map(|ratio| heat_color(ratio, 0.70, 0.90)).unwrap_or(Color::Cyan)),
        bar_span(" │ IO ", Color::Gray),
        bar_span(io, io_ratio.map(|ratio| heat_color(ratio, 0.50, 0.90)).unwrap_or(Color::Cyan)),
        bar_span(" │ ↓", Color::Gray),
        bar_span(down, Color::Cyan),
        bar_span(" ↑", Color::Gray),
        bar_span(up, Color::Cyan),
        bar_span(" │ load ", Color::Gray),
        bar_span(load, load_color),
        bar_span(
            format!(" │ 开机 {} │ {} │ {} ", uptime_text(), local_clock(), app.host_line),
            Color::Gray,
        ),
    ]);
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

fn label_span(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::default().fg(Color::DarkGray))
}

fn value_span(text: impl Into<String>, color: Color) -> Span<'static> {
    Span::styled(
        text.into(),
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    )
}

fn labeled(label: &str, value: &str, color: Color) -> Line<'static> {
    Line::from(vec![label_span(label), value_span(format!("  {value}"), color)])
}

fn heat_color(value: f64, warm: f64, hot: f64) -> Color {
    if value >= hot {
        Color::Red
    } else if value >= warm {
        Color::Yellow
    } else {
        Color::Cyan
    }
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
    match state {
        "R" => Color::Green,
        "D" => Color::Yellow,
        "Z" | "T" | "t" => Color::Red,
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
    if proc.state == "D" || proc.vmswap_kb > 0 {
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
        format_uptime, heat_color, log_window, place_cursor, sort_rows, toggle_sort, App, Screen,
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
    fn log_window_follows_the_tail() {
        let lines: Vec<_> = (0..10).map(|index| index.to_string()).collect();
        assert_eq!(log_window(&lines, 3, 0), vec!["7", "8", "9"]);
        assert_eq!(log_window(&lines, 3, 2), vec!["5", "6", "7"]);
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
            screen: Screen::Home,
            help: false,
            page_rows: 20,
            log_lines: Vec::new(),
            log_note: String::new(),
            log_from_bottom: 0,
            status: String::new(),
            host_line: String::new(),
        };
        toggle_sort(&mut app, SortKey::Cpu);
        let visible = super::visible_procs(&app);
        place_cursor(&mut app, &visible);
        assert_eq!(app.cursor, 0);
        assert_eq!(visible[app.cursor].comm, "nginx");
    }
}
