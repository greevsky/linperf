use crate::model::{
    CpuCounters, DiskCounters, HostSample, LoadAvg, MemInfo, NetCounters, Pressure, VmCounters,
};
use crate::procs::ProcRate;

struct Step {
    user: u64,
    system: u64,
    idle: u64,
    iowait: u64,
    disk_io_ms: u64,
    disk_ops: u64,
    disk_op_ms: u64,
    psi_some: f64,
    psi_full: f64,
    load1: f64,
}

/// 四帧演示：前一跳很闲，最后一跳是磁盘饱和。
pub fn timeline() -> Vec<HostSample> {
    let steps = [
        Step {
            user: 80,
            system: 40,
            idle: 860,
            iowait: 20,
            disk_io_ms: 40,
            disk_ops: 10,
            disk_op_ms: 40,
            psi_some: 0.2,
            psi_full: 0.0,
            load1: 0.3,
        },
        Step {
            user: 100,
            system: 50,
            idle: 750,
            iowait: 100,
            disk_io_ms: 400,
            disk_ops: 40,
            disk_op_ms: 800,
            psi_some: 8.0,
            psi_full: 2.0,
            load1: 1.2,
        },
        Step {
            user: 80,
            system: 40,
            idle: 200,
            iowait: 680,
            disk_io_ms: 980,
            disk_ops: 100,
            disk_op_ms: 9_000,
            psi_some: 55.0,
            psi_full: 25.0,
            load1: 2.4,
        },
    ];
    let mut user = 0;
    let mut system = 0;
    let mut idle = 0;
    let mut iowait = 0;
    let mut io_ms = 0;
    let mut ops = 0;
    let mut op_ms = 0;
    let mut samples = vec![sample(0, 0, 0, 0, 0, 0, 0, 0, 0.0, 0.0, 0.2)];
    for (index, step) in steps.iter().enumerate() {
        user += step.user;
        system += step.system;
        idle += step.idle;
        iowait += step.iowait;
        io_ms += step.disk_io_ms;
        ops += step.disk_ops;
        op_ms += step.disk_op_ms;
        samples.push(sample(
            (index as u64 + 1) * 1000,
            user,
            system,
            idle,
            iowait,
            io_ms,
            ops,
            op_ms,
            step.psi_some,
            step.psi_full,
            step.load1,
        ));
    }
    samples
}

pub fn demo_folded() -> &'static str {
    "\
app;read_path;wait_on_page_bit 40
app;read_path;submit_bio 25
app;fsync;jbd2_log_wait 15
app;lock_page;io_schedule 10
"
}

pub fn demo_processes(hot: bool) -> Vec<ProcRate> {
    let mut rows = vec![ProcRate {
        pid: 1820,
        comm: "nginx".into(),
        cmdline: "nginx: worker process".into(),
        state: "Ss+".into(),
        ppid: 1,
        uid: 33,
        cpu_ratio: 0.03,
        rss_kb: 48_000,
        vmsize_kb: 80_000,
        vmswap_kb: 0,
        threads: 1,
        read_bps: 20_000.0,
        write_bps: 4_000.0,
        vol_ctxt_per_sec: 5.0,
        nonvol_ctxt_per_sec: 0.2,
        wchan: "ep_poll".into(),
    }];
    rows.push(ProcRate {
        pid: 900,
        comm: "sshd".into(),
        cmdline: "sshd: dgbc [priv]".into(),
        state: "Ss".into(),
        ppid: 1,
        uid: 0,
        cpu_ratio: 0.01,
        rss_kb: 8_000,
        vmsize_kb: 16_000,
        vmswap_kb: 0,
        threads: 1,
        read_bps: 0.0,
        write_bps: 0.0,
        vol_ctxt_per_sec: 1.0,
        nonvol_ctxt_per_sec: 0.0,
        wchan: "poll".into(),
    });
    rows.push(ProcRate {
        pid: 2200,
        comm: "postgres".into(),
        cmdline: "postgres: checkpointer".into(),
        state: "Ssl".into(),
        ppid: 2100,
        uid: 999,
        cpu_ratio: 0.55,
        rss_kb: 1_200_000,
        vmsize_kb: 2_000_000,
        vmswap_kb: 0,
        threads: 1,
        read_bps: 100_000.0,
        write_bps: 80_000.0,
        vol_ctxt_per_sec: 20.0,
        nonvol_ctxt_per_sec: 1.0,
        wchan: "ep_poll".into(),
    });
    if hot {
        rows.insert(
            0,
            ProcRate {
                pid: 4242,
                comm: "fio".into(),
                cmdline: "fio --name=write --rw=write --bs=128k".into(),
                state: "D".into(),
                ppid: 1,
                uid: 0,
                cpu_ratio: 0.18,
                rss_kb: 210_000,
                vmsize_kb: 480_000,
                vmswap_kb: 0,
                threads: 2,
                read_bps: 1_200_000.0,
                write_bps: 82_000_000.0,
                vol_ctxt_per_sec: 40.0,
                nonvol_ctxt_per_sec: 2.0,
                wchan: "io_schedule".into(),
            },
        );
    }
    rows
}

fn sample(
    mono_ms: u64,
    user: u64,
    system: u64,
    idle: u64,
    iowait: u64,
    io_ms: u64,
    ops: u64,
    op_ms: u64,
    psi_some: f64,
    psi_full: f64,
    load1: f64,
) -> HostSample {
    HostSample {
        mono_ms,
        wall_ms: 1_759_000_000_000 + mono_ms as i64,
        kernel: "demo".into(),
        cpu: CpuCounters {
            user,
            nice: 0,
            system,
            idle,
            iowait,
            irq: 0,
            softirq: 0,
            steal: 0,
            ncpu: 4,
        },
        mem: MemInfo {
            total_kb: 32_000_000,
            available_kb: 20_000_000,
            available_estimated: false,
            swap_total_kb: 0,
            swap_free_kb: 0,
            dirty_kb: 12_000,
        },
        vm: VmCounters {
            pswpin: 0,
            pswpout: 0,
        },
        load: LoadAvg {
            load1,
            load5: load1 * 0.7,
            load15: load1 * 0.4,
        },
        psi_cpu: Some(Pressure {
            some_avg10: 0.1,
            some_avg60: 0.1,
            full_avg10: 0.0,
            full_avg60: 0.0,
        }),
        psi_memory: Some(Pressure::default()),
        psi_io: Some(Pressure {
            some_avg10: psi_some,
            some_avg60: psi_some / 2.0,
            full_avg10: psi_full,
            full_avg60: psi_full / 2.0,
        }),
        disks: vec![DiskCounters {
            name: "sda".into(),
            reads: ops,
            read_ms: op_ms,
            writes: 0,
            write_ms: 0,
            in_flight: if psi_full > 10.0 { 8 } else { 0 },
            io_ms,
        }],
        nets: vec![NetCounters {
            name: "eth0".into(),
            rx_bytes: mono_ms * 1000,
            rx_errs: 0,
            rx_drop: 0,
            rx_fifo: 0,
            rx_frame: 0,
            tx_bytes: mono_ms * 500,
            tx_errs: 0,
            tx_drop: 0,
            tx_fifo: 0,
            tx_colls: 0,
            tx_carrier: 0,
        }],
        softnet: crate::model::SoftnetCounters::default(),
        cgroup: None,
    }
}
