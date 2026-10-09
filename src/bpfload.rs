use std::collections::HashMap;
use std::fs;

use crate::error::{Error, Result};
use crate::kallsyms::Kallsyms;

const BPF_MAP_CREATE: u64 = 0;
const BPF_MAP_LOOKUP_ELEM: u64 = 1;
const BPF_MAP_UPDATE_ELEM: u64 = 2;
const BPF_MAP_GET_NEXT_KEY: u64 = 4;
const BPF_PROG_LOAD: u64 = 5;
const BPF_PROG_TYPE_TRACEPOINT: u32 = 5;
const BPF_PROG_TYPE_PERF_EVENT: u32 = 7;
const R_BPF_64_64: u32 = 1;
const PERF_TYPE_SOFTWARE: u32 = 1;
const PERF_TYPE_TRACEPOINT: u32 = 2;
const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
const PERF_EVENT_IOC_SET_BPF: libc::c_ulong = 0x4004_2408;
const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 8;

#[cfg(linji_ebpf)]
const ONCPU_OBJ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/oncpu.bpf.o"));
#[cfg(linji_ebpf)]
const OFFCPU_OBJ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/offcpu.bpf.o"));

struct ElfProg {
    insns: Vec<u8>,
    license: String,
    maps: Vec<MapDef>,
    relocs: Vec<(usize, usize)>,
    prog_type: u32,
}

struct MapDef {
    name: String,
    offset: usize,
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    fd: i32,
}

pub fn embedded() -> bool {
    cfg!(linji_ebpf)
}

pub fn sample_folded(kind: &str, seconds: u64, pid: Option<i32>) -> Result<String> {
    #[cfg(not(linji_ebpf))]
    {
        let _ = (kind, seconds, pid);
        return Err(Error::Message(
            "这个构建还没有嵌入 eBPF 字节码。".into(),
        ));
    }
    #[cfg(linji_ebpf)]
    {
        let (bytes, prog_type) = match kind {
            "oncpu" => (ONCPU_OBJ, BPF_PROG_TYPE_PERF_EVENT),
            "offcpu" => (OFFCPU_OBJ, BPF_PROG_TYPE_TRACEPOINT),
            other => {
                return Err(Error::Message(format!(
                    "未知采样类型 {other}，用 oncpu 或 offcpu"
                )))
            }
        };
        let mut prog = parse_prog(bytes, prog_type)?;
        let mut fds = Vec::new();
        let result = (|| {
            load_maps(&mut prog)?;
            patch_map_fds(&mut prog);
            if kind == "offcpu" {
                if let Some(target) = prog.maps.iter().find(|item| item.name == "target") {
                    let pid = pid.unwrap_or(0) as u32;
                    map_update(target.fd, &0u32.to_ne_bytes(), &pid.to_ne_bytes())?;
                }
            }
            let prog_fd = load_program(&prog)?;
            fds.push(prog_fd);
            let events = attach(kind, prog_fd, pid)?;
            fds.extend(events);
            std::thread::sleep(std::time::Duration::from_secs(seconds.max(1)));
            let table = Kallsyms::parse(&fs::read_to_string("/proc/kallsyms").unwrap_or_default());
            if kind == "oncpu" {
                fold_oncpu(&prog, &table)
            } else {
                fold_offcpu(&prog, &table)
            }
        })();
        for fd in fds {
            unsafe { libc::close(fd) };
        }
        for map in &prog.maps {
            if map.fd >= 0 {
                unsafe { libc::close(map.fd) };
            }
        }
        result
    }
}

fn parse_prog(bytes: &[u8], prog_type: u32) -> Result<ElfProg> {
    if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" {
        return Err(Error::Message("eBPF 对象不是 ELF".into()));
    }
    let u16 = |off: usize| u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap());
    let u32 = |off: usize| u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
    let u64 = |off: usize| u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
    let shoff = u64(40) as usize;
    let shentsize = u16(58) as usize;
    let shnum = u16(60) as usize;
    let shstrndx = u16(62) as usize;
    let section = |index: usize| -> Result<&[u8]> {
        let off = shoff + index * shentsize;
        if off + shentsize > bytes.len() {
            return Err(Error::Message("ELF 节头越界".into()));
        }
        let start = u64(off + 24) as usize;
        let size = u64(off + 32) as usize;
        bytes
            .get(start..start + size)
            .ok_or_else(|| Error::Message("ELF 节内容越界".into()))
    };
    let shstr = section(shstrndx)?;
    let name_of = |index: usize| -> Result<String> {
        let off = shoff + index * shentsize;
        let name_off = u32(off) as usize;
        let end = shstr[name_off..]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(0);
        Ok(String::from_utf8_lossy(&shstr[name_off..name_off + end]).into_owned())
    };
    let mut sections = HashMap::new();
    for index in 0..shnum {
        sections.insert(name_of(index)?, index);
    }
    let prog_index = sections
        .iter()
        .find(|(name, _)| {
            name.as_str() == "perf_event" || name.starts_with("tracepoint/")
        })
        .map(|(_, index)| *index)
        .ok_or_else(|| Error::Message("ELF 里没有采样程序".into()))?;
    let mut insns = section(prog_index)?.to_vec();
    let license = sections
        .get("license")
        .map(|index| {
            let raw = section(*index).unwrap_or_default();
            String::from_utf8_lossy(raw)
                .trim_matches('\0')
                .to_string()
        })
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "GPL".into());
    let maps = read_maps(bytes, sections.get("maps").copied(), &sections, shoff, shentsize, u32, u64)?;
    let relocs = relocations(bytes, prog_index, &maps, &sections, shoff, shentsize, u32, u64)?;
    Ok(ElfProg {
        insns,
        license,
        maps,
        relocs,
        prog_type,
    })
}

fn patch_map_fds(prog: &mut ElfProg) {
    for (offset, map_offset) in prog.relocs.clone() {
        let Some(fd) = prog
            .maps
            .iter()
            .find(|item| item.offset == map_offset)
            .map(|item| item.fd)
        else {
            continue;
        };
        if offset + 8 > prog.insns.len() {
            continue;
        }
        prog.insns[offset + 1] = (prog.insns[offset + 1] & 0x0f) | (1 << 4);
        prog.insns[offset + 4..offset + 8].copy_from_slice(&(fd as u32).to_le_bytes());
    }
}

fn read_maps(
    bytes: &[u8],
    maps_index: Option<usize>,
    sections: &HashMap<String, usize>,
    shoff: usize,
    shentsize: usize,
    u32: impl Fn(usize) -> u32,
    u64: impl Fn(usize) -> u64,
) -> Result<Vec<MapDef>> {
    let Some(index) = maps_index else {
        return Ok(Vec::new());
    };
    let off = shoff + index * shentsize;
    let start = u64(off + 24) as usize;
    let size = u64(off + 32) as usize;
    let body = bytes
        .get(start..start + size)
        .ok_or_else(|| Error::Message("maps 节越界".into()))?;
    let symtab = sections
        .get(".symtab")
        .copied()
        .ok_or_else(|| Error::Message("缺少符号表".into()))?;
    let strtab = sections
        .get(".strtab")
        .copied()
        .ok_or_else(|| Error::Message("缺少字符串表".into()))?;
    let sym_off = shoff + symtab * shentsize;
    let sym_start = u64(sym_off + 24) as usize;
    let sym_size = u64(sym_off + 32) as usize;
    let syms = &bytes[sym_start..sym_start + sym_size];
    let str_off = shoff + strtab * shentsize;
    let str_start = u64(str_off + 24) as usize;
    let str_size = u64(str_off + 32) as usize;
    let strings = &bytes[str_start..str_start + str_size];
    let mut maps = Vec::new();
    let mut cursor = 0;
    while cursor + 24 <= syms.len() {
        let name_off = u32::from_le_bytes(syms[cursor..cursor + 4].try_into().unwrap()) as usize;
        let info = syms[cursor + 4];
        let shndx = u16::from_le_bytes(syms[cursor + 6..cursor + 8].try_into().unwrap()) as usize;
        let value = u64::from_le_bytes(syms[cursor + 8..cursor + 16].try_into().unwrap()) as usize;
        let bind = info >> 4;
        if shndx == index && bind == 1 && value + 20 <= body.len() {
            let def = &body[value..value + 20];
            let name_end = strings[name_off..]
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(0);
            let name = String::from_utf8_lossy(&strings[name_off..name_off + name_end]).into_owned();
            maps.push(MapDef {
                name,
                offset: value,
                map_type: u32::from_le_bytes(def[0..4].try_into().unwrap()),
                key_size: u32::from_le_bytes(def[4..8].try_into().unwrap()),
                value_size: u32::from_le_bytes(def[8..12].try_into().unwrap()),
                max_entries: u32::from_le_bytes(def[12..16].try_into().unwrap()),
                fd: -1,
            });
        }
        cursor += 24;
    }
    if maps.is_empty() {
        return Err(Error::Message("没有找到 BPF map".into()));
    }
    Ok(maps)
}

fn relocations(
    bytes: &[u8],
    prog_index: usize,
    maps: &[MapDef],
    sections: &HashMap<String, usize>,
    shoff: usize,
    shentsize: usize,
    u32: impl Fn(usize) -> u32,
    u64: impl Fn(usize) -> u64,
) -> Result<Vec<(usize, usize)>> {
    let rel_name = format!(".rel{}", section_name(bytes, prog_index, shoff, shentsize, u32, &u64)?);
    let Some(rel_index) = sections.get(&rel_name).copied() else {
        return Ok(Vec::new());
    };
    let off = shoff + rel_index * shentsize;
    let start = u64(off + 24) as usize;
    let size = u64(off + 32) as usize;
    let rels = bytes
        .get(start..start + size)
        .ok_or_else(|| Error::Message("重定位节越界".into()))?;
    let symtab = *sections
        .get(".symtab")
        .ok_or_else(|| Error::Message("缺少符号表".into()))?;
    let sym_off = shoff + symtab * shentsize;
    let sym_start = u64(sym_off + 24) as usize;
    let syms = &bytes[sym_start..sym_start + u64(sym_off + 32) as usize];
    let mut found = Vec::new();
    let mut cursor = 0;
    while cursor + 16 <= rels.len() {
        let r_offset = u64::from_le_bytes(rels[cursor..cursor + 8].try_into().unwrap()) as usize;
        let r_info = u64::from_le_bytes(rels[cursor + 8..cursor + 16].try_into().unwrap());
        let r_type = r_info as u32;
        let r_sym = (r_info >> 32) as usize;
        if r_type == R_BPF_64_64 {
            let sym = r_sym * 24;
            if sym + 16 > syms.len() {
                return Err(Error::Message("重定位符号越界".into()));
            }
            let value = u64::from_le_bytes(syms[sym + 8..sym + 16].try_into().unwrap()) as usize;
            if !maps.iter().any(|item| item.offset == value) {
                return Err(Error::Message("重定位指向了未知 map".into()));
            }
            found.push((r_offset, value));
        }
        cursor += 16;
    }
    Ok(found)
}

fn section_name(
    bytes: &[u8],
    index: usize,
    shoff: usize,
    shentsize: usize,
    u32: impl Fn(usize) -> u32,
    u64: &impl Fn(usize) -> u64,
) -> Result<String> {
    let shstrndx = u16::from_le_bytes(bytes[62..64].try_into().unwrap()) as usize;
    let str_off = shoff + shstrndx * shentsize;
    let str_start = u64(str_off + 24) as usize;
    let str_size = u64(str_off + 32) as usize;
    let shstr = &bytes[str_start..str_start + str_size];
    let name_off = u32(shoff + index * shentsize) as usize;
    let end = shstr[name_off..]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(0);
    Ok(String::from_utf8_lossy(&shstr[name_off..name_off + end]).into_owned())
}

fn load_maps(prog: &mut ElfProg) -> Result<()> {
    for map in &mut prog.maps {
        let mut name = [0u8; 16];
        let bytes = map.name.as_bytes();
        let n = bytes.len().min(15);
        name[..n].copy_from_slice(&bytes[..n]);
        #[repr(C)]
        struct Attr {
            map_type: u32,
            key_size: u32,
            value_size: u32,
            max_entries: u32,
            map_flags: u32,
            inner_map_fd: u32,
            numa_node: u32,
            map_name: [u8; 16],
        }
        let attr = Attr {
            map_type: map.map_type,
            key_size: map.key_size,
            value_size: map.value_size,
            max_entries: map.max_entries,
            map_flags: 0,
            inner_map_fd: 0,
            numa_node: 0,
            map_name: name,
        };
        let fd = bpf(BPF_MAP_CREATE, &attr)?;
        map.fd = fd;
    }
    Ok(())
}

fn load_program(prog: &ElfProg) -> Result<i32> {
    let mut log = vec![0u8; 64 * 1024];
    let license = std::ffi::CString::new(prog.license.clone()).unwrap_or_else(|_| {
        std::ffi::CString::new("GPL").expect("GPL")
    });
    #[repr(C)]
    struct Attr {
        prog_type: u32,
        insn_cnt: u32,
        insns: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log_buf: u64,
        kern_version: u32,
        prog_flags: u32,
        prog_name: [u8; 16],
    }
    let mut prog_name = [0u8; 16];
    let name = b"linji";
    prog_name[..name.len()].copy_from_slice(name);
    let attr = Attr {
        prog_type: prog.prog_type,
        insn_cnt: (prog.insns.len() / 8) as u32,
        insns: prog.insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 1,
        log_size: log.len() as u32,
        log_buf: log.as_mut_ptr() as u64,
        kern_version: 0,
        prog_flags: 0,
        prog_name,
    };
    match bpf(BPF_PROG_LOAD, &attr) {
        Ok(fd) => Ok(fd),
        Err(err) => {
            let text = String::from_utf8_lossy(&log);
            let text = text.trim_matches('\0').trim();
            let tail = text
                .lines()
                .rev()
                .take(8)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join(" ");
            if tail.is_empty() {
                Err(err)
            } else {
                Err(Error::Message(format!("{err} {tail}")))
            }
        }
    }
}

fn bpf<T>(cmd: u64, attr: &T) -> Result<i32> {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            attr as *const T,
            std::mem::size_of::<T>(),
        )
    };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        Err(Error::Message(format!("bpf 系统调用失败: {err}")))
    } else {
        Ok(rc as i32)
    }
}

fn map_update(fd: i32, key: &[u8], value: &[u8]) -> Result<()> {
    #[repr(C)]
    struct Attr {
        map_fd: u32,
        _pad: u32,
        key: u64,
        value: u64,
        flags: u64,
    }
    let attr = Attr {
        map_fd: fd as u32,
        _pad: 0,
        key: key.as_ptr() as u64,
        value: value.as_ptr() as u64,
        flags: 0,
    };
    bpf(BPF_MAP_UPDATE_ELEM, &attr).map(|_| ())
}

fn map_lookup(fd: i32, key: &[u8], value: &mut [u8]) -> bool {
    #[repr(C)]
    struct Attr {
        map_fd: u32,
        _pad: u32,
        key: u64,
        value: u64,
        flags: u64,
    }
    let attr = Attr {
        map_fd: fd as u32,
        _pad: 0,
        key: key.as_ptr() as u64,
        value: value.as_mut_ptr() as u64,
        flags: 0,
    };
    bpf(BPF_MAP_LOOKUP_ELEM, &attr).is_ok()
}

fn map_next(fd: i32, key: Option<&[u8]>, next: &mut [u8]) -> bool {
    #[repr(C)]
    struct Attr {
        map_fd: u32,
        _pad: u32,
        key: u64,
        next_key: u64,
    }
    let attr = Attr {
        map_fd: fd as u32,
        _pad: 0,
        key: key.map(|item| item.as_ptr() as u64).unwrap_or(0),
        next_key: next.as_mut_ptr() as u64,
    };
    bpf(BPF_MAP_GET_NEXT_KEY, &attr).is_ok()
}

fn attach(kind: &str, prog_fd: i32, pid: Option<i32>) -> Result<Vec<i32>> {
    if kind == "oncpu" {
        return attach_oncpu(prog_fd, pid);
    }
    attach_offcpu(prog_fd)
}

fn attach_oncpu(prog_fd: i32, pid: Option<i32>) -> Result<Vec<i32>> {
    let mut attr = [0u8; 128];
    attr[0..4].copy_from_slice(&PERF_TYPE_SOFTWARE.to_le_bytes());
    attr[4..8].copy_from_slice(&128u32.to_le_bytes());
    attr[16..24].copy_from_slice(&49u64.to_le_bytes());
    let mut flags = 1u64 << 10;
    if pid.is_some() {
        flags |= 1 << 1;
    }
    attr[40..48].copy_from_slice(&flags.to_le_bytes());
    let targets = match pid {
        Some(pid) => task_ids(pid),
        None => vec![-1],
    };
    if targets.is_empty() {
        return Err(Error::Message("进程已经退出，不能采样".into()));
    }
    let mut fds = Vec::new();
    for tid in targets {
        let cpu = if tid < 0 { 0 } else { -1 };
        let fd = perf_open(attr.as_ptr(), tid, cpu)?;
        set_bpf(fd, prog_fd)?;
        fds.push(fd);
    }
    if pid.is_none() {
        // 上面只开了 cpu 0。系统级采样补齐其余 CPU。
        let mut rest = Vec::new();
        for cpu in online_cpus().into_iter().skip(1) {
            let fd = perf_open(attr.as_ptr(), -1, cpu as i32)?;
            set_bpf(fd, prog_fd)?;
            rest.push(fd);
        }
        fds.extend(rest);
    }
    Ok(fds)
}

fn attach_offcpu(prog_fd: i32) -> Result<Vec<i32>> {
    let id_text = fs::read_to_string("/sys/kernel/tracing/events/sched/sched_switch/id")
        .or_else(|_| fs::read_to_string("/sys/kernel/debug/tracing/events/sched/sched_switch/id"))
        .map_err(|_| Error::Message("读不到 sched_switch tracepoint".into()))?;
    let id: u64 = id_text
        .trim()
        .parse()
        .map_err(|_| Error::Message("sched_switch id 无法解析".into()))?;
    let mut attr = [0u8; 128];
    attr[0..4].copy_from_slice(&PERF_TYPE_TRACEPOINT.to_le_bytes());
    attr[4..8].copy_from_slice(&128u32.to_le_bytes());
    attr[8..16].copy_from_slice(&id.to_le_bytes());
    attr[16..24].copy_from_slice(&1u64.to_le_bytes());
    attr[40..48].copy_from_slice(&1u64.to_le_bytes());
    let mut fds = Vec::new();
    for cpu in online_cpus() {
        let fd = perf_open(attr.as_ptr(), -1, cpu as i32)?;
        set_bpf(fd, prog_fd)?;
        fds.push(fd);
    }
    Ok(fds)
}

fn task_ids(pid: i32) -> Vec<i32> {
    let mut ids = Vec::new();
    if let Ok(entries) = fs::read_dir(format!("/proc/{pid}/task")) {
        for entry in entries.flatten() {
            if let Ok(tid) = entry.file_name().to_string_lossy().parse::<i32>() {
                ids.push(tid);
            }
        }
    }
    if ids.is_empty() && crate::procs::proc_exists(pid) {
        ids.push(pid);
    }
    ids.truncate(256);
    ids
}

fn online_cpus() -> Vec<usize> {
    let text = fs::read_to_string("/sys/devices/system/cpu/online").unwrap_or_else(|_| "0".into());
    let mut cpus = Vec::new();
    for part in text.trim().split(',') {
        if let Some((start, end)) = part.split_once('-') {
            let start: usize = start.parse().unwrap_or(0);
            let end: usize = end.parse().unwrap_or(start);
            cpus.extend(start..=end);
        } else if let Ok(cpu) = part.parse::<usize>() {
            cpus.push(cpu);
        }
    }
    if cpus.is_empty() {
        cpus.push(0);
    }
    cpus
}

fn perf_open(attr: *const u8, pid: i32, cpu: i32) -> Result<i32> {
    let fd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            attr,
            pid,
            cpu,
            -1i32,
            PERF_FLAG_FD_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(Error::Message(format!(
            "perf_event_open 失败: {}",
            std::io::Error::last_os_error()
        )))
    } else {
        Ok(fd as i32)
    }
}

fn set_bpf(event: i32, prog: i32) -> Result<()> {
    let rc = unsafe { libc::ioctl(event, PERF_EVENT_IOC_SET_BPF, prog) };
    if rc < 0 {
        return Err(Error::Message(format!(
            "挂载 BPF 程序失败: {}",
            std::io::Error::last_os_error()
        )));
    }
    let rc = unsafe { libc::ioctl(event, PERF_EVENT_IOC_ENABLE, 0) };
    if rc < 0 {
        return Err(Error::Message(format!(
            "启用采样失败: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn fold_oncpu(prog: &ElfProg, table: &Kallsyms) -> Result<String> {
    let counts = prog
        .maps
        .iter()
        .find(|item| item.name == "counts")
        .ok_or_else(|| Error::Message("缺少 counts map".into()))?;
    let stacks = prog
        .maps
        .iter()
        .find(|item| item.name == "stacks")
        .ok_or_else(|| Error::Message("缺少 stacks map".into()))?;
    let mut folded: HashMap<String, u64> = HashMap::new();
    let mut key = vec![0u8; counts.key_size as usize];
    let mut next = vec![0u8; counts.key_size as usize];
    let mut have = false;
    loop {
        let prev = if have { Some(key.as_slice()) } else { None };
        if !map_next(counts.fd, prev, &mut next) {
            break;
        }
        key.copy_from_slice(&next);
        have = true;
        let mut value = [0u8; 8];
        if !map_lookup(counts.fd, &key, &mut value) {
            continue;
        }
        let count = u64::from_ne_bytes(value);
        if count == 0 || key.len() < 28 {
            continue;
        }
        let pid = i32::from_ne_bytes(key[0..4].try_into().unwrap());
        let kern = i32::from_ne_bytes(key[4..8].try_into().unwrap());
        let user = i32::from_ne_bytes(key[8..12].try_into().unwrap());
        let comm = cstr(&key[12..28]);
        let mut frames = Vec::new();
        frames.extend(stack_frames(stacks.fd, user, pid, table, true));
        frames.extend(stack_frames(stacks.fd, kern, pid, table, false));
        if frames.is_empty() {
            frames.push(comm.clone());
        }
        let line = format!("{comm};{}", frames.join(";"));
        *folded.entry(line).or_insert(0) += count;
    }
    Ok(format_folded(&folded))
}

fn fold_offcpu(prog: &ElfProg, table: &Kallsyms) -> Result<String> {
    let off = prog
        .maps
        .iter()
        .find(|item| item.name == "off_ns")
        .ok_or_else(|| Error::Message("缺少 off_ns map".into()))?;
    let mut folded: HashMap<String, u64> = HashMap::new();
    let key_size = off.key_size as usize;
    let mut key = vec![0u8; key_size];
    let mut next = vec![0u8; key_size];
    let mut have = false;
    loop {
        let prev = if have { Some(key.as_slice()) } else { None };
        if !map_next(off.fd, prev, &mut next) {
            break;
        }
        key.copy_from_slice(&next);
        have = true;
        let mut value = [0u8; 8];
        if !map_lookup(off.fd, &key, &mut value) {
            continue;
        }
        let ns = u64::from_ne_bytes(value);
        if ns == 0 || key.len() < 24 {
            continue;
        }
        let comm = cstr(&key[0..16]);
        let pid = u32::from_ne_bytes(key[16..20].try_into().unwrap()) as i32;
        let nr = u32::from_ne_bytes(key[20..24].try_into().unwrap()) as usize;
        let mut frames = Vec::new();
        let ips = key.get(24..).unwrap_or_default();
        for index in 0..nr.min(ips.len() / 8) {
            let ip = u64::from_ne_bytes(ips[index * 8..index * 8 + 8].try_into().unwrap());
            if ip == 0 {
                continue;
            }
            frames.push(symbolize(ip, pid, table, false));
        }
        frames.reverse();
        if frames.is_empty() {
            frames.push(comm.clone());
        }
        let line = format!("{comm};{}", frames.join(";"));
        *folded.entry(line).or_insert(0) += ns;
    }
    Ok(format_folded(&folded))
}

fn stack_frames(fd: i32, id: i32, pid: i32, table: &Kallsyms, user: bool) -> Vec<String> {
    if id < 0 {
        return Vec::new();
    }
    let mut raw = vec![0u8; 32 * 8];
    if !map_lookup(fd, &id.to_ne_bytes(), &mut raw) {
        return Vec::new();
    }
    let mut frames = Vec::new();
    for index in 0..32 {
        let ip = u64::from_ne_bytes(raw[index * 8..index * 8 + 8].try_into().unwrap());
        if ip == 0 {
            break;
        }
        frames.push(symbolize(ip, pid, table, user));
    }
    frames.reverse();
    frames
}

fn symbolize(ip: u64, pid: i32, table: &Kallsyms, user: bool) -> String {
    if !user {
        if let Some(name) = table.lookup(ip) {
            return name.to_string();
        }
    } else if let Some(name) = user_symbol(pid, ip) {
        return name;
    }
    format!("0x{ip:x}")
}

fn user_symbol(pid: i32, ip: u64) -> Option<String> {
    let text = fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let range = parts.next()?;
        let _perm = parts.next()?;
        let offset = parts.next()?;
        let _dev = parts.next()?;
        let _inode = parts.next()?;
        let path = parts.next().unwrap_or("");
        let (start, end) = range.split_once('-')?;
        let start = u64::from_str_radix(start, 16).ok()?;
        let end = u64::from_str_radix(end, 16).ok()?;
        if ip < start || ip >= end {
            continue;
        }
        let offset = u64::from_str_radix(offset, 16).ok().unwrap_or(0);
        let file_off = ip - start + offset;
        let base = path.rsplit('/').next().unwrap_or(path);
        if base.is_empty() {
            return Some(format!("0x{ip:x}"));
        }
        return Some(format!("{base}+0x{file_off:x}"));
    }
    None
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

fn format_folded(folded: &HashMap<String, u64>) -> String {
    if folded.is_empty() {
        return "这一窗口没有采到栈。权限不够时需要 root 或 CAP_BPF、CAP_PERFMON。".into();
    }
    let mut rows: Vec<_> = folded.iter().collect();
    rows.sort_by(|left, right| right.1.cmp(left.1));
    rows.into_iter()
        .map(|(stack, count)| format!("{stack} {count}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::parse_prog;

    #[test]
    fn embedded_object_has_maps_and_license() {
        if !cfg!(linji_ebpf) {
            return;
        }
        let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/oncpu.bpf.o"));
        let prog = parse_prog(bytes, 7).unwrap();
        assert!(prog.license.contains("GPL"));
        assert!(prog.insns.len() > 8);
        assert!(prog.maps.iter().any(|item| item.name == "stacks"));
        assert!(prog.maps.iter().any(|item| item.name == "counts"));
    }
}
