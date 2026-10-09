use std::fs;
use std::path::Path;

use serde::Serialize;

use crate::error::Result;

#[derive(Debug, Clone, Serialize)]
pub struct HostCaps {
    pub os: String,
    pub kernel: String,
    pub arch: String,
    pub procfs: bool,
    pub psi: bool,
    pub distro_id: String,
    pub cgroup_v2: bool,
    /// v2、v1、hybrid、none。hybrid 表示统一层级和 v1 控制器同时挂着。
    pub cgroup_layout: String,
    pub in_container: bool,
    pub cgroup_path: String,
    pub virt: String,
    pub perf_event_paranoid: Option<i32>,
    pub btf: bool,
    pub cap_bpf: bool,
    pub cap_perfmon: bool,
    pub cap_sys_admin: bool,
    pub ebpf_linked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectPlan {
    pub counters: bool,
    pub ebpf: bool,
    pub notes: Vec<String>,
}

impl HostCaps {
    pub fn plan(&self) -> CollectPlan {
        plan(self)
    }
}

pub fn plan(caps: &HostCaps) -> CollectPlan {
    let mut notes = Vec::new();
    if !caps.procfs {
        notes.push("读不到 /proc，计数分析不可用。".into());
    }
    if !caps.psi {
        let old_kernel = kernel_release_version(&caps.kernel)
            .is_some_and(|(major, minor)| major < 4 || (major == 4 && minor < 20));
        if old_kernel {
            notes.push("内核低于 4.20，没有 PSI。内存和 IO 停顿靠可用内存、换页和磁盘 util 判断。".into());
        } else {
            notes.push("没有 PSI。内存和 IO 停顿只能靠利用率间接判断。".into());
        }
    }
    match caps.cgroup_layout.as_str() {
        "v1" => notes.push(
            "cgroup v1：限流读 throttled_time，内存上限读 memory.limit_in_bytes。".into(),
        ),
        "hybrid" => notes.push(
            "cgroup 是混合层级。本进程在 v2 上有 cpu.stat 时用 v2，否则用 v1 控制器。".into(),
        ),
        "none" => notes.push("没有挂载 cgroup，限流和内存上限规则不会触发。".into()),
        _ => {}
    }
    if caps.in_container {
        notes.push(format!(
            "当前进程在 cgroup {} 里。/proc 里的 CPU 和磁盘多半仍是整机视角。",
            caps.cgroup_path
        ));
    }
    let privileged = caps.cap_sys_admin || (caps.cap_bpf && caps.cap_perfmon);
    if caps.ebpf_linked && caps.btf && privileged {
        notes.push("可以加载内置 eBPF，做 on-CPU 和 off-CPU。".into());
    } else if !caps.ebpf_linked {
        notes.push("这个二进制还没有嵌入 eBPF 字节码。计数和规则可用，profile 需要在 Linux 上重新构建。".into());
    } else if !caps.btf {
        notes.push("内核没有 BTF，eBPF CO-RE 不能加载。".into());
    } else {
        notes.push("缺少 CAP_SYS_ADMIN，或缺少 CAP_BPF 加 CAP_PERFMON，eBPF 采样加载不了。".into());
    }
    if let Some(level) = caps.perf_event_paranoid {
        if level > 1 && !caps.cap_sys_admin && !caps.cap_perfmon {
            notes.push(format!(
                "perf_event_paranoid={level}，普通用户打不开 CPU 性能事件。"
            ));
        }
    }
    CollectPlan {
        counters: caps.procfs,
        ebpf: caps.ebpf_linked && caps.btf && privileged,
        notes,
    }
}

pub fn format_check(caps: &HostCaps) -> String {
    let plan = caps.plan();
    let mode = if plan.ebpf {
        "eBPF + 计数器"
    } else if plan.counters {
        "仅计数器"
    } else {
        "无法采集"
    };
    let mut lines = vec![
        format!("{}  本机采集路径", crate::identity::PRODUCT),
        format!("系统    {} ({})", caps.os, caps.distro_id),
        format!("内核    {}", caps.kernel),
        format!("架构    {}", caps.arch),
        format!("虚拟化  {}", virt_label(&caps.virt)),
        format!("模式    {mode}"),
        format!("procfs  {}", yes(caps.procfs)),
        format!("PSI     {}", yes(caps.psi)),
        format!("层级    {}", layout_label(&caps.cgroup_layout)),
        format!("容器内  {}", yes(caps.in_container)),
        format!("cgroup  {}", caps.cgroup_path),
        format!(
            "paranoid {}",
            caps.perf_event_paranoid
                .map(|v| v.to_string())
                .unwrap_or_else(|| "未知".into())
        ),
        format!("BTF     {}", yes(caps.btf)),
        format!(
            "权限    bpf={} perfmon={} sys_admin={}",
            yes(caps.cap_bpf),
            yes(caps.cap_perfmon),
            yes(caps.cap_sys_admin)
        ),
        format!("eBPF 已编入 {}", yes(caps.ebpf_linked)),
        String::new(),
        "说明".into(),
    ];
    for note in plan.notes {
        lines.push(format!("- {note}"));
    }
    lines.push(String::new());
    lines.push("采集只读 /proc、/sys 和 cgroup，随内核能力降级。".into());
    crate::identity::sign(&mut lines);
    lines.join("\n")
}

pub fn parse_os_release(text: &str) -> Option<(String, String)> {
    let mut pretty = None;
    let mut name = None;
    let mut id = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("PRETTY_NAME=") {
            pretty = Some(unquote(value));
        } else if let Some(value) = line.strip_prefix("NAME=") {
            name = Some(unquote(value));
        } else if let Some(value) = line.strip_prefix("ID=") {
            id = Some(unquote(value));
        }
    }
    let pretty = pretty.or(name).or_else(|| id.clone())?;
    let id = id.unwrap_or_else(|| "linux".into());
    Some((pretty, id))
}

pub fn identify_os(
    os_release: Option<&str>,
    redhat: Option<&str>,
    alpine: Option<&str>,
    debian: Option<&str>,
) -> (String, String) {
    if let Some((pretty, id)) = os_release.and_then(parse_os_release) {
        return (pretty, id);
    }
    if let Some(line) = redhat.and_then(|text| text.lines().find(|line| !line.trim().is_empty())) {
        let id = if line.contains("CentOS") {
            "centos"
        } else if line.contains("Fedora") {
            "fedora"
        } else if line.contains("Alma") {
            "almalinux"
        } else if line.contains("Rocky") {
            "rocky"
        } else if line.contains("openEuler") {
            "openeuler"
        } else if line.contains("Anolis") {
            "anolis"
        } else if line.contains("Kylin") || line.contains("kylin") {
            "kylin"
        } else {
            "rhel"
        };
        return (line.trim().to_string(), id.into());
    }
    if let Some(ver) = alpine.and_then(|text| text.lines().next()) {
        let ver = ver.trim();
        if !ver.is_empty() {
            return (format!("Alpine Linux {ver}"), "alpine".into());
        }
    }
    if let Some(ver) = debian.and_then(|text| text.lines().next()) {
        let ver = ver.trim();
        if !ver.is_empty() {
            return (format!("Debian {ver}"), "debian".into());
        }
    }
    ("Linux".into(), "linux".into())
}

pub fn kernel_release_version(release: &str) -> Option<(u32, u32)> {
    let head = release.split(['-', '+']).next().unwrap_or(release);
    let mut parts = head.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor))
}

pub fn cgroup_layout_name(v2: bool, v1: bool) -> &'static str {
    match (v2, v1) {
        (true, true) => "hybrid",
        (true, false) => "v2",
        (false, true) => "v1",
        (false, false) => "none",
    }
}

pub fn classify_virt(hypervisor_flag: bool, xen: bool, product: &str, vendor: &str) -> &'static str {
    let text = format!("{product}\n{vendor}").to_ascii_lowercase();
    if xen || text.contains("xen") {
        return "xen";
    }
    if text.contains("vmware") {
        return "vmware";
    }
    if text.contains("virtualbox") {
        return "virtualbox";
    }
    if text.contains("hyper-v") || text.contains("microsoft corporation") {
        return "hyperv";
    }
    if text.contains("qemu") || text.contains("kvm") {
        return "kvm";
    }
    if hypervisor_flag {
        return "hypervisor";
    }
    "none"
}

fn unquote(value: &str) -> String {
    value.trim().trim_matches('"').trim().to_string()
}

fn virt_label(virt: &str) -> &str {
    match virt {
        "none" => "无",
        "kvm" => "KVM",
        "xen" => "Xen",
        "vmware" => "VMware",
        "virtualbox" => "VirtualBox",
        "hyperv" => "Hyper-V",
        "hypervisor" => "虚拟机",
        _ => virt,
    }
}

fn layout_label(layout: &str) -> &str {
    match layout {
        "v2" => "cgroup v2",
        "v1" => "cgroup v1",
        "hybrid" => "cgroup v1+v2 混合",
        "none" => "没有 cgroup",
        _ => layout,
    }
}

pub fn detect() -> Result<HostCaps> {
    #[cfg(target_os = "linux")]
    {
        Ok(detect_linux())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(HostCaps {
            os: std::env::consts::OS.into(),
            distro_id: std::env::consts::OS.into(),
            kernel: "unknown".into(),
            arch: std::env::consts::ARCH.into(),
            procfs: false,
            psi: false,
            cgroup_v2: false,
            cgroup_layout: "none".into(),
            in_container: false,
            cgroup_path: String::new(),
            virt: "none".into(),
            perf_event_paranoid: None,
            btf: false,
            cap_bpf: false,
            cap_perfmon: false,
            cap_sys_admin: false,
            ebpf_linked: cfg!(linji_ebpf),
        })
    }
}

#[cfg(target_os = "linux")]
fn detect_linux() -> HostCaps {
    let os_release = fs::read_to_string("/etc/os-release").ok();
    let redhat = fs::read_to_string("/etc/redhat-release")
        .ok()
        .or_else(|| fs::read_to_string("/etc/centos-release").ok());
    let alpine = fs::read_to_string("/etc/alpine-release").ok();
    let debian = fs::read_to_string("/etc/debian_version").ok();
    let (os, distro_id) = identify_os(
        os_release.as_deref(),
        redhat.as_deref(),
        alpine.as_deref(),
        debian.as_deref(),
    );
    let kernel = read_trimmed("/proc/sys/kernel/osrelease").unwrap_or_else(|| "unknown".into());
    let cgroup_text = fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    let cgroup_path = crate::parse::parse_cgroup_path(&cgroup_text).unwrap_or_else(|| "/".into());
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let eff = cap_eff(&status);
    let paranoid = read_trimmed("/proc/sys/kernel/perf_event_paranoid").and_then(|text| text.parse().ok());
    let v2 = v2_mount().is_some();
    let v1 = v1_mounted();
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let product = read_trimmed("/sys/class/dmi/id/product_name").unwrap_or_default();
    let vendor = read_trimmed("/sys/class/dmi/id/sys_vendor").unwrap_or_default();
    let xen = Path::new("/proc/xen").exists() || Path::new("/sys/hypervisor/type").is_file();
    HostCaps {
        os,
        distro_id,
        kernel,
        arch: std::env::consts::ARCH.into(),
        procfs: Path::new("/proc/stat").is_file(),
        psi: Path::new("/proc/pressure/cpu").is_file()
            || Path::new("/proc/pressure/io").is_file()
            || Path::new("/proc/pressure/memory").is_file(),
        cgroup_v2: v2,
        cgroup_layout: cgroup_layout_name(v2, v1).into(),
        in_container: container_cgroup(&cgroup_text)
            || Path::new("/.dockerenv").exists()
            || Path::new("/run/.containerenv").exists(),
        cgroup_path,
        virt: classify_virt(cpuinfo.contains("hypervisor"), xen, &product, &vendor).into(),
        perf_event_paranoid: paranoid,
        btf: Path::new("/sys/kernel/btf/vmlinux").is_file(),
        cap_bpf: has_cap(eff, 39),
        cap_perfmon: has_cap(eff, 38),
        cap_sys_admin: has_cap(eff, 21),
        ebpf_linked: cfg!(linji_ebpf),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn v2_mount() -> Option<&'static str> {
    for root in ["/sys/fs/cgroup", "/sys/fs/cgroup/unified"] {
        if Path::new(root).join("cgroup.controllers").is_file() {
            return Some(root);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn v1_mounted() -> bool {
    [
        "/sys/fs/cgroup/cpu/cpu.stat",
        "/sys/fs/cgroup/cpu,cpuacct/cpu.stat",
        "/sys/fs/cgroup/memory/memory.usage_in_bytes",
    ]
    .iter()
    .any(|path| Path::new(path).is_file())
}

#[cfg(target_os = "linux")]
fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

fn cap_eff(status: &str) -> u64 {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:") {
            let hex = rest.trim();
            let hex = if hex.len() > 16 {
                &hex[hex.len() - 16..]
            } else {
                hex
            };
            return u64::from_str_radix(hex, 16).unwrap_or(0);
        }
    }
    0
}

fn has_cap(eff: u64, cap: u32) -> bool {
    cap < 64 && eff & (1u64 << cap) != 0
}

pub fn container_cgroup(path: &str) -> bool {
    ["docker", "kubepods", "containerd", "libpod", "/lxc/", "crio-", "podman"]
        .iter()
        .any(|marker| path.contains(marker))
}

fn yes(value: bool) -> &'static str {
    if value {
        "是"
    } else {
        "否"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps() -> HostCaps {
        HostCaps {
            os: "Ubuntu".into(),
            distro_id: "ubuntu".into(),
            kernel: "6.8.0".into(),
            arch: "x86_64".into(),
            procfs: true,
            psi: true,
            cgroup_v2: true,
            cgroup_layout: "v2".into(),
            in_container: false,
            cgroup_path: "/".into(),
            virt: "none".into(),
            perf_event_paranoid: Some(4),
            btf: true,
            cap_bpf: false,
            cap_perfmon: false,
            cap_sys_admin: false,
            ebpf_linked: false,
        }
    }

    #[test]
    fn root_with_bytecode_enables_ebpf() {
        let mut host = caps();
        host.cap_sys_admin = true;
        host.ebpf_linked = true;
        let plan = plan(&host);
        assert!(plan.counters);
        assert!(plan.ebpf);
    }

    #[test]
    fn missing_bytecode_stays_on_counters() {
        let plan = plan(&caps());
        assert!(plan.counters);
        assert!(!plan.ebpf);
        assert!(plan.notes.iter().any(|note| note.contains("没有嵌入 eBPF")));
    }

    #[test]
    fn user_slice_is_not_a_container() {
        assert!(!container_cgroup("/user.slice/user-1000.slice/session-1.scope"));
        assert!(container_cgroup("/system.slice/docker-abc.scope"));
    }

    #[test]
    fn cap_eff_reads_low_64_bits() {
        let status = "CapEff:\t000001ffffffffff\n";
        let eff = cap_eff(status);
        assert!(has_cap(eff, 21));
        assert!(has_cap(eff, 38));
        assert!(has_cap(eff, 39));
    }

    #[test]
    fn identifies_common_distro_files() {
        let ubuntu = "NAME=\"Ubuntu\"\nID=ubuntu\nPRETTY_NAME=\"Ubuntu 24.04.4 LTS\"\n";
        assert_eq!(
            identify_os(Some(ubuntu), None, None, None),
            ("Ubuntu 24.04.4 LTS".into(), "ubuntu".into())
        );
        assert_eq!(
            identify_os(None, Some("CentOS Linux release 7.9.2009 (Core)\n"), None, None),
            ("CentOS Linux release 7.9.2009 (Core)".into(), "centos".into())
        );
        assert_eq!(
            identify_os(None, None, Some("3.19.1\n"), None),
            ("Alpine Linux 3.19.1".into(), "alpine".into())
        );
        assert_eq!(
            identify_os(None, Some("openEuler release 22.03 LTS\n"), None, None),
            ("openEuler release 22.03 LTS".into(), "openeuler".into())
        );
    }

    #[test]
    fn kernel_and_virt_and_layout() {
        assert_eq!(kernel_release_version("3.10.0-1160.el7.x86_64"), Some((3, 10)));
        assert_eq!(kernel_release_version("6.8.0-136-generic"), Some((6, 8)));
        assert_eq!(cgroup_layout_name(true, true), "hybrid");
        assert_eq!(classify_virt(true, false, "KVM", "QEMU"), "kvm");
        assert_eq!(classify_virt(false, false, "OptiPlex", "Dell Inc."), "none");
        let mut old = caps();
        old.psi = false;
        old.kernel = "3.10.0-1160.el7.x86_64".into();
        old.cgroup_v2 = false;
        old.cgroup_layout = "v1".into();
        let plan = plan(&old);
        assert!(plan.notes.iter().any(|note| note.contains("4.20")));
        assert!(plan.notes.iter().any(|note| note.contains("cgroup v1")));
    }
}
