use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    for name in ["oncpu.bpf.c", "offcpu.bpf.c"] {
        println!("cargo:rerun-if-changed=bpf/{name}");
    }
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_define = match arch.as_str() {
        "aarch64" => "-D__TARGET_ARCH_arm64",
        "arm" => "-D__TARGET_ARCH_arm",
        _ => "-D__TARGET_ARCH_x86",
    };
    let mut includes = vec!["-I/usr/include".to_string()];
    if let Some(triple) = env::var("CARGO_CFG_TARGET_ARCH").ok().as_deref() {
        let arch_include = match triple {
            "x86_64" => "/usr/include/x86_64-linux-gnu",
            "aarch64" => "/usr/include/aarch64-linux-gnu",
            _ => "",
        };
        if !arch_include.is_empty() && PathBuf::from(arch_include).join("asm/types.h").is_file() {
            includes.insert(0, format!("-I{arch_include}"));
        }
    }
    for name in ["oncpu", "offcpu"] {
        let src = manifest.join("bpf").join(format!("{name}.bpf.c"));
        let dest = out.join(format!("{name}.bpf.o"));
        let mut cmd = Command::new("clang");
        cmd.arg("-O2")
            .arg("-g")
            .arg("-target")
            .arg("bpf")
            .arg(target_define)
            .args(&includes)
            .arg("-c")
            .arg(&src)
            .arg("-o")
            .arg(&dest);
        let status = cmd.status().unwrap_or_else(|err| {
            panic!("无法运行 clang 来编译 {name}.bpf.c: {err}");
        });
        if !status.success() {
            panic!("编译 bpf/{name}.bpf.c 失败");
        }
    }
    println!("cargo:rustc-cfg=linuxtui_ebpf");
}
