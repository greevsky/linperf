use crate::error::{Error, Result};

pub fn sample_folded(kind: &str, seconds: u64) -> Result<String> {
    let _ = (kind, seconds);
    Err(Error::Message(
        "这个构建还没有嵌入 eBPF 字节码。计数、规则和火焰图绘制已经可以离线使用；on-CPU / off-CPU 采样要在这台 Linux 上把 bpf 程序编进二进制后再运行。".into(),
    ))
}
