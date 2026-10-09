# linuxtui

我把这个工具放在一台 Linux 上。打开先进入导航：硬件、进程、容器、防火墙、网络、日志。性能定位、等保基线和抓包都在里面，所以不再叫 linperf。名字就是 linuxtui，没有对应的中文名。

命令是 `linuxtui`。采集只读 `/proc`、`/sys` 和 cgroup。发行版不同时按内核能力降级：没有 PSI、只有 cgroup v1、或者内核太旧，计数分析仍然可用。`linuxtui check` 会写出这台机器实际走哪条路径。

界面以导航为入口。`1` 到 `6` 进入各块，`j` / `k` 移动，回车进入。性能结论里，证据和下一步跟着当前选中的那条变。

研制过程见 [docs/研制记录.md](docs/研制记录.md)。

版权所有 © 2026 lei <mr.greevsky@gmail.com>
https://github.com/greevsky/linperf

在 Linux 上：

```bash
cargo test
cargo build --release
./target/release/linuxtui
./target/release/linuxtui check
./target/release/linuxtui snapshot
./target/release/linuxtui baseline
./target/release/linuxtui flame --demo -o /tmp/linuxtui.svg
```

`profile oncpu` / `profile offcpu` 要等 eBPF 字节码编进这个二进制之后才能采样。现在运行它会说明缺什么。
