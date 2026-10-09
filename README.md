# linperf

在一台 Linux 上快速定位性能瓶颈。打开先看到结论、证据和下一步，指标留在旁边做对照。用来做现场排查，结论要能回到采样窗口里的计数。

采集只读 `/proc`、`/sys` 和 cgroup。发行版不同时按内核能力降级：没有 PSI、只有 cgroup v1、或者内核太旧，计数分析仍然可用。`linperf check` 会写出当前机器实际走哪条路径。

界面以当前选中的结论为第一眼。`j` / `k` 在结论之间切换，证据和下一步跟着变；仪表只高亮和这条结论相关的那一项。

研制范围见 [docs/研制记录.md](docs/研制记录.md)。

在 Linux 上：

```bash
cargo test
cargo build --release
./target/release/linperf check
./target/release/linperf snapshot
./target/release/linperf snapshot --demo
./target/release/linperf watch
./target/release/linperf flame --demo -o /tmp/linperf.svg
```

`profile oncpu` / `profile offcpu` 要等 eBPF 字节码编进这个二进制之后才能采样。现在运行它会说明缺什么。
