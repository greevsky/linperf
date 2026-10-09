fn main() {
    if let Err(err) = linperf::cli_main() {
        eprintln!("linperf: {err}");
        std::process::exit(1);
    }
}
