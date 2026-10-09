fn main() {
    if let Err(err) = linuxtui::cli_main() {
        eprintln!("{}: {err}", linuxtui::COMMAND);
        std::process::exit(1);
    }
}
