fn main() {
    if let Err(err) = linji::cli_main() {
        eprintln!("{}: {err}", linji::COMMAND);
        std::process::exit(1);
    }
}
