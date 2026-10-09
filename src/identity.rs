pub const PRODUCT: &str = "linuxtui";
pub const COMMAND: &str = "linuxtui";
pub const AUTHOR: &str = "lei <mr.greevsky@gmail.com>";
pub const REPOSITORY: &str = "https://github.com/greevsky/linperf";

pub fn copyright() -> String {
    format!("版权所有 © 2026 {AUTHOR}")
}

pub fn sign(lines: &mut Vec<String>) {
    lines.push(String::new());
    lines.push(copyright());
    lines.push(REPOSITORY.into());
}
