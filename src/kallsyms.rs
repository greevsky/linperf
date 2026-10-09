#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Kallsyms {
    entries: Vec<(u64, String)>,
}

#[allow(dead_code)]
impl Kallsyms {
    pub fn parse(text: &str) -> Self {
        let mut entries = Vec::new();
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let Some(addr) = parts.next().and_then(|item| u64::from_str_radix(item, 16).ok()) else {
                continue;
            };
            let Some(_kind) = parts.next() else {
                continue;
            };
            let Some(name) = parts.next() else {
                continue;
            };
            if addr == 0 {
                continue;
            }
            entries.push((addr, name.to_string()));
        }
        entries.sort_by_key(|(addr, _)| *addr);
        entries.dedup_by_key(|(addr, _)| *addr);
        Self { entries }
    }

    pub fn lookup(&self, ip: u64) -> Option<&str> {
        if self.entries.is_empty() || ip < self.entries[0].0 {
            return None;
        }
        let idx = self.entries.partition_point(|(addr, _)| *addr <= ip);
        self.entries.get(idx - 1).map(|(_, name)| name.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_symbol_at_or_below_the_address() {
        let table = Kallsyms::parse(
            "\
0000000000000000 t ignore_me
ffffffff81000000 T startup
ffffffff81001000 T do_wait
ffffffff81002000 T io_schedule
",
        );
        assert_eq!(table.lookup(0xffff_ffff_8100_1010), Some("do_wait"));
        assert_eq!(table.lookup(0xffff_ffff_8100_0000), Some("startup"));
        assert_eq!(table.lookup(0x1000), None);
    }
}
