use std::fs;
use std::io::{Cursor, Write};
use std::path::Path;

use crate::demo;
use crate::error::{Error, Result};

pub fn render_folded(folded: &str, title: &str, out: &Path) -> Result<()> {
    let mut options = inferno::flamegraph::Options::default();
    options.title = title.to_string();
    options.count_name = "samples".into();
    let mut file = fs::File::create(out)?;
    inferno::flamegraph::from_reader(&mut options, Cursor::new(folded.as_bytes()), &mut file)
        .map_err(|err| Error::Message(format!("火焰图生成失败: {err}")))?;
    file.flush()?;
    Ok(())
}

pub fn render_demo(out: &Path) -> Result<()> {
    render_folded(demo::demo_folded(), "linuxtui off-CPU 演示", out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_svg_contains_the_sleeping_frames() {
        let path = std::env::temp_dir().join("linuxtui-demo-flame.svg");
        render_demo(&path).unwrap();
        let svg = fs::read_to_string(&path).unwrap();
        assert!(svg.contains("<svg"));
        assert!(svg.contains("wait_on_page_bit"));
        let _ = fs::remove_file(path);
    }
}
