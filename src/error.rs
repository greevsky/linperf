use std::fmt;

#[derive(Debug)]
pub enum Error {
    NotLinux,
    Io(std::io::Error),
    Parse(String),
    NeedTwoSamples,
    Message(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotLinux => write!(f, "当前不是 Linux，不能做现场采集"),
            Error::Io(err) => write!(f, "读写失败: {err}"),
            Error::Parse(msg) => write!(f, "解析失败: {msg}"),
            Error::NeedTwoSamples => write!(f, "至少需要两个采样点才能计算速率"),
            Error::Message(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
