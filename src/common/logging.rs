/*！

本模块利用 log crate 为你提供了日志功能，使用方式见 lib.

*/

use log::{self, Level, LevelFilter, Log, Metadata, Record};

use crate::println;
use super::utils::cpu_id;

use spin::Mutex;

static LOG_MUTEX: Mutex<()> = Mutex::new(());
struct SimpleLogger;

impl Log for SimpleLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }
    fn log(&self, record: &Record) {
        let _lock = LOG_MUTEX.lock();
        if !self.enabled(record.metadata()) {
            return;
        }
        let color = match record.level() {
            Level::Error => 31, // Red
            Level::Warn => 93,  // BrightYellow
            Level::Info => 34,  // Blue
            Level::Debug => 32, // Green
            Level::Trace => 90, // BrightBlack
        };
        println!(
            "\u{1B}[{}m[{:>5} {}] {}\u{1B}[0m",
            color,
            record.level(),
            cpu_id(),
            record.args(),
        );
    }
    fn flush(&self) {
        let _lock = LOG_MUTEX.lock();
    }
}

pub fn init() {
    static LOGGER: SimpleLogger = SimpleLogger;
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(match option_env!("LOG") {
        Some("ERROR") => LevelFilter::Error,
        Some("WARN") => LevelFilter::Warn,
        Some("INFO") => LevelFilter::Info,
        Some("DEBUG") => LevelFilter::Debug,
        Some("TRACE") => LevelFilter::Trace,
        _ => LevelFilter::Debug,
    });
}