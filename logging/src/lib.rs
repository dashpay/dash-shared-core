#[cfg(target_os = "ios")]
use tracing::{error, warn, info, debug};

#[cfg(target_os = "ios")]
use std::sync::Once;

#[cfg(target_os = "ios")]
use std::path::PathBuf;

#[cfg(target_os = "ios")]
use dirs::document_dir;

#[cfg(target_os = "ios")]
use std::fs::{File, OpenOptions};

#[cfg(target_os = "ios")]
use std::io::{Write, Result};  // Importing std::io::Result only for iOS

#[cfg(target_os = "ios")]
use std::sync::Mutex;

#[cfg(target_os = "ios")]
use tracing_subscriber::fmt::writer::BoxMakeWriter;

#[cfg(target_os = "ios")]
use tracing_subscriber::fmt::{MakeWriter, SubscriberBuilder};

#[cfg(target_os = "ios")]
use tracing_appender::rolling::{RollingFileAppender, Rotation};

#[cfg(target_os = "ios")]
static INIT: Once = Once::new();

// Function to initialize logging
// Custom MakeWriter struct that holds a Mutex around a File
#[cfg(target_os = "ios")]
#[allow(unused)]
struct MutexMakeWriter {
    file: Mutex<File>,
}

#[cfg(target_os = "ios")]
impl MutexMakeWriter {
    #[allow(unused)]
    fn new(file: File) -> Self {
        Self {
            file: Mutex::new(file),
        }
    }
}

// Implement MakeWriter for MutexMakeWriter to be used in tracing_subscriber
#[cfg(target_os = "ios")]
impl<'a> MakeWriter<'a> for MutexMakeWriter {
    type Writer = MutexWriter<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        MutexWriter {
            guard: self.file.lock().unwrap(),
        }
    }
}

// MutexWriter struct to handle writing to the file
#[cfg(target_os = "ios")]
struct MutexWriter<'a> {
    guard: std::sync::MutexGuard<'a, File>,
}

// Implement the Write trait for MutexWriter
#[cfg(target_os = "ios")]
impl<'a> Write for MutexWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.guard.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.guard.flush()
    }
}

#[cfg(target_os = "ios")]
pub fn init_logging() {
    INIT.call_once(|| {
        // Get the path to the cache directory.
        let cache_path = match dirs_next::cache_dir() {
            Some(path) => path,
            None => panic!("Failed to find the cache directory"),
        };

        // Create the log directory if it doesn't exist.
        let log_dir = cache_path.join("Logs");
        if !log_dir.exists() {
            std::fs::create_dir_all(&log_dir).expect("Failed to create log directory");
        }

        let file_appender = RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .filename_prefix("processor")
            .filename_suffix("log")
            .max_log_files(5)
            .build(log_dir)
            .expect("Failed to create file appender");

        // Initialize the subscriber with file-based logging
        let subscriber = SubscriberBuilder::default()
            .with_writer(file_appender)
            .with_ansi(false) // Disable ANSI colors
            .with_max_level(if cfg!(debug_assertions) {
                tracing::Level::DEBUG
            } else {
                tracing::Level::INFO
            })
            .finish();

        tracing::subscriber::set_global_default(subscriber)
            .expect("Unable to set global subscriber");
        println!("logger initialized");
    });
}

#[cfg(not(target_os = "ios"))]
pub fn init_logging() {
    // No-op for non-iOS platforms
    println!("Logging is set to println! on this platform.");
}

// Conditional macro for logging errors with optional log prefix
#[cfg(target_os = "ios")]
#[macro_export]
macro_rules! log_error {
    (target: $target:expr, $($arg:tt)*) => {
        {
            tracing::error!(target: $target, $($arg)*); // Logs to file via tracing
            println!("ERROR [{}]: {}", $target, format!($($arg)*)); // Console output
        }
    };
    ($($arg:tt)*) => {
        {
            tracing::error!(target: "default_log_prefix", $($arg)*); // Logs to file via tracing
            println!("ERROR [default_log_prefix]: {}", format!($($arg)*)); // Console output
        }
    };
}

#[cfg(not(target_os = "ios"))]
#[macro_export]  // Ensures the macro is available across the crate
macro_rules! log_error {
    (target: $target:expr, $($arg:tt)*) => {
        println!("[{}] ERROR: {}", $target, format!($($arg)*))
    };
    ($($arg:tt)*) => {
        println!("[default_log_prefix] ERROR: {}", format!($($arg)*))
    };
}

// Conditional macro for logging warnings with optional log prefix
#[cfg(target_os = "ios")]
#[macro_export]
macro_rules! log_warn {
    (target: $target:expr, $($arg:tt)*) => {
        {
            tracing::warn!(target: $target, $($arg)*); // Logs to file via tracing
            println!("WARN [{}]: {}", $target, format!($($arg)*)); // Console output
        }
    };
    ($($arg:tt)*) => {
        {
            tracing::warn!(target: "default_log_prefix", $($arg)*); // Logs to file via tracing
            println!("WARN [default_log_prefix]: {}", format!($($arg)*)); // Console output
        }
    };
}

#[cfg(not(target_os = "ios"))]
#[macro_export]  // Ensures the macro is available across the crate
macro_rules! log_warn {
    (target: $target:expr, $($arg:tt)*) => {
        println!("[{}] WARN: {}", $target, format!($($arg)*))
    };
    ($($arg:tt)*) => {
        println!("[default_log_prefix] WARN: {}", format!($($arg)*))
    };
}

// Conditional macro for logging info with optional log prefix
#[cfg(target_os = "ios")]
#[macro_export]
macro_rules! log_info {
    (target: $target:expr, $($arg:tt)*) => {
        {
            tracing::info!(target: $target, $($arg)*); // Logs to file via tracing
            println!("INFO [{}]: {}", $target, format!($($arg)*)); // Console output
        }
    };
    ($($arg:tt)*) => {
        {
            tracing::info!(target: "default_log_prefix", $($arg)*); // Logs to file via tracing
            println!("INFO [default_log_prefix]: {}", format!($($arg)*)); // Console output
        }
    };
}

#[cfg(not(target_os = "ios"))]
#[macro_export]  // Ensures the macro is available across the crate
macro_rules! log_info {
    (target: $target:expr, $($arg:tt)*) => {
        println!("[{}] INFO: {}", $target, format!($($arg)*))
    };
    ($($arg:tt)*) => {
        println!("[default_log_prefix] INFO: {}", format!($($arg)*))
    };
}

// Conditional macro for logging info with optional log prefix
#[cfg(target_os = "ios")]
#[macro_export]
macro_rules! log_debug {
    (target: $target:expr, $($arg:tt)*) => {
        {
            tracing::debug!(target: $target, $($arg)*); // Logs to file via tracing
            println!("DEBUG [{}]: {}", $target, format!($($arg)*)); // Console output
        }
    };
    ($($arg:tt)*) => {
        {
            tracing::debug!(target: "default_log_prefix", $($arg)*); // Logs to file via tracing
            println!("DEBUG [default_log_prefix]: {}", format!($($arg)*)); // Console output
        }
    };
}

#[cfg(not(target_os = "ios"))]
#[macro_export]  // Ensures the macro is available across the crate
macro_rules! log_debug {
    (target: $target:expr, $($arg:tt)*) => {
        println!("[{}] DEBUG: {}", $target, format!($($arg)*))
    };
    ($($arg:tt)*) => {
        println!("[default_log_prefix] DEBUG: {}", format!($($arg)*))
    };
}