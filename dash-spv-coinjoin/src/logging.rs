use tracing::{subscriber::set_global_default, Subscriber};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, Registry};

#[cfg(target_os = "ios")]
use std::ffi::CString;
#[cfg(target_os = "ios")]
use std::os::raw::c_char;

#[cfg(target_os = "ios")]
mod ios_log {
    use super::*;

    #[link(name = "os")]
    extern "C" {
        fn os_log_create(subsystem: *const c_char, category: *const c_char) -> *mut std::ffi::c_void;
        fn os_log_info(log: *mut std::ffi::c_void, message: *const c_char);
    }

    pub struct IOSLogger {
        log: *mut std::ffi::c_void,
    }

    impl IOSLogger {
        pub fn new(subsystem: &str, category: &str) -> Self {
            let subsystem_c = CString::new(subsystem).unwrap();
            let category_c = CString::new(category).unwrap();
            unsafe {
                let log = os_log_create(subsystem_c.as_ptr(), category_c.as_ptr());
                Self { log }
            }
        }

        pub fn log_info(&self, message: &str) {
            let message_c = CString::new(message).unwrap();
            unsafe {
                os_log_info(self.log, message_c.as_ptr());
            }
        }
    }

    pub fn log_message(subsystem: &str, category: &str, message: &str) {
        let logger = IOSLogger::new(subsystem, category);
        logger.log_info(message);
    }
}

#[cfg(not(target_os = "ios"))]
mod dev_log {
    pub fn log_message(subsystem: &str, category: &str, message: &str) {
        println!("[{}][{}] {}", subsystem, category, message); // Fallback to println! for non-iOS environments
    }
}

// Re-export log_message function depending on the platform
#[cfg(target_os = "ios")]
pub use ios_log::log_message;

#[cfg(not(target_os = "ios"))]
pub use dev_log::log_message;

// Setup tracing-based logging for iOS or other platforms
pub fn setup_logs() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let subscriber = Registry::default()
        .with(env_filter)
        .with(fmt::layer().with_target(false).with_writer(std::io::stderr));

    if set_global_default(subscriber).is_err() {
        log_message("platform", "logging", "Failed to set global default subscriber");
    }
}