use std::fs::File;
use simplelog::{ColorChoice, CombinedLogger, ConfigBuilder, LevelFilter, TerminalMode, TermLogger, WriteLogger};

/// Initializes logger (it could be initialize only once)
#[no_mangle]
pub unsafe extern "C" fn register_rust_logger() {
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

    // Create the log file inside the cache directory.
    let log_file_path = log_dir.join("processor.log");
    println!("Log file create at: {:?}", log_file_path);
    let log_file = File::create(log_file_path)
        .expect("Failed to create log file");
    let config = ConfigBuilder::new().build();
    //let config = ConfigBuilder::new().set_time_level(LevelFilter::Off).set_max_level(LevelFilter::Off).build();
    match CombinedLogger::init(
        vec![
            TermLogger::new(LevelFilter::Error, config.clone(), TerminalMode::Mixed, ColorChoice::Auto),
            TermLogger::new(LevelFilter::Warn, config.clone(), TerminalMode::Mixed, ColorChoice::Auto),
            WriteLogger::new(LevelFilter::Error, config.clone(), log_file.try_clone().unwrap()),
            WriteLogger::new(LevelFilter::Warn, config.clone(), log_file.try_clone().unwrap()),
            WriteLogger::new(LevelFilter::Info, config.clone(), log_file.try_clone().unwrap()),
        ]
    ) {
        Ok(()) => println!("Logger initialized"),
        Err(err) => println!("Failed to init logger: {}", err)
    }
}
