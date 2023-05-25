use std::fs::File;
use std::io;
use std::io::Write;
use serde::Serialize;

pub fn create_file(name: &str) -> io::Result<File> { // "processor.log"
    let cache_path = match dirs_next::cache_dir() {
        Some(path) => path,
        None => panic!("Failed to find the cache directory"),
    };
    let dir = cache_path.join("Logs");
    if !dir.exists() {
        std::fs::create_dir_all(&dir)
            .expect("Failed to create 'Logs' directory");
    }
    let file_path = dir.join(name);
    File::create(file_path)
}

pub fn save_json_file<T: Serialize>(name: &str, value: &T) -> io::Result<()> {
    create_file(name)
        .and_then(|mut out| out.write(serde_json::to_string_pretty(value).unwrap().as_ref()).map(|_| ()))
}

pub fn save_java_class(name: &str, contents: &[u8]) -> io::Result<()> {
    create_file(name)
        .and_then(|mut out| out.write(contents).map(|_| ()))
}
