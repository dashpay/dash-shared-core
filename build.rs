extern crate cbindgen;

use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut config: cbindgen::Config = Default::default();
    let mut parse_config: cbindgen::ParseConfig = cbindgen::ParseConfig::default();
    parse_config.parse_deps = true;
    parse_config.include = Some(vec!["dash_mndiff".to_string(), "rs-merk-verify-c-binding".to_string()]);
    parse_config.extra_bindings = vec!["dash_mndiff".to_string(), "rs-merk-verify-c-binding".to_string()];
    config.language = cbindgen::Language::C;
    config.parse = parse_config;
    cbindgen::generate_with_config(&crate_dir, config)
        .unwrap()
        .write_to_file("target/dash_shared_core.h");
}
