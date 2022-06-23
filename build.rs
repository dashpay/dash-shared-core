extern crate cbindgen;

use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    // let mut config: cbindgen::Config = cbindgen::Config::from_file("./cbindgen.toml").expect("Error config");
    let mut config: cbindgen::Config = cbindgen::Config::default();
    let mut parse_config: cbindgen::ParseConfig = cbindgen::ParseConfig::default();
    parse_config.parse_deps = true;
    // Here we write down crate names (!) where we want to retrieve C-bindings
    let includes = vec![
        "dash-spv-ffi".to_string(),
        "dash-spv-models".to_string(),
        "dash_mndiff".to_string(),
        "rs-merk-verify-c-binding".to_string()
    ];
    parse_config.include = Some(includes.clone());
    parse_config.extra_bindings = includes.clone();
    config.language = cbindgen::Language::C;
    config.parse = parse_config;
    cbindgen::generate_with_config(&crate_dir, config)
        .unwrap()
        .write_to_file("target/dash_shared_core.h");
}
