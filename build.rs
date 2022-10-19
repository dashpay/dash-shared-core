extern crate cbindgen;

use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    // Here we write down crate names (!) where we want to retrieve C-bindings
    let includes = vec![
        "dash-spv-ffi".to_string(),
        "dash-spv-models".to_string(),
        "dash-spv-masternode-processor".to_string(),
        "rs-merk-verify-c-binding".to_string()
    ];
    let mut config: cbindgen::Config = cbindgen::Config::default();
    config.language = cbindgen::Language::C;
    config.parse = cbindgen::ParseConfig {
        parse_deps: true,
        include: Some(includes.clone()),
        extra_bindings: includes,
        ..Default::default()
    };
    cbindgen::generate_with_config(&crate_dir, config)
        .unwrap()
        .write_to_file("target/dash_shared_core.h");
}
