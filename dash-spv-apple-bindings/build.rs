extern crate cbindgen;

use std::env;
// [parse.expand]
// # A list of crate names that should be run through `cargo expand` before
// # parsing to expand any macros. Note that if a crate is named here, it
// # will always be parsed, even if the blacklist/whitelist says it shouldn't be.
// #
// # default: []
// crates = ["your_crate_name"]

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    // Here we write down crate names (!) where we want to retrieve C-bindings
    let includes = vec![
        "dash-spv-masternode-processor".to_string(),
        "rs-merk-verify-c-binding".to_string()
    ];
    let config = cbindgen::Config {
        language: cbindgen::Language::C,
        parse: cbindgen::ParseConfig {
            parse_deps: true,
            include: Some(includes.clone()),
            extra_bindings: includes.clone(),
            // expand: cbindgen::ParseExpandConfig {
            //     crates: includes.clone(),
            //     ..Default::default()
            // },
            ..Default::default()
        },
        enumeration: cbindgen::EnumConfig {
            prefix_with_name: true,
            ..Default::default()
        },
        braces: cbindgen::Braces::SameLine,
        line_length: 80,
        tab_width: 4,
        documentation_style: cbindgen::DocumentationStyle::C,
        include_guard: Some("dash_shared_core_h".to_string()),
        ..Default::default()
    };
    cbindgen::generate_with_config(&crate_dir, config)
        .unwrap()
        .write_to_file("../target/dash_shared_core.h");
}
