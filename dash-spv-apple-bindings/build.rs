extern crate cbindgen;
extern crate ferment_sys;

use ferment_sys::{Ferment, Lang, ObjC, XCodeConfig};

fn main() {
    match Ferment::with_crate_name("dash_spv_apple_bindings")
        .with_cbindgen_config_from_file("cbindgen.toml")
        .with_default_mod_name()
        .with_external_crates(vec![
            "dash-spv-masternode-processor",
            "dash-spv-platform",
            "dash-sdk",
            "platform-value",
            "platform-version",
            "dpp",
            "drive-proof-verifier",
            "rs-dapi-client"
        ])
        .with_languages(vec![
            Lang::ObjC(ObjC::new(XCodeConfig {
                class_prefix: "DS".to_string(),
                framework_name: "DashSharedCore".to_string(),
                header_name: "dash_shared_core".to_string()
            })),
        ])
        .generate() {
        Ok(_) => println!("[ferment] [ok]"),
        Err(err) => panic!("[ferment] [err]: {}", err)
    }
}
