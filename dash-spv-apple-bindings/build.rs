extern crate cbindgen;
extern crate ferment_sys;

use ferment_sys::{Ferment, Lang, ObjC, XCodeConfig};

fn main() {
    const SELF_NAME: &str = "dash_spv_apple_bindings";
    match Ferment::with_crate_name(SELF_NAME)
        .with_cbindgen_config("cbindgen.toml")
        .with_default_mod_name()
        .with_external_crates(vec![
            "dash-spv-masternode-processor",
            "dash-spv-platform",
            "dash-sdk",
            "platform-value",
            "platform-version",
            "dpp",
            "drive-proof-verifier"
        ])
        .with_languages(vec![
            Lang::ObjC(ObjC::new(XCodeConfig {
                class_prefix: "DS".to_string(),
                framework_name: "DashSharedCore".to_string(),
                header_name: SELF_NAME.to_string()
            })),
        ])
        .generate() {
        Ok(_) => println!("[ferment] [ok]: {SELF_NAME}"),
        Err(err) => panic!("[ferment] [err]: {}", err)
    }
}
