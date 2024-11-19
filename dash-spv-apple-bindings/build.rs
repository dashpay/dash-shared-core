extern crate cbindgen;
extern crate ferment_sys;

use ferment_sys::Ferment;
#[cfg(feature = "objc")]
use ferment_sys::{Lang, ObjC, XCodeConfig};

fn main() {
    match Ferment::with_crate_name("dash_spv_apple_bindings")
        .with_cbindgen_config_from_file("cbindgen.toml")
        .with_default_mod_name()
        .with_external_crates(vec![
            "dash-spv-crypto",
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
            #[cfg(feature = "objc")]
            Lang::ObjC(ObjC::new(XCodeConfig::new("DS", "DashSharedCore", "dash_shared_core"))),
        ])
        .generate() {
        Ok(_) => println!("[ferment] [ok]"),
        Err(err) => panic!("[ferment] [err]: {}", err)
    }
}
