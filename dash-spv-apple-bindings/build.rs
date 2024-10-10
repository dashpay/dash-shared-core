extern crate cbindgen;
extern crate ferment_sys;

use ferment_sys::{Ferment, Lang, ObjC, XCodeConfig};

// [parse.expand]
// # A list of crate names that should be run through `cargo expand` before
// # parsing to expand any macros. Note that if a crate is named here, it
// # will always be parsed, even if the blacklist/whitelist says it shouldn't be.
// #
// # default: []
// crates = ["your_crate_name"]

// pub const SELF_NAME: &str = "dash_spv_apple_bindings";

// fn main() {
//     let c_header = "target/dash_shared_core.h";
//     match Ferment::with_crate_name(SELF_NAME)
//         .with_default_mod_name()
//         .with_external_crates(vec![
//             "dash-spv-masternode-processor",
//             "dash-spv-platform",
//             "dash-sdk",
//             "platform-value",
//             "platform-version",
//             "dpp",
//             "drive-proof-verifier"
//         ])
//         .with_languages(vec![
//             Lang::ObjC(ObjC::new(XCodeConfig {
//                 class_prefix: "DS".to_string(),
//                 framework_name: "dash_shared_core".to_string()
//             })),
//         ])
//         .generate() {
//         Ok(()) => match Command::new("cbindgen")
//             .args(["--config", "cbindgen.toml", "-o", c_header])
//             .status() {
//             Ok(status) => println!("[cbindgen] [ok] generated into {c_header} with status: {status}"),
//             Err(err) => panic!("[cbindgen] [error] {}", err)
//         }
//         Err(err) => panic!("[ferment] Can't create FFI expansion: {}", err)
//     }
//
//
// }
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


// fn main() {
//
//     match ferment::Builder::new()
//         .with_crates(vec![
//             "dash_spv_masternode_processor".to_string(),
//             "rs_merk_verify_c_binding".to_string()
//         ])
//         .generate() {
//         Ok(()) => match std::process::Command::new("cbindgen")
//             .args(&["--config", "cbindgen.toml", "-o", "target/dash_shared_core.h"])
//             .status() {
//             Ok(status) => println!("Bindings generated into target/example.h with status: {status}"),
//             Err(err) => panic!("Can't generate bindings: {}", err)
//         }
//         Err(err) => panic!("Can't create FFI expansion: {}", err)
//     }
//
//
//     // match ferment::Builder::new().generate() {
//     //     Ok(()) => {
//     //         let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
//     //         // Here we write down crate names (!) where we want to retrieve C-bindings
//     //         let includes = vec![
//     //             "dash-spv-masternode-processor".to_string(),
//     //             "rs-merk-verify-c-binding".to_string()
//     //         ];
//     //         let config = cbindgen::Config {
//     //             language: cbindgen::Language::C,
//     //             parse: cbindgen::ParseConfig {
//     //                 parse_deps: true,
//     //                 include: Some(includes.clone()),
//     //                 extra_bindings: includes.clone(),
//     //                 // expand: cbindgen::ParseExpandConfig {
//     //                 //     crates: includes.clone(),
//     //                 //     ..Default::default()
//     //                 // },
//     //                 ..Default::default()
//     //             },
//     //             enumeration: cbindgen::EnumConfig {
//     //                 prefix_with_name: true,
//     //                 ..Default::default()
//     //             },
//     //             braces: cbindgen::Braces::SameLine,
//     //             line_length: 80,
//     //             tab_width: 4,
//     //             documentation_style: cbindgen::DocumentationStyle::C,
//     //             include_guard: Some("dash_shared_core_h".to_string()),
//     //             ..Default::default()
//     //         };
//     //         cbindgen::generate_with_config(&crate_dir, config)
//     //             .unwrap()
//     //             .write_to_file("../target/dash_shared_core.h");
//     //
//     //     },
//     //     Err(err) => println!("ferment::error: {err}")
//     // }
// }

// fn main() {
//
//     match ferment::Builder::new().generate() {
//         Ok(()) => {
//             let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
//             // Here we write down crate names (!) where we want to retrieve C-bindings
//             let includes = vec![
//                 "dash-spv-masternode-processor".to_string(),
//                 "rs-merk-verify-c-binding".to_string()
//             ];
//             let config = cbindgen::Config {
//                 language: cbindgen::Language::C,
//                 parse: cbindgen::ParseConfig {
//                     parse_deps: true,
//                     include: Some(includes.clone()),
//                     extra_bindings: includes.clone(),
//                     // expand: cbindgen::ParseExpandConfig {
//                     //     crates: includes.clone(),
//                     //     ..Default::default()
//                     // },
//                     ..Default::default()
//                 },
//                 enumeration: cbindgen::EnumConfig {
//                     prefix_with_name: true,
//                     ..Default::default()
//                 },
//                 braces: cbindgen::Braces::SameLine,
//                 line_length: 80,
//                 tab_width: 4,
//                 documentation_style: cbindgen::DocumentationStyle::C,
//                 include_guard: Some("dash_shared_core_h".to_string()),
//                 ..Default::default()
//             };
//             cbindgen::generate_with_config(&crate_dir, config)
//                 .unwrap()
//                 .write_to_file("../target/dash_shared_core.h");
//
//         },
//         Err(err) => println!("ferment::error: {err}")
//     }
// }
