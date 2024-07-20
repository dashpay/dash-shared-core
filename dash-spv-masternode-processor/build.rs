extern crate cbindgen;
extern crate ferment;

// use std::process::Command;
// use ferment::Builder;
// use ferment::builder::Crate;

pub const SELF_NAME: &str = "dash_spv_masternode_processor";
fn main() {

    // let c_header = format!("target/{}.h", SELF_NAME);
    // match Builder::new(Crate::current_with_name(SELF_NAME))
    //     .with_mod_name("fermented")
    //     // .with_crates(vec!["ferment-example", "platform-value", "dpp"])
    //     // .with_crates(vec!["ferment-example"])
    //     .generate() {
    //     Ok(()) => match Command::new("cbindgen")
    //         .args(["--config", "cbindgen.toml", "-o", c_header.as_str()])
    //         .status() {
    //         Ok(status) => println!("[cbindgen] [ok] generated into {c_header} with status: {status}"),
    //         Err(err) => panic!("[cbindgen] [error] {err}")
    //     }
    //     Err(err) => panic!("[ferment] Can't create FFI expansion: {err}")
    // }
}
//
// fn main() {
//     // let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
//     // let mut config = cbindgen::Config::from_file("./cbindgen.toml").expect("Error config");
//     // // Here we write down crate names (!) where we want to retrieve C-bindings
//     // let includes = vec![/*"dash-spv-ffi".to_string(), "dash-spv-models".to_string()*/];
//     // config.language = cbindgen::Language::C;
//     // config.parse = cbindgen::ParseConfig {
//     //     parse_deps: true,
//     //     include: Some(includes.clone()),
//     //     extra_bindings: includes.clone(),
//     //     expand: cbindgen::ParseExpandConfig {
//     //         crates: includes.clone(),
//     //         // crates: vec!["ffi-proc-macro-derive".to_string()],
//     //         ..Default::default()
//     //     },
//     //     ..Default::default()
//     // };
//     // config.enumeration = cbindgen::EnumConfig {
//     //     prefix_with_name: true,
//     //     ..Default::default()
//     // };
//     //
//     // config.macro_expansion = cbindgen::MacroExpansionConfig {
//     //     bitflags: true,
//     // };
//     //
//     // cbindgen::generate_with_config(&crate_dir, config)
//     //     .unwrap()
//     //     .write_to_file("target/dash_spv_masternode_processor.h");
//     match ferment::Builder::new()
//         .with_crates(vec![])
//         .generate() {
//         Ok(()) => match Command::new("cbindgen")
//             .args(&["--config", "cbindgen.toml", "-o", "target/example.h"])
//             .status() {
//             Ok(status) => println!("Bindings generated into target/example.h with status: {status}"),
//             Err(err) => panic!("Can't generate bindings: {}", err)
//         }
//         Err(err) => panic!("Can't create FFI expansion: {}", err)
//     }
//
//
//     // let status = Command::new("cargo")
//     //     .args(&["fmt", output_path.to_str().unwrap()])
//     //     .status()
//     //     .expect("Failed to run cargo fmt");
//     //
//     // if !status.success() {
//     //     println!("cargo:warning=cargo fmt failed");
//     // }
//
// }
