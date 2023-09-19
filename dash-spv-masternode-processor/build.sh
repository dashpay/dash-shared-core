set -e
cargo build --release --verbose
cargo expand | sed '/#!/d' > target/expanded.rs
sed -n '/#\[prelude_import\]/,$p' target/expanded.rs > target/expanded_reduced.rs
cbindgen --config cbindgen.toml -o target/example.h target/expanded_reduced.rs