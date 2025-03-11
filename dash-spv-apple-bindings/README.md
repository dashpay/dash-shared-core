# dash-spv-apple-bindings
C-bindings for dash spv written in rust for different platforms (currently for iOS and macOS)

To release it as cocoapod don't forget to
- update spec version
- tag commit with version 
- and push it to spec repo:
- pod trunk push DashSharedCore.podspec --allow-warnings

- if the bls fails to compile, try to remove git cache (rm -rf  /Users/$USER/.cargo/git/checkouts/bls-signatures-*) and try again: