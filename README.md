# Boink (matter-rs): The Rust Implementation of Matter

[![Test Linux (OpenSSL)](https://github.com/kedars/matter-rs/actions/workflows/test-linux-openssl.yml/badge.svg)](https://github.com/kedars/matter-rs/actions/workflows/test-linux-openssl.yml)
[![Test Linux (mbedTLS)](https://github.com/kedars/matter-rs/actions/workflows/test-linux-mbedtls.yml/badge.svg)](https://github.com/kedars/matter-rs/actions/workflows/test-linux-mbedtls.yml)

## Build

Building the library:
```
$ cd matter
$ cargo build
```

Building the example:
```
$ cd matter
$ RUST_LOG="matter" cargo run --example onoff_light
```


## Functionality
- PASE Works (TLV Parser/Generator, SPAKE2+, AEAD, Commissioning/Operational Certificates Cluster)
- CASE Works 
- Some [TODO](TODO.md) are captured here
