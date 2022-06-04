# Boink (matter-rs): The Rust Implementation of Matter

[![Test Linux (OpenSSL)](https://github.com/kedars/matter-rs/actions/workflows/test-linux-openssl.yml/badge.svg)](https://github.com/kedars/matter-rs/actions/workflows/test-linux-openssl.yml)
[![Test Linux (mbedTLS)](https://github.com/kedars/matter-rs/actions/workflows/test-linux-mbedtls.yml/badge.svg)](https://github.com/kedars/matter-rs/actions/workflows/test-linux-mbedtls.yml)
[![Build-ESP32](https://github.com/kedars/matter-rs/actions/workflows/build-esp32.yml/badge.svg)](https://github.com/kedars/matter-rs/actions/workflows/build-esp32.yml)

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

With the chip-tool (the current tool for testing Matter) use the Ethernet commissioning mechanism:
```
$ chip-tool pairing ethernet 12344321 123456 0 <IP-Address> 5540
```

## Functionality
- Secure Channel:
  - PASE
  - CASE
- Interactions:
  - Invoke Command(s), Read Attribute(s), Write Attribute(s)
- Commissioning:
  - over Ethernet
  - Network Commissioning Cluster
  - General Commissioning Cluster
  - Operational Certificates Cluster
- Some [TODO](TODO.md) are captured here
