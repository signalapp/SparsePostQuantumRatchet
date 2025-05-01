// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

fn main() {
    let protos = ["src/proto/pq_ratchet.proto"];
    let mut prost_build = prost_build::Config::new();
    prost_build
        .compile_protos(&protos, &["src"])
        .expect("Protobufs in src are valid");
    for proto in &protos {
        println!("cargo:rerun-if-changed={proto}");
    }
}
