// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8 AI
// SPDX-License-Identifier: Apache-2.0

//! OpenAPI drift guard (OAPEC design §3) - bin-crate variant.
//!
//! The router lives in the binary crate (`main.rs` declares `mod server` and
//! `mod openapi`), which an integration test cannot link; the dumped spec
//! shape is pinned here instead. The authoritative router introspection
//! guard (`sentin8::shell::drift_guard`) applies to lib-router services.

#[test]
fn openapi_dump_exists_and_exceeds_floor() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/openapi.json"))
        .expect("docs/openapi.json - regenerate via --print-registration --section=openapi");
    let spec: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
    let paths = spec.get("paths").and_then(|p| p.as_object()).expect("paths object");
    let ops: usize = paths.values()
        .map(|v| v.as_object().map(|o| o.keys().filter(|k| *k != "parameters").count()).unwrap_or(0))
        .sum();
    assert!(ops >= 47, "spec floor: expected >= 47 ops, got {ops} - an annotation was removed or stale");
}
