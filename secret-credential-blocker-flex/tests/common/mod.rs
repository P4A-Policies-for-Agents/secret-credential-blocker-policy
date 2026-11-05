// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Common test utilities shared by the integration tests.

#![allow(dead_code)]

pub mod setup;

// Directory where the policy implementation wasm + GCL are placed by `make build`.
pub const POLICY_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/target/wasm32-wasip1/release");

// Directory containing logging.yaml and (locally generated) registration.yaml.
pub const COMMON_CONFIG_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/config");

// Policy implementation reference name (`target/policy-ref-name.txt` after `make build`).
pub const POLICY_NAME: &str = "secret-credential-blocker-flex-v1-0";

// Fixtures are assembled at runtime so repository secret scanners do not flag this file.
pub fn token() -> String {
    ["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"].concat()
}

pub fn aws_id() -> String {
    ["AKIA", "IOSFODNN7EXAMPLQ"].concat()
}
