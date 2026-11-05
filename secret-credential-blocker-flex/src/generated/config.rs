// Copyright 2026 Salesforce, Inc. All rights reserved.
//
// Hand-maintained: the GCL schema uses nested objects and object arrays, which
// `cargo anypoint config-gen` does not prettify. Keep in sync with
// secret-credential-blocker-definition/gcl.yaml.
use serde::Deserialize;

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Config {
    #[serde(alias = "action")]
    pub action: Option<String>,
    #[serde(alias = "protocol")]
    pub protocol: Option<String>,
    #[serde(alias = "disabledDetectors")]
    pub disabled_detectors: Vec<String>,
    #[serde(alias = "customPatterns")]
    pub custom_patterns: Vec<CustomPattern>,
    #[serde(alias = "entropy")]
    pub entropy: Option<Entropy>,
    #[serde(alias = "allowlist")]
    pub allowlist: Option<Allowlist>,
    #[serde(alias = "scan")]
    pub scan: Option<Scan>,
    #[serde(alias = "responseScanning")]
    pub response_scanning: Option<ResponseScanning>,
    #[serde(alias = "maxBodyBytes")]
    pub max_body_bytes: Option<i64>,
    #[serde(alias = "oversizeBehavior")]
    pub oversize_behavior: Option<String>,
    #[serde(alias = "errorDetail")]
    pub error_detail: Option<bool>,
    #[serde(alias = "errorDomain")]
    pub error_domain: Option<String>,
    #[serde(alias = "fingerprintSalt")]
    pub fingerprint_salt: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct CustomPattern {
    pub name: String,
    pub regex: String,
}

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Entropy {
    pub enabled: Option<bool>,
    pub threshold: Option<f64>,
    #[serde(alias = "minLength")]
    pub min_length: Option<i64>,
}

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Allowlist {
    pub values: Vec<String>,
    pub fingerprints: Vec<String>,
    pub patterns: Vec<String>,
    #[serde(alias = "skipPaths")]
    pub skip_paths: Vec<String>,
}

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Scan {
    pub headers: Vec<String>,
    #[serde(alias = "queryParams")]
    pub query_params: Option<bool>,
    #[serde(alias = "restBody")]
    pub rest_body: Option<bool>,
    pub multipart: Option<bool>,
    #[serde(alias = "decodeBase64Parts")]
    pub decode_base64_parts: Option<bool>,
    #[serde(alias = "maxDecodedBytes")]
    pub max_decoded_bytes: Option<i64>,
}

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct ResponseScanning {
    pub enabled: Option<bool>,
    pub action: Option<String>,
    #[serde(alias = "sseMode")]
    pub sse_mode: Option<String>,
}

#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    abi.setup()?;
    Ok(())
}
