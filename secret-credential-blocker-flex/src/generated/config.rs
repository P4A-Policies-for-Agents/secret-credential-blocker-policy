use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct AllowlistConfig {
    #[serde(alias = "fingerprints")]
    pub fingerprints: Option<Vec<String>>,
    #[serde(alias = "patterns")]
    pub patterns: Option<Vec<String>>,
    #[serde(alias = "skipPaths")]
    pub skip_paths: Option<Vec<String>>,
    #[serde(alias = "values")]
    pub values: Option<Vec<String>>,
}
#[derive(Deserialize, Clone, Debug)]
pub struct CustomPatterns0Config {
    #[serde(alias = "name")]
    pub name: String,
    #[serde(alias = "regex")]
    pub regex: String,
}
#[derive(Deserialize, Clone, Debug)]
pub struct EntropyConfig {
    #[serde(alias = "enabled")]
    pub enabled: Option<bool>,
    #[serde(alias = "minLength")]
    pub min_length: Option<i64>,
    #[serde(alias = "threshold")]
    pub threshold: Option<f64>,
}
#[derive(Deserialize, Clone, Debug)]
pub struct ResponseScanningConfig {
    #[serde(alias = "action")]
    pub action: Option<String>,
    #[serde(alias = "enabled")]
    pub enabled: Option<bool>,
    #[serde(alias = "sseMode")]
    pub sse_mode: Option<String>,
}
#[derive(Deserialize, Clone, Debug)]
pub struct ScanConfig {
    #[serde(alias = "decodeBase64Parts")]
    pub decode_base_64_parts: Option<bool>,
    #[serde(alias = "headers")]
    pub headers: Option<Vec<String>>,
    #[serde(alias = "maxDecodedBytes")]
    pub max_decoded_bytes: Option<i64>,
    #[serde(alias = "multipart")]
    pub multipart: Option<bool>,
    #[serde(alias = "queryParams")]
    pub query_params: Option<bool>,
    #[serde(alias = "restBody")]
    pub rest_body: Option<bool>,
}
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "action")]
    pub action: Option<String>,
    #[serde(alias = "allowlist")]
    pub allowlist: Option<AllowlistConfig>,
    #[serde(alias = "customPatterns")]
    pub custom_patterns: Option<Vec<CustomPatterns0Config>>,
    #[serde(alias = "disabledDetectors")]
    pub disabled_detectors: Option<Vec<String>>,
    #[serde(alias = "entropy")]
    pub entropy: Option<EntropyConfig>,
    #[serde(alias = "errorDetail")]
    pub error_detail: Option<bool>,
    #[serde(alias = "errorDomain")]
    pub error_domain: Option<String>,
    #[serde(alias = "fingerprintSalt")]
    pub fingerprint_salt: Option<String>,
    #[serde(alias = "maxBodyBytes")]
    pub max_body_bytes: Option<i64>,
    #[serde(alias = "oversizeBehavior")]
    pub oversize_behavior: Option<String>,
    #[serde(alias = "protocol")]
    pub protocol: Option<String>,
    #[serde(alias = "responseScanning")]
    pub response_scanning: Option<ResponseScanningConfig>,
    #[serde(alias = "scan")]
    pub scan: Option<ScanConfig>,
}
#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    abi.setup()?;
    Ok(())
}
