// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Secret & Credential Leakage Blocker: detects secrets and credentials in
//! REST, MCP and A2A (v0.3 and v1.0) traffic and blocks, redacts or reports them.

mod detect;
mod errors;
mod fingerprint;
mod generated;
mod path;
mod protocol;
mod redact;
mod report;
mod request;
mod response;
mod settings;
mod sse;
mod walk;

#[cfg(test)]
mod tests;

use anyhow::{anyhow, Result};
use pdk::hl::*;
use pdk::logger;
use pdk::policy_violation::PolicyViolations;

use crate::generated::config::Config;
use crate::settings::Settings;

#[entrypoint]
async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    violations: PolicyViolations,
) -> Result<()> {
    // The configuration is not echoed: it may hold allowlisted values and the salt.
    let config: Config =
        serde_json::from_slice(&bytes).map_err(|err| anyhow!("Failed to parse configuration: {err}"))?;
    let settings = Settings::from_config(&config)?;
    logger::info!(
        "[secret-blocker] initialized (action={:?}, protocol={:?}, responseScanning={})",
        settings.action,
        settings.mode,
        settings.response.is_some()
    );
    let filter = on_request(|rs| request::request_filter(rs, &settings, &violations))
        .on_response(|rs, rd| response::response_filter(rs, rd, &settings, &violations));
    launcher.launch(filter).await?;
    Ok(())
}
