// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Known-safe values. Configured values are kept only as SHA-256 digests.

use std::collections::HashSet;

use anyhow::{anyhow, bail, Result};
use regex::Regex;

use crate::fingerprint::digest;

#[derive(Default)]
pub struct Allowlist {
    values: HashSet<[u8; 32]>,
    fingerprints: HashSet<String>,
    patterns: Vec<Regex>,
}

impl Allowlist {
    pub fn new(values: &[String], fingerprints: &[String], patterns: &[String]) -> Result<Self> {
        let values = values.iter().filter(|v| !v.is_empty()).map(|v| digest(v)).collect();
        let mut fps = HashSet::new();
        for fp in fingerprints {
            let fp = fp.trim().to_ascii_lowercase();
            let hex = fp
                .strip_prefix("sha256:")
                .ok_or_else(|| anyhow!("allowlist fingerprint '{fp}' must look like sha256:<12 hex>"))?;
            if hex.len() != 12 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("allowlist fingerprint '{fp}' must look like sha256:<12 hex>");
            }
            fps.insert(fp);
        }
        let mut compiled = Vec::new();
        for (i, p) in patterns.iter().enumerate() {
            // Pattern text may itself be sensitive, so it is not echoed.
            let re = Regex::new(&format!("^(?:{p})$"))
                .map_err(|_| anyhow!("allowlist.patterns[{i}] is not a valid regular expression"))?;
            compiled.push(re);
        }
        Ok(Self {
            values,
            fingerprints: fps,
            patterns: compiled,
        })
    }

    pub fn allows(&self, value: &str, fingerprint: &str) -> bool {
        self.fingerprints.contains(fingerprint)
            || (!self.values.is_empty() && self.values.contains(&digest(value)))
            || self.patterns.iter().any(|p| p.is_match(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_value_fingerprint_and_pattern() {
        let a = Allowlist::new(
            &["known-value".into()],
            &["sha256:2CF24DBA5FB0".into()],
            &["test_[0-9]+".into()],
        )
        .unwrap();
        assert!(a.allows("known-value", "sha256:000000000000"));
        assert!(a.allows("x", "sha256:2cf24dba5fb0"));
        assert!(a.allows("test_42", "sha256:000000000000"));
        assert!(!a.allows("test_42x", "sha256:000000000000"));
        assert!(!a.allows("other", "sha256:000000000000"));
    }

    #[test]
    fn rejects_malformed_entries() {
        assert!(Allowlist::new(&[], &["abc".into()], &[]).is_err());
        assert!(Allowlist::new(&[], &["sha256:zz".into()], &[]).is_err());
        assert!(Allowlist::new(&[], &[], &["(".into()]).is_err());
    }
}
