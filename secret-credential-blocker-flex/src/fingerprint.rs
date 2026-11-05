// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Stable, non-reversible identifiers for detected secrets. Logs and allowlists
//! refer to a secret only by its fingerprint, never by its value.

use sha2::{Digest, Sha256};

const HEX_CHARS: usize = 12;

/// `sha256:<first 12 hex chars of sha256(salt || value)>`.
///
/// With an empty salt this is reproducible offline:
/// `printf %s "$VALUE" | shasum -a 256 | cut -c1-12`.
pub fn fingerprint(salt: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(7 + HEX_CHARS);
    out.push_str("sha256:");
    for byte in digest.iter().take(HEX_CHARS / 2) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Full unsalted SHA-256, used to compare against `allowlist.values` without keeping them in memory.
pub fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_shasum_prefix() {
        // printf %s hello | shasum -a 256 → 2cf24dba5fb0a30e...
        assert_eq!(fingerprint("", "hello"), "sha256:2cf24dba5fb0");
    }

    #[test]
    fn salt_changes_fingerprint() {
        assert_ne!(fingerprint("", "hello"), fingerprint("pepper", "hello"));
        assert_eq!(fingerprint("pepper", "hello"), fingerprint("pepper", "hello"));
    }
}
