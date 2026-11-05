// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Opt-in high-entropy token detection for credentials no named detector knows.

use anyhow::{bail, Result};
use regex::Regex;

pub const KIND: &str = "high_entropy_string";

pub struct EntropyDetector {
    token: Regex,
    threshold: f64,
}

impl EntropyDetector {
    pub fn new(threshold: f64, min_length: usize) -> Result<Self> {
        if !(1.0..=8.0).contains(&threshold) {
            bail!("entropy.threshold must be between 1 and 8");
        }
        if !(8..=1024).contains(&min_length) {
            bail!("entropy.minLength must be between 8 and 1024");
        }
        let token = Regex::new(&format!(r"[A-Za-z0-9+/_\-]{{{min_length},}}={{0,2}}"))?;
        Ok(Self { token, threshold })
    }

    /// Spans of candidate tokens whose Shannon entropy reaches the threshold.
    pub fn find(&self, text: &str) -> Vec<(usize, usize)> {
        self.token
            .find_iter(text)
            .filter(|m| is_candidate(m.as_str()) && shannon(m.as_str()) >= self.threshold)
            .map(|m| (m.start(), m.end()))
            .collect()
    }
}

/// Excludes hex digests and UUIDs (high entropy, but identifiers, not secrets)
/// and tokens without both letters and digits.
fn is_candidate(token: &str) -> bool {
    let has_digit = token.bytes().any(|b| b.is_ascii_digit());
    let has_alpha = token.bytes().any(|b| b.is_ascii_alphabetic());
    if !has_digit || !has_alpha {
        return false;
    }
    let hexish = token.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-');
    !hexish
}

pub fn shannon(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = f64::from(*c) / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_values() {
        assert_eq!(shannon("aaaa"), 0.0);
        assert!((shannon("ab") - 1.0).abs() < 1e-9);
    }

    #[test]
    fn finds_random_tokens_but_not_hex_or_uuid() {
        let d = EntropyDetector::new(4.0, 24).unwrap();
        let text = "id=550e8400-e29b-41d4-a716-446655440000 sha=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 key=Zx9Qp2Lm7Rt4Vb8Nc1Kd6Hs3Jf5Wg0Ya";
        let spans = d.find(text);
        assert_eq!(spans.len(), 1);
        assert_eq!(&text[spans[0].0..spans[0].1], "Zx9Qp2Lm7Rt4Vb8Nc1Kd6Hs3Jf5Wg0Ya");
    }

    #[test]
    fn rejects_bad_settings() {
        assert!(EntropyDetector::new(0.5, 24).is_err());
        assert!(EntropyDetector::new(4.5, 2).is_err());
    }
}
