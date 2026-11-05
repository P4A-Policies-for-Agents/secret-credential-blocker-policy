// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Structural detection: a JSON member, form field or query parameter whose
//! *name* says it holds a credential (`"password": "..."`).

use super::{has_mixed_charset, is_placeholder};

/// Normalized (lowercase, no `-`/`_`/`.`) key names that carry credentials.
const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "pass",
    "secret",
    "clientsecret",
    "apikey",
    "xapikey",
    "apitoken",
    "accesstoken",
    "refreshtoken",
    "authtoken",
    "bearertoken",
    "sessiontoken",
    "token",
    "privatekey",
    "secretkey",
    "secretaccesskey",
    "awssecretaccesskey",
    "accesskeysecret",
    "connectionstring",
    "webhooksecret",
    "signingsecret",
    "encryptionkey",
];

pub fn normalize(key: &str) -> String {
    key.chars()
        .filter(|c| !matches!(c, '-' | '_' | '.' | ' '))
        .flat_map(char::to_lowercase)
        .collect()
}

pub fn is_sensitive_key(key: &str) -> bool {
    let n = normalize(key);
    SENSITIVE_KEYS.contains(&n.as_str())
}

/// True for AWS secret-key names (`aws_secret_access_key`, `SecretAccessKey`).
pub fn is_aws_secret_key(key: &str) -> bool {
    let n = normalize(key);
    n.contains("secretaccesskey") || n == "awssecretkey"
}

/// Values that plausibly are a credential rather than a word, a number or a
/// template placeholder: at least 8 chars, no whitespace, and either a digit
/// or symbol, or mixed case.
pub fn looks_like_secret_value(value: &str) -> bool {
    let v = value.trim();
    if v.len() < 8 || v.len() > 4096 || v.chars().any(char::is_whitespace) || is_placeholder(v) {
        return false;
    }
    if v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("false") || v.eq_ignore_ascii_case("null") {
        return false;
    }
    let has_digit = v.chars().any(|c| c.is_ascii_digit());
    let has_alpha = v.chars().any(|c| c.is_ascii_alphabetic());
    let has_symbol = v.chars().any(|c| !c.is_ascii_alphanumeric());
    if !has_alpha {
        return false;
    }
    has_digit || has_symbol || has_mixed_case(v) || has_mixed_charset(v)
}

fn has_mixed_case(v: &str) -> bool {
    v.chars().any(|c| c.is_ascii_uppercase()) && v.chars().any(|c| c.is_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_key_names() {
        for k in ["password", "Password", "api_key", "X-API-Key", "client_secret", "accessToken", "aws.secret_access_key"] {
            assert!(is_sensitive_key(k), "{k}");
        }
        for k in ["passwordless", "tokens", "nextPageToken", "keyboard", "username", "description"] {
            assert!(!is_sensitive_key(k), "{k}");
        }
    }

    #[test]
    fn secret_like_values() {
        for v in ["hunter22", "S3cr3t!pass", "Tr0ub4dor&3", "abcDEFghiJKL"] {
            assert!(looks_like_secret_value(v), "{v}");
        }
        for v in ["short", "required", "12345678", "${DB_PASSWORD}", "<your-password>", "********", "changeme123", "two words here", "true"] {
            assert!(!looks_like_secret_value(v), "{v}");
        }
    }
}
