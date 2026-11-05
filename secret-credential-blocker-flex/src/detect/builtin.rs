// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Built-in credential detectors.
//!
//! Each detector is a keyword prefilter (any keyword, ASCII case-insensitive,
//! must occur in the text before the regex runs), a regex, an optional
//! validator and a priority used to resolve overlapping matches. A capture
//! group named `secret` narrows the reported/redacted span to the credential
//! itself (e.g. only the password of a connection string).

use base64::Engine;

use super::{has_mixed_charset, Validator};

pub struct Spec {
    pub kind: &'static str,
    pub pattern: &'static str,
    pub keywords: &'static [&'static str],
    pub validator: Option<Validator>,
    pub priority: u8,
}

/// Every built-in detector name, in the order of `disabledDetectors` in gcl.yaml.
pub const BUILTIN_KINDS: &[&str] = &[
    "aws_access_key_id",
    "aws_secret_access_key",
    "gcp_api_key",
    "gcp_service_account",
    "azure_storage_connection_string",
    "azure_sas_token",
    "github_token",
    "gitlab_token",
    "slack_token",
    "slack_webhook",
    "stripe_key",
    "anthropic_api_key",
    "openai_api_key",
    "jwt",
    "private_key_pem",
    "ssh_private_key",
    "db_connection_string",
    "basic_auth_url",
    "generic_secret_assignment",
];

pub fn specs() -> Vec<Spec> {
    vec![
        Spec {
            kind: "aws_access_key_id",
            pattern: r"\b(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z2-7]{16}\b",
            keywords: &["akia", "asia", "abia", "acca", "a3t"],
            validator: None,
            priority: 90,
        },
        Spec {
            // Only with an AWS secret context; a bare 40-char base64 string is too ambiguous.
            kind: "aws_secret_access_key",
            pattern: r#"(?i)aws.{0,24}?(?:secret|sk)[a-z_]{0,16}\\?["']?\s*[:=]\s*\\?["']?(?P<secret>[A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+=]|$)"#,
            keywords: &["aws"],
            validator: None,
            priority: 90,
        },
        Spec {
            kind: "gcp_api_key",
            pattern: r"\bAIza[0-9A-Za-z_\-]{35}",
            keywords: &["aiza"],
            validator: None,
            priority: 90,
        },
        Spec {
            // Service-account JSON serialized inside a string. The structured
            // form (a parsed JSON object) is handled by the JSON walker.
            kind: "gcp_service_account",
            pattern: r#"(?s)private_key\\?"\s*:\s*\\?"(?P<secret>-----BEGIN .*?-----END [A-Z ]*PRIVATE KEY-----)"#,
            keywords: &["service_account"],
            validator: None,
            priority: 96,
        },
        Spec {
            kind: "azure_storage_connection_string",
            pattern: r"(?i)\b(?:AccountKey|SharedAccessKey)=(?P<secret>[A-Za-z0-9+/]{32,100}={0,2})",
            keywords: &["accountkey=", "sharedaccesskey="],
            validator: None,
            priority: 90,
        },
        Spec {
            // An HMAC-SHA256 signature is 44 base64 chars ending in '=' ('%3D' URL-encoded).
            kind: "azure_sas_token",
            pattern: r"(?i)\bsig=(?P<secret>[A-Za-z0-9%+/]{40,60}(?:%3D|=))",
            keywords: &["sig="],
            validator: None,
            priority: 90,
        },
        Spec {
            kind: "github_token",
            pattern: r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b",
            keywords: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"],
            validator: None,
            priority: 90,
        },
        Spec {
            kind: "gitlab_token",
            pattern: r"\bgl(?:pat|dt|rt|ptt|cbt|oas)-[A-Za-z0-9_\-]{20,}",
            keywords: &["glpat-", "gldt-", "glrt-", "glptt-", "glcbt-", "gloas-"],
            validator: None,
            priority: 90,
        },
        Spec {
            kind: "slack_token",
            pattern: r"\b(?:xox[abposr]-[0-9A-Za-z\-]{10,}|xapp-[0-9]-[A-Za-z0-9\-]{10,})",
            keywords: &["xox", "xapp-"],
            validator: None,
            priority: 90,
        },
        Spec {
            kind: "slack_webhook",
            pattern: r"https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/_\-]{20,}",
            keywords: &["hooks.slack.com"],
            validator: None,
            priority: 92,
        },
        Spec {
            // Secret and restricted keys only; publishable pk_ keys are public by design.
            kind: "stripe_key",
            pattern: r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,}",
            keywords: &["sk_live_", "sk_test_", "rk_live_", "rk_test_"],
            validator: None,
            priority: 90,
        },
        Spec {
            kind: "anthropic_api_key",
            pattern: r"\bsk-ant-[A-Za-z0-9_\-]{32,}",
            keywords: &["sk-ant-"],
            validator: None,
            priority: 95,
        },
        Spec {
            kind: "openai_api_key",
            pattern: r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}",
            keywords: &["sk-"],
            validator: Some(openai_shape),
            priority: 85,
        },
        Spec {
            kind: "jwt",
            pattern: r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{16,}",
            keywords: &["eyj"],
            validator: Some(jwt_header_has_alg),
            priority: 80,
        },
        Spec {
            // The END line is optional so a truncated key is still caught.
            kind: "private_key_pem",
            pattern: r"(?s)-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----(?:.*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----)?",
            keywords: &["private key-----", "private key block-----"],
            validator: None,
            priority: 90,
        },
        Spec {
            kind: "ssh_private_key",
            pattern: r"(?s)-----BEGIN OPENSSH PRIVATE KEY-----(?:.*?-----END OPENSSH PRIVATE KEY-----)?|PuTTY-User-Key-File-[0-9]+: [^\r\n]+",
            keywords: &["openssh private key", "putty-user-key-file-"],
            validator: None,
            priority: 95,
        },
        Spec {
            kind: "db_connection_string",
            pattern: r#"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|oracle|cockroachdb|clickhouse)://[^\s:/@"'<>]+:(?P<secret>[^\s@/"'<>]+)@[^\s"'<>]+"#,
            keywords: &[
                "postgres", "mysql", "mariadb", "mongodb", "redis", "amqp", "mssql", "sqlserver",
                "oracle", "cockroachdb", "clickhouse",
            ],
            validator: Some(not_placeholder),
            priority: 70,
        },
        Spec {
            // ADO.NET / ODBC style: Server=...;User Id=...;Password=...;
            kind: "db_connection_string",
            pattern: r#"(?i)\b(?:Server|Data Source|Host|Address)\s*=[^;"'\r\n]+;[^"'\r\n]*?\b(?:Password|Pwd)\s*=\s*(?P<secret>[^;"'\s]+)"#,
            keywords: &["password=", "pwd=", "password =", "pwd ="],
            validator: Some(not_placeholder),
            priority: 70,
        },
        Spec {
            kind: "basic_auth_url",
            pattern: r#"\bhttps?://[^\s:/@"'<>]+:(?P<secret>[^\s@/"'<>]+)@[A-Za-z0-9.\-]+"#,
            keywords: &["http://", "https://"],
            validator: Some(not_placeholder),
            priority: 70,
        },
        Spec {
            kind: "generic_secret_assignment",
            pattern: r#"(?i)\b(?:password|passwd|pwd|secret|client_secret|api[_\-]?key|access[_\-]?token|auth[_\-]?token|refresh[_\-]?token|private[_\-]?key|secret[_\-]?key)\b\\?["']?\s*[:=]\s*\\?["']?(?P<secret>[^\s"'\\,;&<>]{8,})"#,
            keywords: &["pass", "pwd", "secret", "key", "token"],
            validator: Some(generic_value),
            priority: 30,
        },
    ]
}

fn not_placeholder(secret: &str, _text: &str) -> bool {
    !super::is_placeholder(secret)
}

fn generic_value(secret: &str, _text: &str) -> bool {
    super::keyname::looks_like_secret_value(secret)
}

/// Rejects hyphenated slugs (`sk-this-is-a-long-name`): real keys either carry
/// the `T3BlbkFJ` marker or are long and mix digits with upper and lower case.
fn openai_shape(secret: &str, _text: &str) -> bool {
    secret.contains("T3BlbkFJ") || (secret.len() >= 40 && has_mixed_charset(secret))
}

/// A JWT header must decode to a JSON object with an `alg` member.
fn jwt_header_has_alg(secret: &str, _text: &str) -> bool {
    let Some(header) = secret.split('.').next() else {
        return false;
    };
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let Ok(bytes) = engine.decode(header.trim_end_matches('=')) else {
        return false;
    };
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v.as_object().map(|o| o.contains_key("alg")))
        .unwrap_or(false)
}
