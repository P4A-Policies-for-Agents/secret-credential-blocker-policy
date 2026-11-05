// Copyright 2026 Salesforce, Inc. All rights reserved.
//! `multipart/form-data` and `multipart/mixed` scanning.
//!
//! Only part headers are interpreted; part bodies are located by byte offset
//! so redaction can rewrite one part and leave every other byte untouched.

use anyhow::{anyhow, bail, Result};
use serde_json::Value;

use crate::redact;
use crate::walk::{Hit, Walker};

use super::query;

#[derive(Debug)]
struct Part {
    name: String,
    content_type: Option<String>,
    filename: bool,
    /// Byte range of the part body within the whole multipart body.
    start: usize,
    end: usize,
}

pub struct MultipartScan {
    pub hits: Vec<Hit>,
    pub rewritten: Option<Vec<u8>>,
}

/// `multipart/*; boundary=...` → boundary (quotes stripped).
pub fn boundary(content_type: &str) -> Option<String> {
    let (mime, params) = content_type.split_once(';')?;
    if !mime.trim().to_ascii_lowercase().starts_with("multipart/") {
        return None;
    }
    params.split(';').find_map(|p| {
        let (k, v) = p.split_once('=')?;
        if !k.trim().eq_ignore_ascii_case("boundary") {
            return None;
        }
        let v = v.trim().trim_matches('"');
        (!v.is_empty() && v.len() <= 70).then(|| v.to_string())
    })
}

pub fn is_multipart(content_type: &str) -> bool {
    let ct = content_type.trim().to_ascii_lowercase();
    ct.starts_with("multipart/form-data") || ct.starts_with("multipart/mixed")
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from > hay.len() {
        return None;
    }
    hay[from..].windows(needle.len()).position(|w| w == needle).map(|p| p + from)
}

fn parse(body: &[u8], boundary: &str) -> Result<Vec<Part>> {
    let delim = format!("--{boundary}");
    let delim = delim.as_bytes();
    let malformed = || anyhow!("malformed multipart body");
    let mut pos = find(body, delim, 0).ok_or_else(malformed)?;
    let mut parts = Vec::new();
    loop {
        pos += delim.len();
        if body[pos..].starts_with(b"--") {
            return Ok(parts);
        }
        // Rest of the delimiter line (transport padding) then CRLF/LF.
        let line_end = find(body, b"\n", pos).ok_or_else(malformed)?;
        let headers_start = line_end + 1;
        let (headers_end, body_start) = match (find(body, b"\r\n\r\n", headers_start), find(body, b"\n\n", headers_start)) {
            (Some(a), Some(b)) if b < a => (b, b + 2),
            (Some(a), _) => (a, a + 4),
            (None, Some(b)) => (b, b + 2),
            (None, None) if body[headers_start..].starts_with(b"\r\n") => (headers_start, headers_start + 2),
            (None, None) => bail!("malformed multipart body"),
        };
        let next = find(body, delim, body_start).ok_or_else(malformed)?;
        let mut end = next;
        if end >= body_start + 2 && &body[end - 2..end] == b"\r\n" {
            end -= 2;
        } else if end > body_start && body[end - 1] == b'\n' {
            end -= 1;
        } else if end != body_start {
            bail!("malformed multipart body");
        }
        let headers = std::str::from_utf8(&body[headers_start..headers_end]).map_err(|_| malformed())?;
        let mut part = Part { name: String::new(), content_type: None, filename: false, start: body_start, end };
        for line in headers.lines() {
            let Some((k, v)) = line.split_once(':') else { continue };
            let k = k.trim().to_ascii_lowercase();
            if k == "content-type" {
                part.content_type = Some(v.trim().to_ascii_lowercase());
            } else if k == "content-disposition" {
                for p in v.split(';').skip(1) {
                    let Some((pk, pv)) = p.split_once('=') else { continue };
                    match pk.trim().to_ascii_lowercase().as_str() {
                        "name" => part.name = pv.trim().trim_matches('"').to_string(),
                        "filename" | "filename*" => part.filename = true,
                        _ => {}
                    }
                }
            }
        }
        parts.push(part);
        pos = next;
    }
}

enum Kind {
    Text,
    Json,
    Form,
    Skip,
}

fn kind(part: &Part) -> Kind {
    match part.content_type.as_deref().map(|c| c.split(';').next().unwrap_or("").trim()) {
        None if part.filename => Kind::Skip,
        None | Some("") => Kind::Text,
        Some(ct) if ct.ends_with("/json") || ct.ends_with("+json") => Kind::Json,
        Some("application/x-www-form-urlencoded") => Kind::Form,
        Some(ct) if ct.starts_with("text/") => Kind::Text,
        _ => Kind::Skip,
    }
}

/// Scans text, JSON and urlencoded parts. Errors on a malformed body.
pub fn scan(body: &[u8], boundary: &str, walker: &Walker) -> Result<MultipartScan> {
    let parts = parse(body, boundary)?;
    let mut hits = Vec::new();
    let mut replacements: Vec<(usize, usize, Vec<u8>)> = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        let label = if part.name.is_empty() { format!("[{i}]") } else { part.name.clone() };
        if walker.skip.multipart(&label) {
            continue;
        }
        let k = kind(part);
        if matches!(k, Kind::Skip) {
            continue;
        }
        let Ok(text) = std::str::from_utf8(&body[part.start..part.end]) else {
            continue;
        };
        let location = format!("multipart:{label}");
        let replacement = match k {
            Kind::Json => match serde_json::from_str::<Value>(text) {
                Ok(mut doc) => {
                    let found = walker.walk_at(&mut doc, &[]);
                    let changed = walker.redact && !found.is_empty();
                    hits.extend(found.into_iter().map(|mut h| {
                        h.location = format!("{location}{}", h.location.trim_start_matches('$'));
                        h
                    }));
                    changed.then(|| serde_json::to_vec(&doc)).transpose()?
                }
                Err(_) => scan_text(&location, &part.name, text, walker, &mut hits),
            },
            Kind::Form => {
                let r = query::scan(text, &format!("{location}."), walker, |_| false);
                hits.extend(r.hits);
                r.rewritten.map(String::into_bytes)
            }
            _ => scan_text(&location, &part.name, text, walker, &mut hits),
        };
        if let Some(bytes) = replacement {
            replacements.push((part.start, part.end, bytes));
        }
    }
    let rewritten = (!replacements.is_empty()).then(|| {
        let mut out = Vec::with_capacity(body.len());
        let mut cursor = 0;
        for (start, end, bytes) in replacements {
            out.extend_from_slice(&body[cursor..start]);
            out.extend_from_slice(&bytes);
            cursor = end;
        }
        out.extend_from_slice(&body[cursor..]);
        out
    });
    Ok(MultipartScan { hits, rewritten })
}

fn scan_text(location: &str, name: &str, text: &str, walker: &Walker, hits: &mut Vec<Hit>) -> Option<Vec<u8>> {
    let findings = walker.scanner.scan_field(name, text, false);
    if findings.is_empty() {
        return None;
    }
    hits.extend(Hit::from_findings(location, &findings));
    walker.redact.then(|| redact::apply(text, &findings).into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{allowlist::Allowlist, Scanner};
    use crate::path::SkipSet;

    fn token() -> String {
        ["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"].concat()
    }

    fn run(body: &[u8], redact: bool, skip: &[&str]) -> Result<MultipartScan> {
        let s = Scanner::new(&[], &[], None, Allowlist::default(), "").unwrap();
        let skip = SkipSet::parse(&skip.iter().map(|s| format!("multipart:{s}")).collect::<Vec<_>>()).unwrap();
        let w = Walker { scanner: &s, skip: &skip, decode_base64: false, max_decoded_bytes: 0, redact };
        scan(body, "XyZ", &w)
    }

    fn body(token: &str) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"preamble\r\n--XyZ\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n");
        b.extend_from_slice(format!("see {token}").as_bytes());
        b.extend_from_slice(b"\r\n--XyZ\r\nContent-Disposition: form-data; name=\"meta\"\r\nContent-Type: application/json\r\n\r\n");
        b.extend_from_slice(format!("{{\"cfg\":{{\"t\":\"{token}\"}}}}").as_bytes());
        b.extend_from_slice(b"\r\n--XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\n");
        b.extend_from_slice(&[0x89, b'P', b'N', b'G', 0xff]);
        b.extend_from_slice(token.as_bytes());
        b.extend_from_slice(b"\r\n--XyZ--\r\nepilogue");
        b
    }

    #[test]
    fn boundary_parsing() {
        assert_eq!(boundary("multipart/form-data; boundary=\"a b\"").as_deref(), Some("a b"));
        assert_eq!(boundary("Multipart/Mixed;charset=x; BOUNDARY=q1").as_deref(), Some("q1"));
        assert_eq!(boundary("application/json; boundary=x"), None);
        assert_eq!(boundary("multipart/form-data"), None);
    }

    #[test]
    fn scans_text_and_json_skips_files() {
        let r = run(&body(&token()), false, &[]).unwrap();
        let locs: Vec<_> = r.hits.iter().map(|h| h.location.as_str()).collect();
        assert_eq!(locs, vec!["multipart:note", "multipart:meta.cfg.t"]);
    }

    #[test]
    fn redact_is_byte_exact_outside_hit_parts() {
        let original = body(&token());
        let r = run(&original, true, &[]).unwrap();
        let expected = body("[REDACTED:github_token]");
        // The binary part keeps the raw token: it is not scanned.
        let mut expected_file = expected.clone();
        let marker = b"[REDACTED:github_token]\r\n--XyZ--";
        let at = find(&expected_file, marker, 0).unwrap();
        expected_file.splice(at..at + marker.len() - 9, token().into_bytes());
        assert_eq!(r.rewritten.unwrap(), expected_file);
    }

    #[test]
    fn lf_only_and_skip() {
        let raw = format!("--XyZ\nContent-Disposition: form-data; name=\"a\"\n\n{}\n--XyZ--\n", token());
        assert_eq!(run(raw.as_bytes(), false, &[]).unwrap().hits.len(), 1);
        assert!(run(raw.as_bytes(), false, &["a"]).unwrap().hits.is_empty());
    }

    #[test]
    fn malformed_is_error() {
        assert!(run(b"no boundary here", false, &[]).is_err());
        assert!(run(b"--XyZ\r\nContent-Disposition: form-data; name=a\r\n\r\nunterminated", false, &[]).is_err());
    }
}
