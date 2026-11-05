// Copyright 2026 Salesforce, Inc. All rights reserved.
//! JSON locations for findings (`$.params.arguments.token`) and the
//! `allowlist.skipPaths` patterns matched against them.

use anyhow::{anyhow, bail, Result};

#[derive(Debug, Clone, PartialEq)]
pub enum Seg {
    Key(String),
    Index(usize),
}

/// Path from the document root to the value being scanned.
#[derive(Debug, Clone, Default)]
pub struct JsonPath(Vec<Seg>);

impl JsonPath {
    pub fn root() -> Self {
        Self(Vec::new())
    }

    pub fn push_key(&mut self, key: &str) {
        self.0.push(Seg::Key(key.to_string()));
    }

    pub fn push_index(&mut self, index: usize) {
        self.0.push(Seg::Index(index));
    }

    pub fn pop(&mut self) {
        self.0.pop();
    }

    pub fn segments(&self) -> &[Seg] {
        &self.0
    }

    /// Renders as `$.a.b[2]`, quoting keys that are not plain identifiers: `$['x-y']`.
    pub fn render(&self) -> String {
        let mut out = String::from("$");
        for seg in &self.0 {
            match seg {
                Seg::Index(i) => out.push_str(&format!("[{i}]")),
                Seg::Key(k) if is_identifier(k) => {
                    out.push('.');
                    out.push_str(k);
                }
                Seg::Key(k) => {
                    out.push_str("['");
                    out.push_str(&k.replace('\\', "\\\\").replace('\'', "\\'"));
                    out.push_str("']");
                }
            }
        }
        out
    }
}

fn is_identifier(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[derive(Debug, Clone, PartialEq)]
enum PatSeg {
    Key(String),
    Index(usize),
    /// `*` or `[*]`: any key or index.
    Any,
    /// `..`: zero or more segments.
    Descend,
}

/// A parsed skip pattern. Matching is by prefix: skipping `$.a` skips everything under `$.a`.
#[derive(Debug, Clone)]
pub struct JsonPattern(Vec<PatSeg>);

impl JsonPattern {
    pub fn parse(raw: &str) -> Result<Self> {
        let s = raw.trim();
        let rest = s
            .strip_prefix('$')
            .ok_or_else(|| anyhow!("skip path '{s}' must start with '$'"))?;
        let chars: Vec<char> = rest.chars().collect();
        let mut segs = Vec::new();
        let mut i = 0;
        while i < chars.len() {
            match chars[i] {
                '.' if chars.get(i + 1) == Some(&'.') => {
                    segs.push(PatSeg::Descend);
                    i += 2;
                    if chars.get(i) == Some(&'[') {
                        continue;
                    }
                    i = parse_name(&chars, i, &mut segs, s)?;
                }
                '.' => {
                    i = parse_name(&chars, i + 1, &mut segs, s)?;
                }
                '[' => {
                    let close = chars[i..]
                        .iter()
                        .position(|c| *c == ']')
                        .map(|p| p + i)
                        .ok_or_else(|| anyhow!("skip path '{s}' has an unclosed '['"))?;
                    let inner: String = chars[i + 1..close].iter().collect();
                    let inner = inner.trim();
                    if inner == "*" {
                        segs.push(PatSeg::Any);
                    } else if let Ok(n) = inner.parse::<usize>() {
                        segs.push(PatSeg::Index(n));
                    } else if inner.len() >= 2
                        && ((inner.starts_with('\'') && inner.ends_with('\''))
                            || (inner.starts_with('"') && inner.ends_with('"')))
                    {
                        segs.push(PatSeg::Key(inner[1..inner.len() - 1].to_string()));
                    } else {
                        bail!("skip path '{s}' has an invalid selector '[{inner}]'");
                    }
                    i = close + 1;
                }
                other => bail!("skip path '{s}' has an unexpected character '{other}'"),
            }
        }
        if matches!(segs.last(), Some(PatSeg::Descend)) {
            bail!("skip path '{s}' cannot end with '..'");
        }
        Ok(Self(segs))
    }

    pub fn matches(&self, path: &JsonPath) -> bool {
        match_prefix(&self.0, path.segments())
    }
}

/// `allowlist.skipPaths`, split by location type.
#[derive(Debug, Default)]
pub struct SkipSet {
    json: Vec<JsonPattern>,
    headers: Vec<String>,
    query: Vec<String>,
    form: Vec<String>,
    multipart: Vec<String>,
}

impl SkipSet {
    pub fn parse(entries: &[String]) -> Result<Self> {
        let mut set = Self::default();
        for raw in entries {
            let e = raw.trim();
            if let Some(h) = e.strip_prefix("header:") {
                set.headers.push(h.trim().to_ascii_lowercase());
            } else if let Some(q) = e.strip_prefix("query:") {
                set.query.push(q.trim().to_string());
            } else if let Some(f) = e.strip_prefix("form:") {
                set.form.push(f.trim().to_string());
            } else if let Some(m) = e.strip_prefix("multipart:") {
                set.multipart.push(m.trim().to_string());
            } else {
                set.json.push(JsonPattern::parse(e)?);
            }
        }
        Ok(set)
    }

    pub fn json(&self, path: &JsonPath) -> bool {
        self.json.iter().any(|p| p.matches(path))
    }

    pub fn header(&self, name: &str) -> bool {
        self.headers.iter().any(|h| h.eq_ignore_ascii_case(name))
    }

    pub fn query(&self, name: &str) -> bool {
        self.query.iter().any(|q| q == name)
    }

    pub fn form(&self, name: &str) -> bool {
        self.form.iter().any(|f| f == name)
    }

    pub fn multipart(&self, name: &str) -> bool {
        self.multipart.iter().any(|m| m == name)
    }
}

fn parse_name(chars: &[char], start: usize, segs: &mut Vec<PatSeg>, s: &str) -> Result<usize> {
    let mut end = start;
    while end < chars.len() && chars[end] != '.' && chars[end] != '[' {
        end += 1;
    }
    if end == start {
        bail!("skip path '{s}' has an empty segment");
    }
    let name: String = chars[start..end].iter().collect();
    segs.push(if name == "*" { PatSeg::Any } else { PatSeg::Key(name) });
    Ok(end)
}

fn match_prefix(pat: &[PatSeg], path: &[Seg]) -> bool {
    let Some((first, rest)) = pat.split_first() else {
        return true;
    };
    if *first == PatSeg::Descend {
        return (0..=path.len()).any(|i| match_prefix(rest, &path[i..]));
    }
    let Some((seg, path_rest)) = path.split_first() else {
        return false;
    };
    let ok = match (first, seg) {
        (PatSeg::Any, _) => true,
        (PatSeg::Key(k), Seg::Key(s)) => k == s,
        (PatSeg::Index(n), Seg::Index(i)) => n == i,
        _ => false,
    };
    ok && match_prefix(rest, path_rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(segs: &[Seg]) -> JsonPath {
        JsonPath(segs.to_vec())
    }

    fn k(s: &str) -> Seg {
        Seg::Key(s.to_string())
    }

    #[test]
    fn renders_identifiers_indexes_and_quoted_keys() {
        let p = path(&[k("params"), k("parts"), Seg::Index(2), k("x-api-key"), k("it's")]);
        assert_eq!(p.render(), "$.params.parts[2]['x-api-key']['it\\'s']");
        assert_eq!(JsonPath::root().render(), "$");
    }

    #[test]
    fn exact_and_prefix_match() {
        let pat = JsonPattern::parse("$.params.arguments").unwrap();
        assert!(pat.matches(&path(&[k("params"), k("arguments"), k("token")])));
        assert!(pat.matches(&path(&[k("params"), k("arguments")])));
        assert!(!pat.matches(&path(&[k("params")])));
        assert!(!pat.matches(&path(&[k("params"), k("other")])));
    }

    #[test]
    fn wildcards_and_indexes() {
        let pat = JsonPattern::parse("$.items[*].key").unwrap();
        assert!(pat.matches(&path(&[k("items"), Seg::Index(7), k("key")])));
        assert!(!pat.matches(&path(&[k("items"), Seg::Index(7), k("value")])));
        let pat = JsonPattern::parse("$.items[1]").unwrap();
        assert!(pat.matches(&path(&[k("items"), Seg::Index(1), k("a")])));
        assert!(!pat.matches(&path(&[k("items"), Seg::Index(0)])));
        let pat = JsonPattern::parse("$.*.token").unwrap();
        assert!(pat.matches(&path(&[k("a"), k("token")])));
    }

    #[test]
    fn recursive_descent() {
        let pat = JsonPattern::parse("$..password").unwrap();
        assert!(pat.matches(&path(&[k("password")])));
        assert!(pat.matches(&path(&[k("a"), Seg::Index(0), k("b"), k("password")])));
        assert!(!pat.matches(&path(&[k("a"), k("passwords")])));
        let pat = JsonPattern::parse("$..['x-key']").unwrap();
        assert!(pat.matches(&path(&[k("a"), k("x-key")])));
    }

    #[test]
    fn skip_set_splits_prefixes() {
        let s = SkipSet::parse(&[
            "header:X-Api-Key".into(),
            "query:key".into(),
            "form:pw".into(),
            "multipart:avatar".into(),
            "$.a".into(),
        ])
        .unwrap();
        assert!(s.header("x-api-key"));
        assert!(s.query("key") && !s.query("Key"));
        assert!(s.form("pw") && !s.query("pw"));
        assert!(s.multipart("avatar"));
        assert!(s.json(&path(&[k("a"), k("b")])));
        assert!(SkipSet::parse(&["nope".into()]).is_err());
    }

    #[test]
    fn rejects_invalid_patterns() {
        for bad in ["params.a", "$.a[", "$.a[x]", "$..", "$.a..", "$a", "$.a.."] {
            assert!(JsonPattern::parse(bad).is_err(), "{bad} should be rejected");
        }
    }
}
