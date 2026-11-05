// Copyright 2026 Salesforce, Inc. All rights reserved.
//! LLM request formats (OpenAI, Anthropic, Gemini): format detection, the
//! conversation parts that are scanned, and secrets split across streamed
//! completion deltas.

use serde_json::Value;

use crate::detect::{Finding, Scanner};
use crate::path::JsonPath;
use crate::walk::{Hit, Walker};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    OpenAi,
    Anthropic,
    Gemini,
}

impl Dialect {
    /// The value of `x-llm-input-format` / `x-input-format` set by the LLM
    /// proxy (case-insensitive). Unknown values are `None`.
    pub fn from_header(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "openai" => Some(Dialect::OpenAi),
            "anthropic" => Some(Dialect::Anthropic),
            "gemini" => Some(Dialect::Gemini),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Dialect::OpenAi => "llm-openai",
            Dialect::Anthropic => "llm-anthropic",
            Dialect::Gemini => "llm-gemini",
        }
    }
}

fn is_gemini_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.contains(":generatecontent") || p.contains(":streamgeneratecontent")
}

/// Format from the path alone (Gemini puts the action in the path).
pub fn dialect_from_path(path: &str) -> Option<Dialect> {
    is_gemini_path(path).then_some(Dialect::Gemini)
}

/// Format from the path and body shape, when the proxy header is absent.
pub fn detect(path: &str, doc: &Value) -> Option<Dialect> {
    if is_gemini_path(path) || doc.get("contents").is_some() {
        return Some(Dialect::Gemini);
    }
    let anthropic_path = path.trim_end_matches('/').to_ascii_lowercase().ends_with("/messages");
    let anthropic_body = doc.get("messages").is_some()
        && ["system", "anthropic_version", "stop_sequences"].iter().any(|k| doc.get(*k).is_some());
    if anthropic_path || anthropic_body {
        return Some(Dialect::Anthropic);
    }
    ["messages", "input", "prompt"]
        .iter()
        .any(|k| doc.get(*k).is_some())
        .then_some(Dialect::OpenAi)
}

/// Operation label for logs; `responses` also selects the Responses API
/// stream error shape.
pub fn operation(d: Dialect, path: &str, doc: &Value) -> String {
    let p = path.trim_end_matches('/').to_ascii_lowercase();
    match d {
        Dialect::OpenAi if p.ends_with("/responses") => "responses".into(),
        Dialect::OpenAi if doc.get("messages").is_some() => "chat.completions".into(),
        Dialect::OpenAi if p.ends_with("/embeddings") => "embeddings".into(),
        Dialect::OpenAi if doc.get("input").is_some() => "responses".into(),
        Dialect::OpenAi => "completions".into(),
        Dialect::Anthropic => "messages".into(),
        Dialect::Gemini => path
            .rsplit_once(':')
            .map(|(_, verb)| verb.split('?').next().unwrap_or(verb).to_string())
            .filter(|v| !v.is_empty() && !v.contains('/'))
            .unwrap_or_else(|| "generateContent".into()),
    }
}

/// `(conversation arrays, instruction members)` for each format.
fn roots(d: Dialect) -> (&'static [&'static str], &'static [&'static str]) {
    match d {
        Dialect::OpenAi => (&["messages", "input"], &["instructions", "prompt"]),
        Dialect::Anthropic => (&["messages"], &["system"]),
        Dialect::Gemini => (&["contents"], &["systemInstruction", "system_instruction"]),
    }
}

/// A turn the model produced (and the client resends as history).
fn is_model_turn(item: &Value) -> bool {
    matches!(item.get("role").and_then(Value::as_str), Some("assistant" | "model"))
        || matches!(item.get("type").and_then(Value::as_str), Some("function_call" | "reasoning"))
}

/// Scans the conversation of an LLM request. With `latest_turn`, only items
/// after the last model turn are scanned, and the instructions only on the
/// first turn, so resent history is not reported again on every call.
/// Model, sampling parameters and tool definitions are never scanned.
pub fn scan_request(doc: &mut Value, d: Dialect, latest_turn: bool, walker: &Walker) -> Vec<Hit> {
    let (conversations, instructions) = roots(d);
    let mut hits = Vec::new();
    let mut has_history = false;
    for key in conversations {
        let Some(node) = doc.get_mut(*key) else { continue };
        let mut path = JsonPath::root();
        path.push_key(key);
        let Value::Array(items) = node else {
            // `input` / `prompt` as a plain string.
            hits.extend(walker.walk_in(node, &mut path));
            continue;
        };
        let start = match items.iter().rposition(is_model_turn) {
            Some(i) if latest_turn => {
                has_history = true;
                i + 1
            }
            _ => 0,
        };
        for (i, item) in items.iter_mut().enumerate().skip(start) {
            path.push_index(i);
            hits.extend(walker.walk_in(item, &mut path));
            path.pop();
        }
    }
    if !has_history {
        for key in instructions {
            if let Some(node) = doc.get_mut(*key) {
                let mut path = JsonPath::root();
                path.push_key(key);
                hits.extend(walker.walk_in(node, &mut path));
            }
        }
    }
    hits
}

/// The completion text carried by one streamed event: content and tool-call
/// argument deltas, which are concatenated across events before scanning.
pub fn stream_deltas(d: Dialect, event: &Value) -> Vec<&str> {
    let mut out = Vec::new();
    match d {
        Dialect::OpenAi => {
            // Responses API: `{"type": "response.output_text.delta", "delta": "..."}`.
            if event.get("type").and_then(Value::as_str).is_some_and(|t| t.ends_with(".delta")) {
                out.extend(event.get("delta").and_then(Value::as_str));
            }
            for choice in event.get("choices").and_then(Value::as_array).into_iter().flatten() {
                let Some(delta) = choice.get("delta") else { continue };
                out.extend(delta.get("content").and_then(Value::as_str));
                out.extend(delta.get("reasoning_content").and_then(Value::as_str));
                for call in delta.get("tool_calls").and_then(Value::as_array).into_iter().flatten() {
                    out.extend(call.pointer("/function/arguments").and_then(Value::as_str));
                }
            }
        }
        Dialect::Anthropic => {
            if let Some(delta) = event.get("delta") {
                for k in ["text", "partial_json", "thinking"] {
                    out.extend(delta.get(k).and_then(Value::as_str));
                }
            }
        }
        Dialect::Gemini => {
            for cand in event.get("candidates").and_then(Value::as_array).into_iter().flatten() {
                for part in cand.pointer("/content/parts").and_then(Value::as_array).into_iter().flatten() {
                    out.extend(part.get("text").and_then(Value::as_str));
                }
            }
        }
    }
    out
}

/// Rolling window over the streamed completion text, so a secret the model
/// emits a few characters per event is still seen as one value.
#[derive(Default)]
pub struct DeltaWindow {
    text: String,
    /// Absolute offset of `text[0]` in the whole stream.
    base: usize,
    /// Absolute start offsets already reported.
    reported: Vec<usize>,
}

/// Text kept after trimming; the window grows to twice this before trimming.
const WINDOW_KEEP: usize = 8192;

impl DeltaWindow {
    /// Appends `deltas` and returns the findings not reported before that
    /// reach into the new text.
    pub fn push(&mut self, scanner: &Scanner, deltas: &[&str]) -> Vec<Finding> {
        let prev = self.text.len();
        for d in deltas {
            self.text.push_str(d);
        }
        if self.text.len() == prev {
            return Vec::new();
        }
        let mut fresh = Vec::new();
        for f in scanner.scan(&self.text) {
            let start = self.base + f.start;
            if f.end > prev && !self.reported.contains(&start) {
                self.reported.push(start);
                fresh.push(f);
            }
        }
        if self.text.len() > 2 * WINDOW_KEEP {
            let mut cut = self.text.len() - WINDOW_KEEP;
            while !self.text.is_char_boundary(cut) {
                cut += 1;
            }
            self.text.drain(..cut);
            self.base += cut;
            let base = self.base;
            self.reported.retain(|s| *s >= base);
        }
        fresh
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::allowlist::Allowlist;
    use crate::path::SkipSet;
    use base64::Engine;
    use serde_json::json;

    fn token() -> String {
        ["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"].concat()
    }

    fn scanner() -> Scanner {
        Scanner::new(&[], &[], None, Allowlist::default(), "").unwrap()
    }

    fn walker<'a>(s: &'a Scanner, skip: &'a SkipSet, redact: bool) -> Walker<'a> {
        Walker { scanner: s, skip, decode_base64: true, max_decoded_bytes: 1 << 20, redact, llm_media: true }
    }

    fn locations(hits: &[Hit]) -> Vec<String> {
        hits.iter().map(|h| h.location.clone()).collect()
    }

    #[test]
    fn header_values() {
        assert_eq!(Dialect::from_header("OpenAI"), Some(Dialect::OpenAi));
        assert_eq!(Dialect::from_header(" anthropic "), Some(Dialect::Anthropic));
        assert_eq!(Dialect::from_header("gemini"), Some(Dialect::Gemini));
        assert_eq!(Dialect::from_header("bedrock"), None);
    }

    #[test]
    fn body_shape_detection() {
        assert_eq!(detect("/v1/chat/completions", &json!({"model": "m", "messages": []})), Some(Dialect::OpenAi));
        assert_eq!(detect("/v1/responses", &json!({"input": "hi"})), Some(Dialect::OpenAi));
        assert_eq!(detect("/v1/messages", &json!({"messages": []})), Some(Dialect::Anthropic));
        assert_eq!(detect("/chat", &json!({"system": "s", "messages": []})), Some(Dialect::Anthropic));
        assert_eq!(detect("/v1beta/models/g:generateContent", &json!({})), Some(Dialect::Gemini));
        assert_eq!(detect("/chat", &json!({"contents": []})), Some(Dialect::Gemini));
        assert_eq!(detect("/orders", &json!({"id": 1})), None);
    }

    #[test]
    fn operations() {
        assert_eq!(operation(Dialect::OpenAi, "/v1/chat/completions", &json!({"messages": []})), "chat.completions");
        assert_eq!(operation(Dialect::OpenAi, "/v1/responses", &json!({"input": "x"})), "responses");
        assert_eq!(operation(Dialect::OpenAi, "/v1/embeddings", &json!({"input": "x"})), "embeddings");
        assert_eq!(operation(Dialect::Gemini, "/v1beta/models/g:streamGenerateContent", &json!({})), "streamGenerateContent");
        assert_eq!(operation(Dialect::Gemini, "/chat", &json!({})), "generateContent");
        assert_eq!(operation(Dialect::Anthropic, "/v1/messages", &json!({})), "messages");
    }

    #[test]
    fn openai_scan_roots_skip_parameters_and_tool_definitions() {
        let s = scanner();
        let skip = SkipSet::default();
        let mut doc = json!({
            "model": token(),
            "tools": [{"type": "function", "function": {"name": "f", "description": token()}}],
            "messages": [
                {"role": "system", "content": "be nice"},
                {"role": "user", "content": [{"type": "text", "text": format!("my key {}", token())}]},
                {"role": "assistant", "tool_calls": [{"function": {"name": "f", "arguments": format!("{{\"password\": \"{}\"}}", "Hunter2!long")}}]}
            ]
        });
        let hits = scan_request(&mut doc, Dialect::OpenAi, false, &walker(&s, &skip, false));
        assert_eq!(
            locations(&hits),
            vec!["$.messages[1].content[0].text", "$.messages[2].tool_calls[0].function.arguments"]
        );
    }

    #[test]
    fn anthropic_and_gemini_roots() {
        let s = scanner();
        let skip = SkipSet::default();
        let mut doc = json!({"system": format!("use {}", token()), "messages": [{"role": "user", "content": [{"type": "tool_result", "content": token()}]}]});
        let hits = scan_request(&mut doc, Dialect::Anthropic, false, &walker(&s, &skip, false));
        assert_eq!(locations(&hits), vec!["$.messages[0].content[0].content", "$.system"]);
        let mut doc = json!({"systemInstruction": {"parts": [{"text": token()}]}, "contents": [{"role": "user", "parts": [{"functionResponse": {"response": {"k": token()}}}]}]});
        let hits = scan_request(&mut doc, Dialect::Gemini, false, &walker(&s, &skip, false));
        assert_eq!(
            locations(&hits),
            vec!["$.contents[0].parts[0].functionResponse.response.k", "$.systemInstruction.parts[0].text"]
        );
    }

    #[test]
    fn latest_turn_skips_resent_history() {
        let s = scanner();
        let skip = SkipSet::default();
        let doc = json!({
            "system": token(),
            "messages": [
                {"role": "user", "content": token()},
                {"role": "assistant", "content": "noted"},
                {"role": "user", "content": format!("again {}", token())}
            ]
        });
        let all = scan_request(&mut doc.clone(), Dialect::Anthropic, false, &walker(&s, &skip, false));
        assert_eq!(all.len(), 3);
        let latest = scan_request(&mut doc.clone(), Dialect::Anthropic, true, &walker(&s, &skip, false));
        assert_eq!(locations(&latest), vec!["$.messages[2].content"]);
        // First turn: no model turn yet, so the instructions are scanned too.
        let mut first = json!({"system": token(), "messages": [{"role": "user", "content": "hi"}]});
        assert_eq!(scan_request(&mut first, Dialect::Anthropic, true, &walker(&s, &skip, false)).len(), 1);
    }

    #[test]
    fn media_is_decoded_or_skipped_and_short_values_still_scanned() {
        let s = scanner();
        let skip = SkipSet::default();
        let engine = base64::engine::general_purpose::STANDARD;
        let image: Vec<u8> = (0..600u32).map(|i| (i * 37 % 251) as u8).collect();
        let text_doc = engine.encode(format!("{}config {}", "x ".repeat(150), token()));
        let mut doc = json!({"messages": [{"role": "user", "content": [
            {"type": "image_url", "image_url": {"url": format!("data:image/png;base64,{}", engine.encode(&image))}},
            {"type": "document", "source": {"type": "base64", "media_type": "text/plain", "data": text_doc}},
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": engine.encode(&image)}},
            {"type": "text", "data": token()}
        ]}]});
        let hits = scan_request(&mut doc, Dialect::Anthropic, false, &walker(&s, &skip, true));
        assert_eq!(locations(&hits), vec!["$.messages[0].content[1].source.data(base64)", "$.messages[0].content[3].data"]);
        let decoded = engine.decode(doc["messages"][0]["content"][1]["source"]["data"].as_str().unwrap()).unwrap();
        assert!(String::from_utf8(decoded).unwrap().ends_with("config [REDACTED:github_token]"));
        assert!(doc["messages"][0]["content"][0]["image_url"]["url"].as_str().unwrap().starts_with("data:image/png;base64,"));
    }

    #[test]
    fn deltas_per_format() {
        let e = json!({"choices": [{"delta": {"content": "a", "tool_calls": [{"function": {"arguments": "b"}}]}}]});
        assert_eq!(stream_deltas(Dialect::OpenAi, &e), vec!["a", "b"]);
        let e = json!({"type": "response.output_text.delta", "delta": "c"});
        assert_eq!(stream_deltas(Dialect::OpenAi, &e), vec!["c"]);
        let e = json!({"type": "content_block_delta", "delta": {"type": "text_delta", "text": "d"}});
        assert_eq!(stream_deltas(Dialect::Anthropic, &e), vec!["d"]);
        let e = json!({"candidates": [{"content": {"parts": [{"text": "e"}]}}]});
        assert_eq!(stream_deltas(Dialect::Gemini, &e), vec!["e"]);
    }

    #[test]
    fn window_finds_a_secret_split_across_deltas_once() {
        let s = scanner();
        let mut w = DeltaWindow::default();
        let t = token();
        let (a, b) = t.split_at(10);
        assert!(w.push(&s, &["here: ", a]).is_empty());
        let found = w.push(&s, &[b, " done"]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, "github_token");
        assert!(w.push(&s, &[" more text"]).is_empty());
    }

    #[test]
    fn window_trims_and_still_detects() {
        let s = scanner();
        let mut w = DeltaWindow::default();
        let filler = "lorem ipsum ".repeat(2000);
        assert!(w.push(&s, &[&filler]).is_empty());
        assert!(w.text.len() <= 2 * WINDOW_KEEP);
        let t = token();
        let (a, b) = t.split_at(20);
        assert!(w.push(&s, &[a]).is_empty());
        assert_eq!(w.push(&s, &[b]).len(), 1);
    }
}
