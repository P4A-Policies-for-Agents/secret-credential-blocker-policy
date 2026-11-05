// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Incremental Server-Sent Events rewriter.
//!
//! Bytes are fed chunk by chunk; complete events (terminated by an empty
//! line, LF or CRLF) are handed to a callback, and an incomplete tail is held
//! back until the next chunk so secrets split across chunks are still seen.

/// What to do with one event.
pub enum Outcome {
    Keep,
    /// Replace the event's `data` with this value (one `data:` line per line).
    Replace(String),
    /// Replace the data, emit the event, and drop everything after it.
    Terminate(String),
}

pub struct Event {
    /// `data` lines joined with `\n`; `None` when the event has no data line.
    pub data: Option<String>,
}

#[derive(Default)]
pub struct SseRewriter {
    pending: Vec<u8>,
    terminated: bool,
}

impl SseRewriter {
    #[cfg(test)]
    pub fn is_terminated(&self) -> bool {
        self.terminated
    }

    /// Feeds one chunk; returns the bytes to emit for it.
    pub fn push(&mut self, chunk: &[u8], f: &mut impl FnMut(&Event) -> Outcome) -> Vec<u8> {
        if self.terminated {
            return Vec::new();
        }
        let mut buf = std::mem::take(&mut self.pending);
        buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        let mut consumed = 0;
        while let Some(end) = event_end(&buf[consumed..]) {
            let raw = &buf[consumed..consumed + end];
            consumed += end;
            if self.process(raw, f, &mut out) {
                return out;
            }
        }
        buf.drain(..consumed);
        self.pending = buf;
        out
    }

    /// Flushes an unterminated trailing event at end of stream.
    pub fn finish(&mut self, f: &mut impl FnMut(&Event) -> Outcome) -> Vec<u8> {
        if self.terminated || self.pending.is_empty() {
            return Vec::new();
        }
        let raw = std::mem::take(&mut self.pending);
        let mut out = Vec::new();
        self.process(&raw, f, &mut out);
        out
    }

    /// Returns `true` when the stream is terminated.
    fn process(&mut self, raw: &[u8], f: &mut impl FnMut(&Event) -> Outcome, out: &mut Vec<u8>) -> bool {
        let event = Event { data: data_of(raw) };
        match f(&event) {
            Outcome::Keep => out.extend_from_slice(raw),
            Outcome::Replace(d) => out.extend_from_slice(&rebuild(raw, &d)),
            Outcome::Terminate(d) => {
                out.extend_from_slice(&rebuild(raw, &d));
                self.terminated = true;
            }
        }
        self.terminated
    }
}

/// Length of the first complete event (through its blank line), if any.
fn event_end(buf: &[u8]) -> Option<usize> {
    let mut start = 0;
    let mut seen_content = false;
    while let Some(nl) = buf[start..].iter().position(|b| *b == b'\n') {
        let line = &buf[start..start + nl];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        start += nl + 1;
        if line.is_empty() {
            if seen_content {
                return Some(start);
            }
        } else {
            seen_content = true;
        }
    }
    None
}

fn lines(raw: &[u8]) -> impl Iterator<Item = &[u8]> {
    raw.split(|b| *b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l))
}

fn data_value(line: &[u8]) -> Option<&[u8]> {
    let rest = line.strip_prefix(b"data")?;
    if rest.is_empty() {
        return Some(rest);
    }
    let rest = rest.strip_prefix(b":")?;
    Some(rest.strip_prefix(b" ").unwrap_or(rest))
}

fn data_of(raw: &[u8]) -> Option<String> {
    let parts: Vec<&[u8]> = lines(raw).filter_map(data_value).collect();
    if parts.is_empty() {
        return None;
    }
    Some(parts.iter().map(|p| String::from_utf8_lossy(p)).collect::<Vec<_>>().join("\n"))
}

/// Re-emits the event with its data lines replaced, other fields kept in
/// place and the original line ending preserved.
fn rebuild(raw: &[u8], data: &str) -> Vec<u8> {
    let eol: &[u8] = if raw.windows(2).any(|w| w == b"\r\n") { b"\r\n" } else { b"\n" };
    let mut out = Vec::new();
    let mut wrote_data = false;
    for line in lines(raw) {
        if line.is_empty() {
            continue;
        }
        if data_value(line).is_some() {
            if !wrote_data {
                for d in data.split('\n') {
                    out.extend_from_slice(b"data: ");
                    out.extend_from_slice(d.as_bytes());
                    out.extend_from_slice(eol);
                }
                wrote_data = true;
            }
            continue;
        }
        out.extend_from_slice(line);
        out.extend_from_slice(eol);
    }
    if !wrote_data {
        out.extend_from_slice(b"data: ");
        out.extend_from_slice(data.as_bytes());
        out.extend_from_slice(eol);
    }
    out.extend_from_slice(eol);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upper(e: &Event) -> Outcome {
        match &e.data {
            Some(d) if d.contains("secret") => Outcome::Replace(d.replace("secret", "[X]")),
            Some(d) if d.contains("stop") => Outcome::Terminate("{\"error\":1}".into()),
            _ => Outcome::Keep,
        }
    }

    fn run(chunks: &[&[u8]]) -> Vec<u8> {
        let mut r = SseRewriter::default();
        let mut f = upper;
        let mut out = Vec::new();
        for c in chunks {
            out.extend(r.push(c, &mut f));
        }
        out.extend(r.finish(&mut f));
        out
    }

    #[test]
    fn keeps_untouched_events_byte_exact() {
        let s = b"event: message\nid: 1\ndata: hello\n\n: comment\n\ndata:[DONE]\n\n";
        assert_eq!(run(&[s]), s.to_vec());
    }

    #[test]
    fn split_across_chunks() {
        let out = run(&[b"id: 7\ndata: a se", b"cret b\n", b"\nda", b"ta: ok\n\n"]);
        assert_eq!(out, b"id: 7\ndata: a [X] b\n\ndata: ok\n\n".to_vec());
    }

    #[test]
    fn crlf_and_multiline_data() {
        let out = run(&[b"data: one\r\ndata: secret\r\nretry: 5\r\n\r\n"]);
        assert_eq!(out, b"data: one\r\ndata: [X]\r\nretry: 5\r\n\r\n".to_vec());
    }

    #[test]
    fn terminate_drops_the_rest() {
        let mut r = SseRewriter::default();
        let mut f = upper;
        let a = r.push(b"data: x\n\ndata: stop\n\ndata: after\n\n", &mut f);
        assert_eq!(a, b"data: x\n\ndata: {\"error\":1}\n\n".to_vec());
        assert!(r.is_terminated());
        assert!(r.push(b"data: more\n\n", &mut f).is_empty());
        assert!(r.finish(&mut f).is_empty());
    }

    #[test]
    fn unterminated_tail_is_flushed_on_finish() {
        assert_eq!(run(&[b"data: secret"]), b"data: [X]\n\n".to_vec());
        assert_eq!(run(&[b"data: fine"]), b"data: fine".to_vec());
    }

    #[test]
    fn leading_blank_lines_do_not_end_an_event() {
        assert_eq!(run(&[b"\n\ndata: secret\n\n"]), b"data: [X]\n\n".to_vec());
    }
}
