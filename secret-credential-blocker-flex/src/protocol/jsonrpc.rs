// Copyright 2026 Salesforce, Inc. All rights reserved.
//! JSON-RPC 2.0 envelope recognition.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub enum Envelope {
    /// A request (or notification, when `id` is `None`).
    Single { method: String, id: Option<Value> },
    /// A batch: a non-empty array whose members are all request envelopes.
    Batch,
    NotJsonRpc,
}

fn single(v: &Value) -> Option<(String, Option<Value>)> {
    let obj = v.as_object()?;
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return None;
    }
    let method = obj.get("method").and_then(Value::as_str)?;
    Some((method.to_string(), obj.get("id").cloned()))
}

pub fn envelope(doc: &Value) -> Envelope {
    match doc {
        Value::Array(items) if !items.is_empty() && items.iter().all(|i| single(i).is_some()) => {
            Envelope::Batch
        }
        _ => match single(doc) {
            Some((method, id)) => Envelope::Single { method, id },
            None => Envelope::NotJsonRpc,
        },
    }
}

/// A JSON-RPC response envelope (`result` or `error` member).
pub fn is_response(doc: &Value) -> bool {
    doc.as_object().is_some_and(|o| {
        o.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
            && (o.contains_key("result") || o.contains_key("error"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn recognizes_envelopes() {
        assert_eq!(
            envelope(&json!({"jsonrpc":"2.0","method":"tools/call","id":7})),
            Envelope::Single { method: "tools/call".into(), id: Some(json!(7)) }
        );
        assert_eq!(
            envelope(&json!({"jsonrpc":"2.0","method":"notifications/initialized"})),
            Envelope::Single { method: "notifications/initialized".into(), id: None }
        );
        assert_eq!(envelope(&json!([{"jsonrpc":"2.0","method":"a","id":1}])), Envelope::Batch);
        assert_eq!(envelope(&json!({"jsonrpc":"1.0","method":"a"})), Envelope::NotJsonRpc);
        assert_eq!(envelope(&json!({"method":"a"})), Envelope::NotJsonRpc);
        assert_eq!(envelope(&json!([])), Envelope::NotJsonRpc);
        assert!(is_response(&json!({"jsonrpc":"2.0","id":1,"result":{}})));
        assert!(!is_response(&json!({"jsonrpc":"2.0","method":"x"})));
    }
}
