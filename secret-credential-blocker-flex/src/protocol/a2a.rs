// Copyright 2026 Salesforce, Inc. All rights reserved.
//! A2A v0.3 / v1.0 vocabulary, version detection and the v1.0 HTTP+JSON route matcher.

/// v0.3 JSON-RPC methods.
const V03_METHODS: &[&str] = &[
    "message/send",
    "message/stream",
    "tasks/get",
    "tasks/list",
    "tasks/cancel",
    "tasks/stream",
    "tasks/resubscribe",
    "tasks/pushNotificationConfig/set",
    "tasks/pushNotificationConfig/get",
    "tasks/pushNotificationConfig/list",
    "tasks/pushNotificationConfig/delete",
    "agent/card",
    "agent/capabilities",
    "agent/getAuthenticatedExtendedCard",
];

/// v1.0 JSON-RPC methods.
const V1_METHODS: &[&str] = &[
    "SendMessage",
    "SendStreamingMessage",
    "GetTask",
    "ListTasks",
    "CancelTask",
    "SubscribeToTask",
    "CreateTaskPushNotificationConfig",
    "GetTaskPushNotificationConfig",
    "ListTaskPushNotificationConfigs",
    "DeleteTaskPushNotificationConfig",
    "GetExtendedAgentCard",
];

pub fn is_a2a_method(method: &str) -> bool {
    V03_METHODS.contains(&method) || V1_METHODS.contains(&method)
}

pub fn is_v1_method(method: &str) -> bool {
    V1_METHODS.contains(&method)
}

/// Push-notification config writes carry webhook credentials the agent needs;
/// those members are not scanned (the webhook `url` still is).
pub fn is_push_config_write(op: &str) -> bool {
    matches!(op, "tasks/pushNotificationConfig/set" | "CreateTaskPushNotificationConfig")
}

/// v1.0 is signalled by an `A2A-Version: 1.0` header or `?A2A-Version=1.0`
/// (case-insensitive key).
pub fn is_v1(header: Option<&str>, query: &str) -> bool {
    if header.map(str::trim) == Some("1.0") {
        return true;
    }
    form_urlencoded::parse(query.as_bytes())
        .any(|(k, v)| k.eq_ignore_ascii_case("a2a-version") && v.trim() == "1.0")
}

/// Maps a v1.0 HTTP+JSON request to its operation, tolerating a `/{tenant}`
/// prefix (and any gateway base path) before the A2A route.
pub fn http_json_operation(method: &str, path: &str) -> Option<&'static str> {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let last = *segs.last()?;
    let prev = segs.len().checked_sub(2).map(|i| segs[i]);
    let prev2 = segs.len().checked_sub(3).map(|i| segs[i]);
    match method {
        "POST" if last == "message:send" => Some("SendMessage"),
        "POST" if last == "message:stream" => Some("SendStreamingMessage"),
        "POST" if prev == Some("tasks") && last.ends_with(":cancel") => Some("CancelTask"),
        "POST" if prev == Some("tasks") && last.ends_with(":subscribe") => Some("SubscribeToTask"),
        "GET" if prev == Some("tasks") && last.ends_with(":subscribe") => Some("SubscribeToTask"),
        "POST" if last == "pushNotificationConfigs" && prev2 == Some("tasks") => {
            Some("CreateTaskPushNotificationConfig")
        }
        "GET" if last == "pushNotificationConfigs" && prev2 == Some("tasks") => {
            Some("ListTaskPushNotificationConfigs")
        }
        "GET" if prev == Some("pushNotificationConfigs") => Some("GetTaskPushNotificationConfig"),
        "DELETE" if prev == Some("pushNotificationConfigs") => {
            Some("DeleteTaskPushNotificationConfig")
        }
        "GET" if last == "tasks" => Some("ListTasks"),
        "GET" if prev == Some("tasks") => Some("GetTask"),
        "GET" if last == "extendedAgentCard" => Some("GetExtendedAgentCard"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_detection() {
        assert!(is_v1(Some(" 1.0 "), ""));
        assert!(is_v1(None, "x=1&a2a-version=1.0"));
        assert!(!is_v1(Some("0.3"), "A2A-Version=0.3"));
        assert!(!is_v1(None, ""));
    }

    #[test]
    fn http_json_routes() {
        let cases = [
            ("POST", "/message:send", Some("SendMessage")),
            ("POST", "/acme/message:stream", Some("SendStreamingMessage")),
            ("POST", "/tasks/t1:cancel", Some("CancelTask")),
            ("POST", "/acme/tasks/t1:subscribe", Some("SubscribeToTask")),
            ("POST", "/tasks/t1/pushNotificationConfigs", Some("CreateTaskPushNotificationConfig")),
            ("GET", "/tasks/t1/pushNotificationConfigs", Some("ListTaskPushNotificationConfigs")),
            ("GET", "/tasks/t1/pushNotificationConfigs/c1", Some("GetTaskPushNotificationConfig")),
            ("DELETE", "/tasks/t1/pushNotificationConfigs/c1", Some("DeleteTaskPushNotificationConfig")),
            ("GET", "/acme/tasks", Some("ListTasks")),
            ("GET", "/tasks/t1", Some("GetTask")),
            ("GET", "/extendedAgentCard", Some("GetExtendedAgentCard")),
            ("POST", "/orders", None),
            ("GET", "/", None),
        ];
        for (m, p, want) in cases {
            assert_eq!(http_json_operation(m, p), want, "{m} {p}");
        }
    }
}
