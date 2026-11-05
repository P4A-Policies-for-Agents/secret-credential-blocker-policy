// Copyright 2026 Salesforce, Inc. All rights reserved.
//! MCP JSON-RPC method vocabulary.

/// Known MCP methods. Used only to recognize MCP traffic in `protocol: auto`.
pub const METHODS: &[&str] = &[
    "initialize",
    "ping",
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/templates/list",
    "resources/read",
    "resources/subscribe",
    "resources/unsubscribe",
    "prompts/list",
    "prompts/get",
    "completion/complete",
    "logging/setLevel",
    "sampling/createMessage",
    "elicitation/create",
    "roots/list",
];

/// Methods whose params carry no user content; they pass through unscanned.
const NO_CONTENT: &[&str] = &[
    "initialize",
    "ping",
    "tools/list",
    "resources/list",
    "resources/templates/list",
    "prompts/list",
    "logging/setLevel",
    "roots/list",
];

pub const TOOLS_CALL: &str = "tools/call";

pub fn is_mcp_method(method: &str) -> bool {
    METHODS.contains(&method) || method.starts_with("notifications/")
}

pub fn carries_content(method: &str) -> bool {
    !NO_CONTENT.contains(&method)
}
