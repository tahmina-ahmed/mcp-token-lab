// Default deny: a tool call is allowed only if the caller's token carries the scope the tool requires.
permit (
    principal,
    action == Action::"CallTool",
    resource
)
when { context.scopes.contains(resource.required_scope) };

// Destructive tools also need explicit human approval, even when the token has the scope.
// This caps what a compromised agent can do with a broad token.
forbid (
    principal,
    action == Action::"CallTool",
    resource
)
when { resource.destructive && !context.human_approved };
