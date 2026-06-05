package policy

// BuiltinPolicies contains the default Rego policy modules shipped with AgentAuth.
// These provide baseline security for all tenants and can be extended or overridden
// with tenant-specific policies.
var BuiltinPolicies = []PolicyModule{
	{
		ID:      "agentauth.baseline",
		Package: "agentauth.baseline",
		Version: "v1.0.0",
		Source: `
package agentauth.baseline

import future.keywords.if
import future.keywords.in

# Default deny
default allow := false

# Allow if all checks pass
allow if {
    not envelope_expired
    not delegation_depth_exceeded
    not tool_blocked
    tool_scope_allows
}

# Deny if envelope has expired
envelope_expired if {
    input.now > input.agent.envelope_expires_at
}

# Deny if delegation chain is too deep
delegation_depth_exceeded if {
    input.agent.delegation_depth > input.tenant.max_delegation_depth
}

# Deny if tool is on tenant blocklist
tool_blocked if {
    some blocked_tool in input.tenant.blocked_tools
    glob.match(blocked_tool, [], input.request.tool)
}

# Allow if the tool and operation are in the envelope's tool_scope
tool_scope_allows if {
    some scope in input.agent.tool_scope
    glob.match(scope.tool, [], input.request.tool)
    some op in scope.operations
    operation_matches(op, input.request.operation)
}

operation_matches("*", _) := true
operation_matches(op, op) := true

# Violation messages for audit logging
violations[msg] if {
    envelope_expired
    msg := "envelope_expired"
}

violations[msg] if {
    delegation_depth_exceeded
    msg := sprintf("delegation_depth_exceeded: %v > %v",
        [input.agent.delegation_depth, input.tenant.max_delegation_depth])
}

violations[msg] if {
    tool_blocked
    msg := sprintf("tool_blocked_by_tenant: %v", [input.request.tool])
}

violations[msg] if {
    not tool_scope_allows
    not envelope_expired
    msg := sprintf("tool_not_in_scope: %v/%v", [input.request.tool, input.request.operation])
}
`,
	},
	{
		ID:      "agentauth.filesystem_safety",
		Package: "agentauth.filesystem_safety",
		Version: "v1.0.0",
		Source: `
package agentauth.filesystem_safety

import future.keywords.if
import future.keywords.in

# Deny writes to sensitive system paths
deny_sensitive_path if {
    input.request.tool == "filesystem.write"
    some sensitive in sensitive_paths
    startswith(input.request.parameters.path, sensitive)
}

sensitive_paths := [
    "/etc/",
    "/sys/",
    "/proc/",
    "/boot/",
    "~/.ssh/",
    "~/.aws/",
    "~/.config/",
]

# Deny execution of system commands by default
deny_shell_execution if {
    input.request.tool in {"shell.exec", "bash.run", "command.run"}
    not agent_explicitly_allowed_exec
}

agent_explicitly_allowed_exec if {
    some scope in input.agent.tool_scope
    scope.tool == input.request.tool
    "exec" in scope.operations
}
`,
	},
	{
		ID:      "agentauth.data_exfil_prevention",
		Package: "agentauth.data_exfil_prevention",
		Version: "v1.0.0",
		Source: `
package agentauth.data_exfil_prevention

import future.keywords.if
import future.keywords.in

# Limit result set sizes to prevent bulk data exfiltration
deny_large_query if {
    input.request.tool == "database.query"
    limit := to_number(input.request.parameters.limit)
    limit > max_query_limit
}

max_query_limit := 10000

# Deny sending data to external endpoints not in allowlist
deny_external_send if {
    input.request.tool == "http.post"
    not url_in_allowlist(input.request.parameters.url)
}

url_in_allowlist(url) if {
    some allowed in input.tenant.allowed_external_urls
    startswith(url, allowed)
}
`,
	},
}

// DefaultTenantConfig returns a safe default TenantContext for new tenants.
func DefaultTenantConfig(tenantID string) TenantContext {
	return TenantContext{
		ID:                 tenantID,
		MaxDelegationDepth: 4,
		AllowedTools:       []string{},
		BlockedTools: []string{
			"shell.exec",
			"bash.run",
			"command.run",
			"filesystem.delete",
		},
	}
}
