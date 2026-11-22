// AgentOctopus Quickstart Deterministic Cedar Policy
permit (
    principal,
    action == Octopus::Action::"exec",
    resource is Octopus::Command
) when {
    context has stem && (context.stem == "python" || context.stem == "python3")
};

forbid (
    principal,
    action == Octopus::Action::"exec",
    resource is Octopus::Command
) when {
    context has stem && (
        context.stem == "bash" ||
        context.stem == "sh" ||
        context.stem == "powershell" ||
        context.stem == "pwsh" ||
        context.stem == "cmd"
    )
};

permit (
    principal,
    action == Octopus::Action::"egress",
    resource is Octopus::NetworkTarget
) when {
    context.destination_domain == "api.github.com" ||
    context.destination_domain == "127.0.0.1"
};

forbid (
    principal,
    action == Octopus::Action::"egress",
    resource is Octopus::NetworkTarget
) when {
    context.destination_domain == "169.254.169.254" ||
    context.destination_domain == "100.100.100.200" ||
    context.destination_domain == "evil.example.com"
};

permit (
    principal,
    action == Octopus::Action::"fs_read",
    resource is Octopus::FilePath
) unless {
    context has is_sensitive && context.is_sensitive == true
};