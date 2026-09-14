"""Shared plan and publication bounds; every required check must fit a revision."""

MAX_AUDIT_VERSIONS = 64
MAX_WLAN_TARGETS = 4
MAX_PORT_TARGETS = 2
MAX_NEIGHBOR_TARGETS = MAX_PORT_TARGETS
MAX_DOCUMENTATION_TARGETS = 2
MAX_CHECKPOINT_EVIDENCE = (
    3 * MAX_WLAN_TARGETS + 2 * MAX_PORT_TARGETS + 2 * MAX_NEIGHBOR_TARGETS + MAX_DOCUMENTATION_TARGETS
)

# Independent spending ceiling, not a promise to fund every possible checkpoint.
# A maximal twenty-two-check plan funds two full checkpoints and twelve more checks.
MAX_AUDIT_CALLS = 56
MAX_PUBLISHED_CHECKPOINTS = 10  # Lifecycle safety cap; ordinary scheduling has seven checkpoints.

MAX_PORT_EVENTS = 200
MAX_AGENT_PORT_EVENTS = 20

# In MCP-led mode, optional rules must leave room for investigation. Four checks
# per normal checkpoint use at most 28 of the 56 audit slots across one hour.
MAX_OPTIONAL_RULE_CHECKS = 4
