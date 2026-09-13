"""Shared plan and publication bounds; every required check must fit a revision."""

MAX_AUDIT_VERSIONS = 64
MAX_WLAN_TARGETS = 4
MAX_PORT_TARGETS = 2
MAX_NEIGHBOR_TARGETS = MAX_PORT_TARGETS
MAX_CHECKPOINT_EVIDENCE = 3 * MAX_WLAN_TARGETS + 2 * MAX_PORT_TARGETS + 2 * MAX_NEIGHBOR_TARGETS

# Independent spending ceiling, not a promise to fund every possible checkpoint.
# A maximal twenty-check plan funds two full checkpoints and sixteen more reads.
MAX_AUDIT_CALLS = 56
MAX_PUBLISHED_CHECKPOINTS = 10  # Lifecycle safety cap; ordinary scheduling has seven checkpoints.

MAX_PORT_EVENTS = 200
MAX_AGENT_PORT_EVENTS = 20
