"""Shared plan and publication bounds; every required check must fit a revision."""

MAX_AUDIT_VERSIONS = 64
MAX_WLAN_TARGETS = 4
MAX_PORT_TARGETS = 2
MAX_NEIGHBOR_TARGETS = MAX_PORT_TARGETS
MAX_CHECKPOINT_EVIDENCE = 2 * MAX_WLAN_TARGETS + MAX_PORT_TARGETS + MAX_NEIGHBOR_TARGETS

# Independent spending ceiling, not a promise to fund every possible checkpoint.
# A maximal twelve-check plan funds four full checkpoints and eight reads at the fifth.
MAX_AUDIT_CALLS = 56
MAX_PUBLISHED_CHECKPOINTS = 10  # Lifecycle safety cap; ordinary scheduling has seven checkpoints.
