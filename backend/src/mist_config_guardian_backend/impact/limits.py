"""Shared plan and publication bounds; every required check must fit a revision."""

MAX_AUDIT_VERSIONS = 64
MAX_WLAN_TARGETS = 4
MAX_PORT_TARGETS = 2
MAX_CHECKPOINT_EVIDENCE = 2 * MAX_WLAN_TARGETS + MAX_PORT_TARGETS

# Independent spending ceiling, not a promise to fund every possible checkpoint.
# A maximal ten-check plan funds five full checkpoints and six reads at the sixth.
MAX_AUDIT_CALLS = 56
MAX_PUBLISHED_CHECKPOINTS = 10  # Lifecycle safety cap; ordinary scheduling has seven checkpoints.
