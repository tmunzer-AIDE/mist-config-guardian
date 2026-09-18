"""Guardian's deterministic rule plug-ins and the boundary they run behind.

``PLUGINS`` is the attempt's fixed set, in id order. Their declared read allowances sum to within the attempt's own
rule-read budget, which :func:`base.rule_allowances` checks and the Reader then charges per plug-in.
"""

from mist_config_guardian_backend.guardian.plugins import base
from mist_config_guardian_backend.guardian.plugins.dns import DnsPlugin
from mist_config_guardian_backend.guardian.plugins.switch_port import SwitchPortPlugin
from mist_config_guardian_backend.guardian.plugins.wlan_auth import WlanAuthPlugin
from mist_config_guardian_backend.guardian.plugins.wlan_removal import WlanRemovalPlugin

PLUGINS: tuple[base.RulePlugin, ...] = (DnsPlugin(), SwitchPortPlugin(), WlanAuthPlugin(), WlanRemovalPlugin())

__all__ = ["PLUGINS", "DnsPlugin", "SwitchPortPlugin", "WlanAuthPlugin", "WlanRemovalPlugin", "base"]
