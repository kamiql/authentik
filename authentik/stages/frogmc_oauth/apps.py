"""authentik FrogMC OAuth stage app config"""

from authentik.blueprints.apps import ManagedAppConfig


class AuthentikStageFrogMCOAuthConfig(ManagedAppConfig):
    """Register the FrogMC OAuth stage."""

    name = "authentik.stages.frogmc_oauth"
    label = "authentik_stages_frogmc_oauth"
    verbose_name = "authentik Stages.FrogMC OAuth"
    default = True
