"""Session cleanup for interrupted FrogMC OAuth attempts."""

from django.http import HttpRequest

from authentik.core.sources.flow_manager import (
    SESSION_KEY_OVERRIDE_FLOW_TOKEN,
    clear_source_flow_session,
)
from authentik.flows.models import FlowToken

PLAN_CONTEXT_FROGMC_OAUTH = "goauthentik.io/stages/frogmc_oauth/suspended"


def cleanup_frogmc_oauth_session(request: HttpRequest) -> bool:
    """Revoke this stage's token and session keys after a failed source attempt."""
    token = request.session.get(SESSION_KEY_OVERRIDE_FLOW_TOKEN)
    if not isinstance(token, FlowToken) or not token.identifier.startswith("frogmc-oauth-"):
        return False

    try:
        token.refresh_from_db()
    except FlowToken.DoesNotExist:
        pass
    else:
        token.delete()
    clear_source_flow_session(request)
    return True
