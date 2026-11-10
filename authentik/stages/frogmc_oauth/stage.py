"""Suspend and resume an existing flow around browser source authentication."""

from typing import Any
from uuid import uuid4

from django.http import HttpRequest, HttpResponse
from django.utils.text import slugify
from django.utils.timezone import now
from guardian.shortcuts import get_anonymous_user

from authentik.core.models import Source, User
from authentik.core.sources.flow_manager import (
    PLAN_CONTEXT_SOURCE_MATCH_FAILURE,
    PLAN_CONTEXT_SOURCE_MATCH_FAILURE_CONFIG,
    SESSION_KEY_OVERRIDE_FLOW_TOKEN,
    SESSION_KEY_SOURCE_FLOW_CONTEXT,
    SESSION_KEY_SOURCE_FLOW_STAGES,
    clear_source_flow_session,
)
from authentik.core.types import UILoginButton
from authentik.flows.challenge import Challenge, ChallengeResponse
from authentik.flows.models import FlowToken, in_memory_stage
from authentik.flows.planner import (
    PLAN_CONTEXT_IS_REDIRECTED,
    PLAN_CONTEXT_IS_RESTORED,
    PLAN_CONTEXT_SOURCE,
    FlowPlan,
)
from authentik.flows.stage import ChallengeStageView, StageView
from authentik.lib.utils.time import timedelta_from_string
from authentik.stages.prompt.stage import PLAN_CONTEXT_PROMPT
from authentik.stages.frogmc_oauth.session import (
    PLAN_CONTEXT_FROGMC_OAUTH,
    cleanup_frogmc_oauth_session,
)


class FrogMCOAuthStageView(ChallengeStageView):
    """Issue the selected source's normal login challenge and suspend this plan."""

    login_button: UILoginButton

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        stage = self.executor.current_stage
        source: Source | None = (
            Source.objects.filter(pk=stage.source_id).select_subclasses().first()
        )
        if not source:
            self.clear_pending_source_flow(request)
            return self.executor.stage_invalid("Source does not exist")

        if not source.enrollment_flow:
            self.clear_pending_source_flow(request)
            return self.executor.stage_invalid("Source cannot authenticate through a browser flow")
        self.login_button = source.ui_login_button(request)
        if not self.login_button:
            self.clear_pending_source_flow(request)
            return self.executor.stage_invalid("Source cannot authenticate through a browser flow")

        restored_token = self.executor.plan.context.get(PLAN_CONTEXT_IS_RESTORED)
        session_token = request.session.get(SESSION_KEY_OVERRIDE_FLOW_TOKEN)
        if restored_token and session_token and restored_token.pk == session_token.pk:
            clear_source_flow_session(request)
            self.executor.plan.context.pop(PLAN_CONTEXT_SOURCE_MATCH_FAILURE_CONFIG, None)
            self.executor.plan.context.pop(PLAN_CONTEXT_FROGMC_OAUTH, None)
            if restored_token.is_expired:
                return self.executor.stage_invalid("Flow token is invalid or expired")
            return self.executor.stage_ok()

        # A prior attempt can be abandoned before the source callback. Revoke its
        # token before starting a fresh authentication to avoid orphaned plans.
        if not self.clear_pending_source_flow(request):
            return self.executor.stage_invalid("A source authentication is already pending")

        return super().dispatch(request, *args, **kwargs)

    @staticmethod
    def clear_pending_source_flow(request: HttpRequest) -> bool:
        """Delete stale resume state before an invalid or fresh source attempt."""
        if SESSION_KEY_OVERRIDE_FLOW_TOKEN in request.session:
            return cleanup_frogmc_oauth_session(request)
        clear_source_flow_session(request)
        return True

    def get_challenge(self, *args, **kwargs) -> Challenge:
        token = self.create_flow_token()
        self.request.session[SESSION_KEY_OVERRIDE_FLOW_TOKEN] = token
        self.request.session[SESSION_KEY_SOURCE_FLOW_STAGES] = [
            in_memory_stage(FrogMCOAuthResumeStage)
        ]
        self.request.session[SESSION_KEY_SOURCE_FLOW_CONTEXT] = {
            PLAN_CONTEXT_IS_REDIRECTED: self.executor.flow,
        }
        return self.login_button.challenge

    def create_flow_token(self) -> FlowToken:
        """Persist the current plan with an expiry and a session-bound opaque token."""
        pending_user: User = self.get_pending_user()
        if pending_user.is_anonymous or not pending_user.pk:
            pending_user = get_anonymous_user()

        stage = self.executor.current_stage
        identifier = slugify(f"frogmc-oauth-{stage.name}-{uuid4()}")
        self.executor.plan.context[PLAN_CONTEXT_FROGMC_OAUTH] = True
        return FlowToken.objects.create(
            expires=now() + timedelta_from_string(stage.resume_timeout),
            user=pending_user,
            identifier=identifier,
            flow=self.executor.flow,
            _plan=FlowToken.pickle(self.executor.plan),
        )

    def challenge_valid(self, _response: ChallengeResponse) -> HttpResponse:
        # A browser source challenge navigates away; keep presenting it if a client posts back.
        return self.get(self.request)


class FrogMCOAuthResumeStage(StageView):
    """Restore the suspended plan after the source manager finishes its own flow."""

    def dispatch(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        token = request.session.get(SESSION_KEY_OVERRIDE_FLOW_TOKEN)
        if not isinstance(token, FlowToken):
            clear_source_flow_session(request)
            return self.executor.stage_invalid("Flow token is invalid or expired")

        try:
            token.refresh_from_db()
        except FlowToken.DoesNotExist:
            clear_source_flow_session(request)
            return self.executor.stage_invalid("Flow token is invalid or expired")

        if token.is_expired:
            token.expire_action()
            clear_source_flow_session(request)
            return self.executor.stage_invalid("Flow token is invalid or expired")

        try:
            plan = token.plan
        except (AttributeError, EOFError, ImportError, IndexError):
            token.delete()
            clear_source_flow_session(request)
            return self.executor.stage_invalid("Flow token is invalid or expired")
        if not isinstance(plan, FlowPlan):
            token.delete()
            clear_source_flow_session(request)
            return self.executor.stage_invalid("Flow token is invalid or expired")

        original_stage = plan.bindings[0].stage if plan.bindings else None
        source = self.executor.plan.context.get(PLAN_CONTEXT_SOURCE)
        if (
            not original_stage
            or getattr(original_stage, "source_id", None) is None
            or not source
            or source.pk != original_stage.source_id
        ):
            token.delete()
            clear_source_flow_session(request)
            return self.executor.stage_invalid("Source does not match the suspended flow")

        original_prompt = plan.context.get(PLAN_CONTEXT_PROMPT, {})
        source_context = self.executor.plan.context
        plan.context.update(source_context)

        # Invitation fixed_data is already validated and merged into the original prompt.
        # Keep its values authoritative while filling other fields from source claims.
        source_prompt = source_context.get(PLAN_CONTEXT_PROMPT, {})
        if original_prompt or source_prompt:
            merged_prompt = dict(source_prompt)
            merged_prompt.update(original_prompt)
            plan.context[PLAN_CONTEXT_PROMPT] = merged_prompt

        plan.context.pop(PLAN_CONTEXT_SOURCE_MATCH_FAILURE_CONFIG, None)
        plan.context.pop(PLAN_CONTEXT_SOURCE_MATCH_FAILURE, None)
        plan.context.pop(PLAN_CONTEXT_IS_REDIRECTED, None)
        plan.context.pop(PLAN_CONTEXT_FROGMC_OAUTH, None)
        plan.context[PLAN_CONTEXT_IS_RESTORED] = token

        response = plan.to_redirect(request, token.flow)
        token.delete()
        return response
