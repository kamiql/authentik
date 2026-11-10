"""FrogMC OAuth stage tests."""

from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.utils.timezone import now
from guardian.shortcuts import get_anonymous_user

from authentik.core.models import Source
from authentik.core.sources.flow_manager import (
    SESSION_KEY_OVERRIDE_FLOW_TOKEN,
    SESSION_KEY_SOURCE_FLOW_CONTEXT,
    SESSION_KEY_SOURCE_FLOW_STAGES,
)
from authentik.core.sources.stage import PostSourceStage
from authentik.core.tests.utils import RequestFactory, create_test_admin_user, create_test_flow
from authentik.flows.markers import StageMarker
from authentik.flows.models import FlowDesignation, FlowStageBinding, FlowToken, in_memory_stage
from authentik.flows.planner import (
    PLAN_CONTEXT_IS_REDIRECTED,
    PLAN_CONTEXT_IS_RESTORED,
    PLAN_CONTEXT_PENDING_USER,
    PLAN_CONTEXT_SOURCE,
    FlowPlan,
)
from authentik.flows.tests import FlowTestCase
from authentik.flows.views.executor import SESSION_KEY_GET, SESSION_KEY_PLAN
from authentik.stages.frogmc_oauth.models import FrogMCOAuthStage
from authentik.stages.frogmc_oauth.session import (
    PLAN_CONTEXT_FROGMC_OAUTH,
    cleanup_frogmc_oauth_session,
)
from authentik.stages.frogmc_oauth.stage import (
    FrogMCOAuthResumeStage,
    FrogMCOAuthStageView,
)
from authentik.stages.invitation.models import Invitation, InvitationStage
from authentik.stages.invitation.stage import (
    PLAN_CONTEXT_INVITATION,
    PLAN_CONTEXT_PROMPT,
    QS_INVITATION_TOKEN_KEY,
    InvitationStageView,
)
from authentik.sources.oauth.models import OAuthSource
from authentik.sources.oauth.views.callback import OAuthSourceFlowManager


class TestFrogMCOAuthStage(FlowTestCase):
    """Suspension and restoration behavior."""

    def setUp(self):
        super().setUp()
        self.flow = create_test_flow(FlowDesignation.ENROLLMENT)
        self.source = Source.objects.create(name="test-source", slug="test-source")
        self.stage = FrogMCOAuthStage.objects.create(
            name="frogmc-oauth", source=self.source, resume_timeout="minutes=10"
        )
        self.binding = FlowStageBinding.objects.create(
            target=self.flow, stage=self.stage, order=0
        )

    def test_model_fields_and_stage_registration(self):
        self.assertIs(self.stage.view, FrogMCOAuthStageView)
        self.assertEqual(self.stage.resume_timeout, "minutes=10")
        self.assertEqual(self.stage.component, "")

    def test_flow_token_captures_plan_with_expiry(self):
        user = create_test_admin_user()
        plan = FlowPlan(
            flow_pk=self.flow.pk.hex,
            bindings=[self.binding],
            markers=[StageMarker()],
            context={"original": "context", PLAN_CONTEXT_PENDING_USER: user},
        )
        request = MagicMock()
        request.session = {}
        executor = MagicMock()
        executor.current_stage = self.stage
        executor.flow = self.flow
        executor.plan = plan
        view = FrogMCOAuthStageView(executor=executor)
        view.request = request
        before = now()

        token = view.create_flow_token()

        self.assertEqual(token.plan.context["original"], "context")
        self.assertEqual(token.plan.bindings[0].stage.pk, self.stage.pk)
        self.assertEqual(token.user, user)
        self.assertGreaterEqual(token.expires, before + timedelta(minutes=10))
        self.assertLessEqual(token.expires, now() + timedelta(minutes=10))

    def test_anonymous_pending_user_uses_anonymous_account_for_token(self):
        plan = FlowPlan(flow_pk=self.flow.pk.hex, context={})
        executor = MagicMock()
        executor.current_stage = self.stage
        executor.flow = self.flow
        executor.plan = plan
        view = FrogMCOAuthStageView(executor=executor)
        view.request = MagicMock()
        view.request.user = get_anonymous_user()

        token = view.create_flow_token()

        self.assertEqual(token.user, get_anonymous_user())

    def test_get_challenge_registers_dynamic_resume(self):
        challenge = MagicMock()
        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        executor = MagicMock()
        executor.current_stage = self.stage
        executor.flow = self.flow
        executor.plan = plan
        view = FrogMCOAuthStageView(executor=executor)
        view.request = MagicMock()
        view.request.session = {}
        view.login_button = MagicMock(challenge=challenge)
        token = MagicMock(spec=FlowToken)

        with patch.object(view, "create_flow_token", return_value=token):
            actual = view.get_challenge()

        self.assertIs(actual, challenge)
        self.assertIs(view.request.session[SESSION_KEY_OVERRIDE_FLOW_TOKEN], token)
        self.assertEqual(
            view.request.session[SESSION_KEY_SOURCE_FLOW_STAGES][0].view,
            FrogMCOAuthResumeStage,
        )
        self.assertIn(SESSION_KEY_SOURCE_FLOW_CONTEXT, view.request.session)

    def test_missing_source_is_rejected(self):
        executor = MagicMock()
        executor.current_stage = self.stage
        request = MagicMock()
        request.session = {}
        view = FrogMCOAuthStageView(executor=executor)
        view.request = request
        expected = MagicMock()
        executor.stage_invalid.return_value = expected

        with patch("authentik.stages.frogmc_oauth.stage.Source.objects.filter") as filter_source:
            filter_source.return_value.select_subclasses.return_value.first.return_value = None
            response = view.dispatch(request)

        self.assertIs(response, expected)
        executor.stage_invalid.assert_called_once_with("Source does not exist")

    def test_source_without_ui_login_button_is_rejected(self):
        source = MagicMock()
        source.ui_login_button.return_value = None
        source.enrollment_flow = self.flow
        executor = MagicMock()
        executor.current_stage = self.stage
        request = MagicMock()
        request.session = {}
        view = FrogMCOAuthStageView(executor=executor)
        view.request = request
        expected = MagicMock()
        executor.stage_invalid.return_value = expected

        with patch("authentik.stages.frogmc_oauth.stage.Source.objects.filter") as filter_source:
            filter_source.return_value.select_subclasses.return_value.first.return_value = source
            response = view.dispatch(request)

        self.assertIs(response, expected)
        executor.stage_invalid.assert_called_once_with(
            "Source cannot authenticate through a browser flow"
        )

    def test_restored_stage_clears_session_without_restarting_oauth(self):
        self.source.enrollment_flow = self.flow
        self.source.save()
        restored_token = MagicMock(pk="restored-token")
        session_token = MagicMock(pk="restored-token")
        request = MagicMock()
        request.session = {
            SESSION_KEY_OVERRIDE_FLOW_TOKEN: session_token,
            SESSION_KEY_SOURCE_FLOW_CONTEXT: {},
            SESSION_KEY_SOURCE_FLOW_STAGES: [],
        }
        executor = MagicMock()
        executor.current_stage = self.stage
        executor.plan.context = {PLAN_CONTEXT_IS_RESTORED: restored_token}
        expected = MagicMock()
        executor.stage_ok.return_value = expected
        view = FrogMCOAuthStageView(executor=executor)

        with patch.object(Source, "ui_login_button", return_value=MagicMock()):
            response = view.dispatch(request)

        self.assertIs(response, expected)
        self.assertEqual(request.session, {})
        executor.stage_ok.assert_called_once()

    def test_resume_preserves_invitation_context_and_merges_source_data(self):
        invitation_stage = InvitationStage.objects.create(name="frogmc-invitation")
        invitation_binding = FlowStageBinding.objects.create(
            target=self.flow, stage=invitation_stage, order=0
        )
        invitation = Invitation.objects.create(
            name="frogmc-invite",
            created_by=get_anonymous_user(),
            fixed_data={"fixed_field": "invitation", "first": "original"},
            flow=self.flow,
        )
        request = MagicMock()
        request.session = {
            SESSION_KEY_GET: {QS_INVITATION_TOKEN_KEY: str(invitation.pk)},
        }
        request.user = get_anonymous_user()
        original_plan = FlowPlan(
            flow_pk=self.flow.pk.hex,
            bindings=[invitation_binding, self.binding],
            markers=[StageMarker(), StageMarker()],
            context={},
        )
        invitation_executor = MagicMock()
        invitation_executor.current_stage = invitation_stage
        invitation_executor.plan = original_plan
        invitation_executor.flow = self.flow
        invitation_view = InvitationStageView(executor=invitation_executor)
        invitation_view.request = request

        invitation_response = invitation_view.dispatch(request)
        self.assertIs(invitation_response, invitation_executor.stage_ok.return_value)
        self.assertIs(original_plan.context[PLAN_CONTEXT_INVITATION], invitation)
        self.assertEqual(
            original_plan.context[PLAN_CONTEXT_PROMPT],
            {"fixed_field": "invitation", "first": "original"},
        )
        original_plan.pop()

        source_executor = MagicMock()
        source_executor.current_stage = self.stage
        source_executor.plan = original_plan
        source_executor.flow = self.flow
        source_view = FrogMCOAuthStageView(executor=source_executor)
        source_view.request = request
        token = source_view.create_flow_token()
        request.session[SESSION_KEY_OVERRIDE_FLOW_TOKEN] = token

        source_plan = FlowPlan(
            flow_pk=self.flow.pk.hex,
            context={
                PLAN_CONTEXT_SOURCE: self.source,
                PLAN_CONTEXT_PROMPT: {"fixed_field": "oauth", "email": "user@example.test"},
                "source_result": True,
            },
        )
        executor = MagicMock()
        executor.plan = source_plan
        view = FrogMCOAuthResumeStage(executor=executor)
        view.request = request
        expected_response = MagicMock()
        with patch.object(
            FlowPlan,
            "to_redirect",
            autospec=True,
            return_value=expected_response,
        ) as redirect:
            response = view.dispatch(request)

        self.assertIs(response, expected_response)
        resumed_plan = redirect.call_args.args[0]
        self.assertEqual(resumed_plan.context[PLAN_CONTEXT_INVITATION], invitation)
        self.assertEqual(
            resumed_plan.context[PLAN_CONTEXT_PROMPT],
            {"fixed_field": "invitation", "first": "original", "email": "user@example.test"},
        )
        self.assertTrue(resumed_plan.context["source_result"])
        self.assertIs(resumed_plan.context[PLAN_CONTEXT_IS_RESTORED], token)
        self.assertFalse(FlowToken.objects.filter(pk=token.pk).exists())

        executor.stage_invalid.return_value = MagicMock()
        reused_response = view.dispatch(request)
        self.assertIs(reused_response, executor.stage_invalid.return_value)
        self.assertEqual(request.session, {})

    def test_expired_flow_token_is_rejected_and_session_is_cleaned(self):
        token = FlowToken.objects.create(
            user=get_anonymous_user(),
            identifier="frogmc-expired-resume-test",
            flow=self.flow,
            expires=now() - timedelta(minutes=1),
            _plan=FlowToken.pickle(FlowPlan(flow_pk=self.flow.pk.hex)),
        )
        request = MagicMock()
        request.session = {SESSION_KEY_OVERRIDE_FLOW_TOKEN: token}
        executor = MagicMock()
        expected = MagicMock()
        executor.stage_invalid.return_value = expected
        view = FrogMCOAuthResumeStage(executor=executor)

        response = view.dispatch(request)

        self.assertIs(response, expected)
        self.assertEqual(request.session, {})
        self.assertFalse(FlowToken.objects.filter(pk=token.pk).exists())

    def test_deleted_flow_token_is_rejected_and_session_is_cleaned(self):
        token = FlowToken.objects.create(
            user=get_anonymous_user(),
            identifier="frogmc-deleted-resume-test",
            flow=self.flow,
            expires=now() + timedelta(minutes=10),
            _plan=FlowToken.pickle(FlowPlan(flow_pk=self.flow.pk.hex)),
        )
        token.delete()
        request = MagicMock()
        request.session = {SESSION_KEY_OVERRIDE_FLOW_TOKEN: token}
        executor = MagicMock()
        expected = MagicMock()
        executor.stage_invalid.return_value = expected
        view = FrogMCOAuthResumeStage(executor=executor)

        response = view.dispatch(request)

        self.assertIs(response, expected)
        self.assertEqual(request.session, {})

    def test_missing_session_token_is_rejected(self):
        request = MagicMock()
        request.session = {}
        executor = MagicMock()
        expected = MagicMock()
        executor.stage_invalid.return_value = expected
        view = FrogMCOAuthResumeStage(executor=executor)

        response = view.dispatch(request)

        self.assertIs(response, expected)
        executor.stage_invalid.assert_called_once_with("Flow token is invalid or expired")

    def test_failed_oauth_cleanup_revokes_only_our_session_token(self):
        token = FlowToken.objects.create(
            user=get_anonymous_user(),
            identifier="frogmc-oauth-cleanup-test",
            flow=self.flow,
            expires=now() + timedelta(minutes=10),
            _plan=FlowToken.pickle(FlowPlan(flow_pk=self.flow.pk.hex)),
        )
        request = MagicMock()
        request.session = {
            SESSION_KEY_OVERRIDE_FLOW_TOKEN: token,
            SESSION_KEY_SOURCE_FLOW_CONTEXT: {},
            SESSION_KEY_SOURCE_FLOW_STAGES: [],
        }

        self.assertTrue(cleanup_frogmc_oauth_session(request))
        self.assertEqual(request.session, {})
        self.assertFalse(FlowToken.objects.filter(pk=token.pk).exists())

    def test_source_flow_manager_appends_dynamic_resume_stage(self):
        source_flow = create_test_flow(FlowDesignation.ENROLLMENT)
        source = OAuthSource.objects.create(
            name="test-oauth-source",
            slug="test-oauth-source",
            enrollment_flow=source_flow,
        )
        source_flow_token = FlowToken.objects.create(
            user=get_anonymous_user(),
            identifier="frogmc-source-flow-test",
            flow=self.flow,
            expires=now() + timedelta(minutes=10),
            _plan=FlowToken.pickle(
                FlowPlan(
                    flow_pk=self.flow.pk.hex,
                    bindings=[self.binding],
                    markers=[StageMarker()],
                )
            ),
        )
        request = RequestFactory().get("/")
        request.session[SESSION_KEY_OVERRIDE_FLOW_TOKEN] = source_flow_token
        request.session[SESSION_KEY_SOURCE_FLOW_STAGES] = [
            in_memory_stage(FrogMCOAuthResumeStage)
        ]
        request.session[SESSION_KEY_SOURCE_FLOW_CONTEXT] = {
            PLAN_CONTEXT_IS_REDIRECTED: self.flow,
        }
        manager = OAuthSourceFlowManager(source, request, "new-user", {"info": {}}, {})

        response = manager.get_flow()

        self.assertEqual(response.status_code, 302)
        source_plan = request.session[SESSION_KEY_PLAN]
        self.assertEqual(source_plan.flow_pk, source_flow.pk.hex)
        self.assertEqual(source_plan.bindings[-1].stage.view, FrogMCOAuthResumeStage)
        self.assertEqual(source_plan.context[PLAN_CONTEXT_IS_REDIRECTED], self.flow)

    def test_source_enrollment_flow_same_as_original_resumes_saved_plan(self):
        """Do not restart an invitation enrollment flow after OAuth enrollment."""
        invitation_context = {"validated_invitation": "invite-id"}
        original_plan = FlowPlan(
            flow_pk=self.flow.pk.hex,
            bindings=[self.binding],
            markers=[StageMarker()],
            context={
                PLAN_CONTEXT_FROGMC_OAUTH: True,
                PLAN_CONTEXT_INVITATION: invitation_context,
            },
        )
        token = FlowToken.objects.create(
            user=get_anonymous_user(),
            identifier="frogmc-oauth-same-enrollment-flow",
            flow=self.flow,
            expires=now() + timedelta(minutes=10),
            _plan=FlowToken.pickle(original_plan),
        )
        source = OAuthSource.objects.create(
            name="test-same-flow-source",
            slug="test-same-flow-source",
            enrollment_flow=self.flow,
        )
        request = RequestFactory().get("/")
        request.session[SESSION_KEY_OVERRIDE_FLOW_TOKEN] = token
        manager = OAuthSourceFlowManager(
            source,
            request,
            "new-user",
            {"info": {"username": "new-user", "email": "user@example.test"}},
            {},
        )

        response = manager.get_flow()

        self.assertEqual(response.status_code, 302)
        resumed_plan = request.session[SESSION_KEY_PLAN]
        self.assertEqual(resumed_plan.flow_pk, self.flow.pk.hex)
        self.assertEqual(resumed_plan.bindings[0].stage, self.stage)
        self.assertEqual(resumed_plan.context[PLAN_CONTEXT_INVITATION], invitation_context)
        self.assertIs(resumed_plan.context[PLAN_CONTEXT_IS_RESTORED], token)
        self.assertEqual(resumed_plan.bindings[-2].stage.view, PostSourceStage)
        self.assertFalse(FlowToken.objects.filter(pk=token.pk).exists())
