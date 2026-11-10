"""FrogMC OAuth stage model."""

from django.db import models
from django.utils.translation import gettext_lazy as _
from django.views import View
from rest_framework.serializers import BaseSerializer

from authentik.flows.models import Stage
from authentik.lib.utils.time import timedelta_string_validator


class FrogMCOAuthStage(Stage):
    """Suspend the current flow for browser authentication with a configured source."""

    source = models.ForeignKey("authentik_core.Source", on_delete=models.CASCADE)
    resume_timeout = models.TextField(
        default="minutes=10",
        validators=[timedelta_string_validator],
        help_text=_("Time allowed for source authentication before the flow token expires."),
    )

    @property
    def serializer(self) -> type[BaseSerializer]:
        from authentik.stages.frogmc_oauth.api import FrogMCOAuthStageSerializer

        return FrogMCOAuthStageSerializer

    @property
    def view(self) -> type[View]:
        from authentik.stages.frogmc_oauth.stage import FrogMCOAuthStageView

        return FrogMCOAuthStageView

    @property
    def component(self) -> str:
        return "ak-stage-frogmc-oauth-form"

    class Meta:
        verbose_name = _("FrogMC OAuth Stage")
        verbose_name_plural = _("FrogMC OAuth Stages")
