"""FrogMC OAuth stage API."""

from rest_framework.exceptions import ValidationError
from rest_framework.viewsets import ModelViewSet

from authentik.core.api.used_by import UsedByMixin
from authentik.core.models import Source
from authentik.flows.api.stages import StageSerializer
from authentik.stages.frogmc_oauth.models import FrogMCOAuthStage


class FrogMCOAuthStageSerializer(StageSerializer):
    """Configure the source used by a FrogMC OAuth stage."""

    def validate_source(self, source: Source) -> Source:
        source = Source.objects.filter(pk=source.pk).select_subclasses().first()
        if not source:
            raise ValidationError("Invalid source")
        if not source.enrollment_flow:
            raise ValidationError("Source must have an enrollment flow")
        request = self.context.get("request")
        if request and not source.ui_login_button(request):
            raise ValidationError("Only sources with browser login are supported")
        return source

    class Meta:
        model = FrogMCOAuthStage
        fields = StageSerializer.Meta.fields + ["source", "resume_timeout"]


class FrogMCOAuthStageViewSet(UsedByMixin, ModelViewSet):
    """Create and configure FrogMC OAuth stages."""

    queryset = FrogMCOAuthStage.objects.all()
    serializer_class = FrogMCOAuthStageSerializer
    filterset_fields = ["stage_uuid", "name", "source", "resume_timeout"]
    ordering = ["name"]
    search_fields = ["name"]
