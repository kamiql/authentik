"""FrogMC OAuth stage API URLs."""

from authentik.stages.frogmc_oauth.api import FrogMCOAuthStageViewSet

api_urlpatterns = [("stages/frogmc_oauth", FrogMCOAuthStageViewSet)]
