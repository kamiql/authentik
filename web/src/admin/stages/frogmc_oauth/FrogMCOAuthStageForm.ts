import "#components/ak-text-input";
import "#elements/forms/HorizontalFormElement";
import "#elements/utils/TimeDeltaHelp";
import { aki } from "#common/api/client";

import { SearchSelectSource, withQuery } from "#elements/forms/SearchSelect/shared";
import { AKSearchSelect } from "#components/ak-search-select-field";

import { BaseStageForm } from "#admin/stages/BaseStageForm";

import { FrogMCOAuthStage, Source, SourcesApi, StagesApi } from "@goauthentik/api";

import { msg } from "@lit/localize";
import { html, TemplateResult } from "lit";
import { customElement } from "lit/decorators.js";
import { ifDefined } from "lit/directives/if-defined.js";

const sourceSource: SearchSelectSource<Source> = {
    fetchObjects: (query) =>
        aki(SourcesApi)
            .sourcesAllList(withQuery(query, { ordering: "name" }))
            .then(({ results }) => results),
    keyOf: (source) => source.pk,
    labelOf: (source) => source.name,
    describe: (source) => source.verboseName,
};

@customElement("ak-stage-frogmc-oauth-form")
export class FrogMCOAuthStageForm extends BaseStageForm<FrogMCOAuthStage> {
    protected endpoints = {
        load: (stageUuid: string) => aki(StagesApi).stagesFrogmcOauthRetrieve({ stageUuid }),
        create: (frogmcOauthStageRequest: FrogMCOAuthStage) =>
            aki(StagesApi).stagesFrogmcOauthCreate({ frogmcOauthStageRequest }),
        update: (stageUuid: string, frogmcOauthStageRequest: FrogMCOAuthStage) =>
            aki(StagesApi).stagesFrogmcOauthUpdate({ stageUuid, frogmcOauthStageRequest }),
    };

    protected override renderForm(): TemplateResult {
        return html`
            <ak-text-input
                label=${msg("Stage Name", { id: "stage.name.label" })}
                required
                name="name"
                value=${this.instance?.name || ""}
                placeholder=${msg("Type a name for this stage...", {
                    id: "stage.name.placeholder",
                })}
                ?autofocus=${!this.instance}
            ></ak-text-input>
            <ak-form-element-horizontal
                label=${msg("Source", { id: "frogmc-oauth.source.label" })}
                required
                name="source"
            >
                ${AKSearchSelect({
                    name: "source",
                    source: sourceSource,
                    value: this.instance?.source,
                    blankable: false,
                })}
            </ak-form-element-horizontal>
            <ak-form-element-horizontal
                label=${msg("Resume timeout", { id: "frogmc-oauth.resume-timeout.label" })}
                required
                name="resumeTimeout"
            >
                <input
                    type="text"
                    value=${ifDefined(this.instance?.resumeTimeout || "minutes=10")}
                    class="pf-c-form-control"
                    required
                />
                <p class="pf-c-form__helper-text">
                    ${msg("Time allowed for source authentication before the flow token expires.", {
                        id: "frogmc-oauth.resume-timeout.description",
                    })}
                </p>
                <ak-utils-time-delta-help></ak-utils-time-delta-help>
            </ak-form-element-horizontal>
        `;
    }
}

declare global {
    interface HTMLElementTagNameMap {
        "ak-stage-frogmc-oauth-form": FrogMCOAuthStageForm;
    }
}
