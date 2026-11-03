# Stage 1, task 1, part B: what landed, per PR (#140714, #142493, #137633, #141959, #143024)

Sources: `git diff --stat <merge>^1 <merge>`, then the filtered diff (excluding vendor, `zz_generated*`, `generated.pb.go`,
`testdata/**`, `openapi/**`, `api/openapi-spec/**`). For #143024: `git show f410163f598` with the same filter.
Generated files were read only when needed: their exported function names (`zz_generated.validations.go`) and the
proto field numbers (`generated.proto`).

Line-number conventions:
- **(d) feature-gate checks** cite `path:line` in the post-image of the diff, i.e. the file as of the merge commit
  (or as of `f410163f598` for #143024). Most of these lines are unchanged on HEAD. Where I checked HEAD and it differs,
  I say so.
- **(b)/(c) symbols** carry a HEAD `path:line` where I grepped it (marked "HEAD"); otherwise just the file.

Notes on code that changed after these PRs landed:
- Commit `60a11890371` ("apiserver: keep CEL out of the webhook authorizer and authorizerfactory", author dims) is not
  part of the series. It landed between #137633 and HEAD and changed `webhook.New` / `newWithBackoff` /
  `NewFromInterface`: they now take a compiled `Matcher` instead of `matchConditions []WebhookMatchCondition` plus a
  `compiler`. So the #137633 signatures quoted below are not the HEAD signatures. The #143024 diff is written against
  the `Matcher` form.
- #137633 rewrote parts of #140714 (renamed `sarV1` to `versionedSAR`, swapped `rest.DeclarativeValidationConfig{}` for
  `apiservervalidation.DeclarativeValidationConfig()`).

> **Orchestrator correction (2026-11-03):** statements below that the `AuthorizationConditionsEnforcer` plugin is default-OFF in kube-apiserver or in the sample generic server are WRONG. On HEAD `pkg/kubeapiserver/options/plugins.go:193` lists it in `defaultOnPlugins`, and `pkg/controlplane/apiserver/samples/generic/server/admission.go:52` likewise. It is default-on everywhere and inert while the gate is off (`Handles()` false). See `D-tests-gates-api.md` §2.5.

---

## PR #140714: Move authz validation/defaults to k8s.io/apiserver (merge `5f72f13c16f`)

**Summary.** The hand-written SAR/SSAR/LSAR validation moves out of `pkg/apis/authorization/validation` and into the new
staging package `k8s.io/apiserver/pkg/apis/authorization/validation`. It is rewritten to operate on **external v1**
types (`k8s.io/api/authorization/v1`) rather than the internal types, so that k8s.io/apiserver importers (the webhook
authorizer in #137633) can reuse it. The kube-side `Validate*Create` functions convert internal→v1 with the generated
`Convert_authorization_*_To_v1_*` functions (scope `nil`), then call the staging validators. Declarative validation is
also published for `k8s.io/api/authorization/v1` itself (new `zz_generated.validations.go`). The title says
"validation/defaults", but **no defaulting code moves**: the diff contains only validation.

Stat: 5 files, +601/−235 (306 lines are generated declarative validation).

**(a) Packages touched**
- `k8s.io/kubernetes/pkg/apis/authorization/validation`
- `k8s.io/apiserver/pkg/apis/authorization/validation` (new package)
- `k8s.io/api/authorization/v1` (`doc.go` tags, plus the generated `zz_generated.validations.go`)

**(b) New / changed exported symbols**
- `staging/src/k8s.io/apiserver/pkg/apis/authorization/validation/validation.go` (new). These are moved from
  `pkg/apis/authorization/validation` with the parameter types changed from `authorizationapi.*` to `authorizationv1.*`:
  - `func ValidateSubjectAccessReviewSpec(spec authorizationv1.SubjectAccessReviewSpec, fldPath *field.Path) field.ErrorList`
  - `func ValidateSelfSubjectAccessReviewSpec(spec authorizationv1.SelfSubjectAccessReviewSpec, fldPath *field.Path) field.ErrorList`
  - `func ValidateSubjectAccessReview(sar *authorizationv1.SubjectAccessReview) field.ErrorList`
  - `func ValidateSelfSubjectAccessReview(sar *authorizationv1.SelfSubjectAccessReview) field.ErrorList`
  - `func ValidateLocalSubjectAccessReview(sar *authorizationv1.LocalSubjectAccessReview) field.ErrorList`
  - unexported helpers: `validateResourceAttributes`, `validateFieldSelectorAttributes`, `validateLabelSelectorAttributes`.
- `pkg/apis/authorization/validation/validation.go`: **removed exports**: `ValidateSubjectAccessReviewSpec`,
  `ValidateSelfSubjectAccessReviewSpec`, `ValidateSubjectAccessReview`, `ValidateSelfSubjectAccessReview`,
  `ValidateLocalSubjectAccessReview`. This is a breaking change for anyone importing them from k/k.
  `Validate{,Self,Local}SubjectAccessReviewCreate` keep their signatures but now convert to v1 first.
- `staging/src/k8s.io/api/authorization/v1/zz_generated.validations.go` (generated, new): `Validate_SubjectAccessReview`,
  `Validate_SelfSubjectAccessReview`, `Validate_LocalSubjectAccessReview`, `Validate_SubjectAccessReviewSpec`,
  `Validate_SelfSubjectAccessReviewSpec`. Enabled by new tags in `staging/src/k8s.io/api/authorization/v1/doc.go`:
  `+k8s:validation-gen=TypesWithField=TypeMeta`, `+k8s:validation-gen-scheme-registry=nil`.

**(c) API fields.** None.

**(d) Feature-gate checks added.** None.

**(e) Tests**
- `pkg/apis/authorization/validation/validation_test.go` was **renamed** to
  `staging/src/k8s.io/apiserver/pkg/apis/authorization/validation/validation_test.go` (67% similarity). The only change
  is internal→v1 types. It covers the same SAR spec, SSAR spec and LSAR metadata/namespace cases as before. No new
  cases.

**(f) Gate-off behaviour changes visible to callers.** For API clients, none: the same rules run, on a byte-identical v1
copy. For Go importers of k/k, the five removed exported functions break the build (see (b)).

---

## PR #142493: `GetOldObject` for `VersionedAttributes` (merge `fa5423953d4`)

**Summary.** It adds `(*admission.VersionedAttributes).GetOldObject()`. The method returns `VersionedOldObject`'s object
when one is set, and otherwise falls back to the embedded `Attributes.GetOldObject()`. This mirrors the existing
`GetObject()` override. It is needed so that `VersionedAttributes`, passed as `authorizer.ConditionsData`, exposes the
old object **in the request's external version** instead of the internal one.

Stat: 2 files, +41.

**(a) Packages touched:** `k8s.io/apiserver/pkg/admission`.

**(b) New / changed exported symbols**
- `staging/src/k8s.io/apiserver/pkg/admission/conversion.go`: new method
  `func (v *VersionedAttributes) GetOldObject() runtime.Object` (HEAD `conversion.go:63`).

**(c) API fields.** None.

**(d) Feature-gate checks added.** None.

**(e) Tests**
- `staging/src/k8s.io/apiserver/pkg/admission/conversion_test.go`: new `TestObjectAccessors`. It checks that
  `GetObject()` and `GetOldObject()` both return the v1-converted pods, with TypeMeta set.

**(f) Gate-off behaviour changes.** Yes, ungated, in principle. Any caller that calls `GetOldObject()` on a
`*VersionedAttributes` (directly, or through the `admission.Attributes` interface) now gets the versioned old object
instead of the internal one. In-tree, `NewVersionedAttributes`/`ConvertVersionedAttributes` read
`attr.Attributes.GetOldObject()` explicitly (HEAD `conversion.go:97`, `:179`), so they are unaffected. A grep of
non-test `GetOldObject()` callers under `staging/src/k8s.io/apiserver/pkg/admission` found only the object-selector
matcher (`plugin/webhook/predicates/object/matcher.go:60`) and resourcequota. Both receive plain `admission.Attributes`
in the paths I checked. I did not exhaustively prove that no in-tree caller passes a `*VersionedAttributes` there.

---

## PR #137633: [3/n] Webhook authorizer supports conditions, plus API types (merge `a5081d96514`)

**Summary.** This PR adds the conditional-authorization **wire API** and the **webhook authorizer** implementation:
- New fields: SAR/SSAR/LSAR `spec.authorizationOptions` and `status.conditionalDecision`, with the `ConditionsAwareDecision`
  tree types in `authorization.k8s.io/v1`.
- A new `authorization.k8s.io/v1alpha1` group version with the `AuthorizationConditionsReview` (ACR) webhook type.
  It is registered in the scheme and the clientset, but **not served** by kube-apiserver: there is no REST storage, and
  `pkg/registry/authorization/rest/storage_authorization.go` is untouched.
- An `AuthorizationConfiguration` v1 `webhook.conditionsReview` stanza, with validation, plus reload wiring.
- Encode/decode between the wire types and `authorizer.ConditionsAwareDecision`.
- Hand-written and declarative validation, and a v1beta1 down-conversion that fails closed.
- Webhook `ConditionsAwareAuthorize`, which sends `authorizationOptions` and decodes `conditionalDecision`, and
  `EvaluateConditions`, which sends an ACR, validates the response, checks the UID and checks that the result is one of
  `PossibleDecisions`.
- The `ConditionalAuthorization` feature gate itself.

Stat: 117 files, +16260/−287. About 70% is generated (proto, deepcopy, conversion, validations, openapi, clientset)
or testdata.

**(a) Packages touched (by area)**
- API types, k8s.io/api: `k8s.io/api/authorization/v1` (types, proto, swagger, new `util.go`, `go.mod` promotes go-cmp
  to a direct dependency) and `k8s.io/api/authorization/v1alpha1` (new: doc, register, types, proto, swagger, generated
  files). `staging/src/k8s.io/api/roundtrip_test.go`.
- Internal API: `pkg/apis/authorization` (types, register, install, fuzzer, validation, v1 conversion, v1beta1
  conversion, new v1alpha1 package), `pkg/apis/admission/v1` (new exported conversion wrappers).
- API test infrastructure: `pkg/api/testing` (fuzzer, validation-equivalence omitted paths, conversion exemptions).
- Generic apiserver: `k8s.io/apiserver/pkg/apis/apiserver` (+`/v1`, `/v1alpha1`, `/v1beta1`, `/validation`),
  `k8s.io/apiserver/pkg/apis/authorization/v1` (new: `encoding.go`), `k8s.io/apiserver/pkg/apis/authorization/validation`,
  `k8s.io/apiserver/pkg/authorization/{authorizerfactory,cel}`, `k8s.io/apiserver/pkg/features`,
  `k8s.io/apiserver/pkg/server/options`, `k8s.io/apiserver/pkg/util/webhook`, `k8s.io/apiserver/plugin/pkg/authorizer/webhook`.
- client-go: `kubernetes/{clientset.go,fake,scheme}`, new `typed/authorization/v1alpha1` (+fake).
- kube-apiserver: `pkg/features`, `pkg/kubeapiserver/authorizer/reload.go`,
  `pkg/registry/authorization/{subjectaccessreview,selfsubjectaccessreview,localsubjectaccessreview}`.
- Other: `hack/lib/init.sh` (adds `authorization.k8s.io/v1alpha1`), `test/compatibility_lifecycle/reference/*`,
  `test/declarative_validation/authorization/*`.

**(b) New / changed exported symbols**

k8s.io/api/authorization/v1:
- `types.go`: new types `AuthorizationOptions` (HEAD `:412`), `Condition` (`:434`), `ConditionsMap` (`:476`),
  `ConditionsAwareDecisionType` (`:514`, `+k8s:enum`), its consts (`:516`), `ConditionsAwareDecision` (`:541`),
  `NamedConditionsAwareDecision` (`:597`), `UnconditionalDecision` (`:613`). Changed: `SubjectAccessReviewSpec`,
  `SelfSubjectAccessReviewSpec`, `SubjectAccessReviewStatus` (new fields, see (c); the allowed/denied docs were
  reworded).
- `util.go` (new): `SupportsConditionalAuthorization(*AuthorizationOptions) bool` (HEAD `:42`; nil→false; superset of
  {Allow,Deny,NoOpinion,ConditionsMap,Union}), `SupportsUnconditionalAuthorization(*AuthorizationOptions) bool`
  (`:57`; nil→true), `GetHandledDecisionTypes(*AuthorizationOptions) sets.Set[ConditionsAwareDecisionType]` (`:67`;
  nil→{Allow,Deny,NoOpinion}), `ConditionalAuthorizationDecisionTypes()` (`:76`), `ConditionalAuthorizationDecisionTypesList()`
  (`:82`), `UnconditionalAuthorizationDecisionTypes()` (`:88`), `UnconditionalAuthorizationDecisionTypesList()` (`:94`).
  Nit: the doc comment of `UnconditionalAuthorizationDecisionTypes` says "to handle conditional authorization".
- Generated: new SwaggerDoc methods, deepcopy, proto, `Validate_*` for the new types.

k8s.io/api/authorization/v1alpha1 (new package):
- `register.go`: `GroupName`, `SchemeGroupVersion` (v1alpha1), `Resource`, `SchemeBuilder`, `AddToScheme`. Known
  types: `AuthorizationConditionsReview` only.
- `types.go`: `AuthorizationConditionsReview` (HEAD `:33`; `+genclient:nonNamespaced`, `onlyVerbs=create`,
  `prerelease-lifecycle-gen:introduced=1.38`), `AuthorizationConditionsRequest` (`:53`),
  `AuthorizationConditionsResponse` (`:67`).

k8s.io/kubernetes/pkg/apis/authorization (internal):
- `types.go`: internal mirrors of all the types above, plus `AuthorizationConditionsReview`, `AuthorizationConditionsRequest`
  (`AdmissionRequest *admission.AdmissionRequest`, internal admission type), `AuthorizationConditionsResponse`. New
  fields on the internal Spec/SelfSpec/Status. Registered in `register.go`.
- `install/install.go`: installs v1alpha1. Version priority is now v1, v1beta1, v1alpha1.
- `v1/conversion.go` (new): `Convert_v1_ConditionsAwareDecision_To_authorization_ConditionsAwareDecision`,
  `Convert_authorization_ConditionsAwareDecision_To_v1_ConditionsAwareDecision`. These are exported wrappers so that
  v1alpha1 can embed the type (TODO references issue 142345).
- `v1alpha1/` (new): `GroupName`, `SchemeGroupVersion`, `Resource`, `AddToScheme`, defaults registration.
- `v1beta1/conversion.go` (new):
  - `Convert_authorization_SelfSubjectAccessReviewSpec_To_v1beta1_SelfSubjectAccessReviewSpec` and
    `Convert_authorization_SubjectAccessReviewSpec_To_v1beta1_SubjectAccessReviewSpec` drop `AuthorizationOptions`
    (lossy).
  - `Convert_authorization_SubjectAccessReviewStatus_To_v1beta1_SubjectAccessReviewStatus` folds `ConditionalDecision`
    into `allowed=false`, with `denied = FailureDecision()==Deny`. Unrecognized types give denied. It also copies the
    decoded `Reason()`/`Error()`.
- `validation/validation.go`: new `OmittedFieldPaths() map[schema.GroupVersionKind][]string` (v1beta1 SAR/SSAR/LSAR
  omit `spec.authorizationOptions` and `status.conditionalDecision`). New
  `ValidateAuthorizationConditionsReviewCreate(ctx, scheme, *authorizationapi.AuthorizationConditionsReview) field.ErrorList`.
  The `Validate*SubjectAccessReviewCreate` functions now pass `apiservervalidation.DeclarativeValidationConfig()`.
- `fuzzer/fuzzer.go`: `Funcs` now nils `AuthorizationOptions` and `ConditionalDecision`, because they do not survive
  the v1beta1 round trip.

k8s.io/kubernetes/pkg/apis/admission/v1:
- `conversion.go` (new): `Convert_v1_AdmissionRequest_To_admission_AdmissionRequest`,
  `Convert_admission_AdmissionRequest_To_v1_AdmissionRequest` (exported wrappers).

k8s.io/kubernetes/pkg/api/testing:
- `validation.go`: new `WithOmittedFieldPaths(map[schema.GroupVersionKind][]string) ValidationTestConfig` and the
  `validationOption.OmittedFieldPaths` field. `VerifyVersionedValidationEquivalence` now drops errors at omitted paths
  per GVK.

k8s.io/apiserver/pkg/apis/apiserver (AuthorizationConfiguration):
- `types.go` (internal) and `v1/types.go`: new field `WebhookConfiguration.ConditionsReview *ConditionsReviewConfiguration`
  and new type `ConditionsReviewConfiguration{Version string; KubeConfigContextName string}`. HEAD v1 `types.go:530`,
  `:535`; internal `types.go:411`, `:414`.
- `v1alpha1/conversion.go`, `v1beta1/conversion.go`: new
  `Convert_apiserver_WebhookConfiguration_To_v1alpha1_WebhookConfiguration` and `..._To_v1beta1_...`. Both deliberately
  drop `ConditionsReview`, so the field exists **only in apiserver.config.k8s.io/v1**.
- `validation/validation.go`: new
  `ValidateConditionsReviewConfiguration(fldPath, parentFldPath *field.Path, crc *api.ConditionsReviewConfiguration, connectionType string) field.ErrorList`.
  `ValidateWebhookConfiguration` now forbids `conditionsReview` unless `subjectAccessReviewVersion=v1` and calls it.

k8s.io/apiserver/pkg/apis/authorization/v1 (new, `encoding.go`):
- `FromAuthorizerConditionsAwareDecision(authorizer.ConditionsAwareDecision) authorizationv1.ConditionsAwareDecision`
  (HEAD `:31`). Unrecognized variants encode as Deny with an aggregated error.
- `ToAuthorizerConditionsAwareDecision(authorizationv1.ConditionsAwareDecision, failClosed func(error) authorizer.ConditionsAwareDecision) authorizer.ConditionsAwareDecision`
  (`:126`). Unknown `type` → `failClosed`. A ConditionsMap with nil map → `ConditionsAwareDecisionConditionsMap(nil,nil,nil)`,
  which produces that constructor's error decision.
- `UnconditionalEvaluationError(*authorizationv1.UnconditionalDecision) error` (`:110`) and
  `UnconditionalReason(*authorizationv1.UnconditionalDecision) string` (`:118`).

k8s.io/apiserver/pkg/apis/authorization/validation:
- New: `ValidateSubjectAccessReviewStatus(status authorizationv1.SubjectAccessReviewStatus, clientIsConditionsAware bool, fldPath) field.ErrorList`
  (HEAD `:90`); `ValidateAuthorizationConditionsReview(*v1alpha1.AuthorizationConditionsReview)` (`:244`);
  `ValidateAuthorizationConditionsRequest` (`:263`); `ValidateAuthorizationConditionsResponse` (`:287`);
  `DeclarativeValidationConfig() rest.DeclarativeValidationConfig` (`:310`; passes the gate as DV option
  `"ConditionalAuthorization"`); `CombinedValidateSubjectAccessReviewCreate(ctx, *v1.SubjectAccessReview)` (`:319`);
  `CombinedValidateAuthorizationConditionsReviewCreate(ctx, *v1alpha1.AuthorizationConditionsReview)` (`:337`). Both
  `Combined*` functions recover panics into `InternalError`.
- Changed: `ValidateSubjectAccessReviewSpec` and `ValidateSelfSubjectAccessReviewSpec` call `validateAuthorizationOptions`
  (which requires a superset of {Allow,Deny,NoOpinion} when 1–32 entries are present).
  `ValidateSubjectAccessReview`, `ValidateSelfSubjectAccessReview` and `ValidateLocalSubjectAccessReview` now **also
  validate status**: allowed and denied are mutually exclusive; `conditionalDecision` is forbidden unless the client is
  conditions-aware; `conditionalDecision.type` may not be Allow/Deny/NoOpinion; and allowed, denied, reason and
  evaluationError must be empty when `conditionalDecision` is set.
- Doc nits: `ValidateSubjectAccessReviewStatus`'s comment says "validates a SubjectAccessReviewSpec", and there is a
  stray duplicate doc line "GetDeclarativeValidationOptions returns…" above `DeclarativeValidationConfig`.

k8s.io/apiserver/pkg/authorization/authorizerfactory/delegating.go:
- New field `DelegatingAuthorizerConfig.AuthorizationConditionsReviewClient authorizationv1alpha1client.AuthorizationV1alpha1Interface`,
  passed to `webhook.NewFromInterface`.

k8s.io/apiserver/pkg/authorization/cel/compile.go:
- The CEL `request` type (`kubernetes.SubjectAccessReviewSpec`) gains `authorizationOptions` (type
  `kubernetes.AuthorizationOptions{handledDecisionTypes: list(string), required}`) **only when the gate is on**.
  `convertObjectToUnstructured` populates it, also gate-on only. The new helper `buildAuthorizationOptionsType` is
  unexported.

k8s.io/apiserver/pkg/features/kube_features.go:
- New const `ConditionalAuthorization featuregate.Feature = "ConditionalAuthorization"`, `{1.38, Default false, Alpha}`.

k8s.io/apiserver/pkg/server/options/authorization.go:
- `DelegatingAuthorizationOptions.toAuthorizer` always sets `AuthorizationConditionsReviewClient: client.AuthorizationV1alpha1()`.

k8s.io/apiserver/pkg/util/webhook/webhook.go:
- New `LoadKubeconfigWithContext(kubeConfigFile, contextName string, customDial utilnet.DialFunc) (*rest.Config, error)`.
  `LoadKubeconfig` now delegates to it with `""`.

k8s.io/apiserver/plugin/pkg/authorizer/webhook/webhook.go:
- `NewFromInterface(...)`: new trailing parameter `authorizationV1Alpha1Interface authorizationv1alpha1client.AuthorizationV1alpha1Interface`.
  This is an exported signature change.
- `New(sarConfig, sarVersion, ..., conditionsReviewConfig *rest.Config, conditionsReviewVersion string)`: two new
  trailing parameters, and the first two were renamed. This is an exported signature change. Later changed again by
  `60a11890371`.
- `(*WebhookAuthorizer).ConditionsAwareAuthorize` is now a real implementation (previously
  `ConditionsAwareDecisionFromParts(w.Authorize(...))`). It sets `spec.authorizationOptions.handledDecisionTypes` =
  `ConditionalAuthorizationDecisionTypesList()` only when an ACR client is configured. It validates the response with
  `CombinedValidateSubjectAccessReviewCreate` and fails closed via `conditionsAwareFailureDecision` (NoOpinion when
  `failurePolicy=NoOpinion`, otherwise Deny, reason "failed closed").
- `(*WebhookAuthorizer).EvaluateConditions` is now real (previously returned `ErrorConditionEvaluationNotSupported`):
  - It rejects unconditional input and nil data.
  - It requires apiVersion/kind on non-nil (and non-typed-nil) object/oldObject.
  - It builds an `admissionv1.AdmissionRequest` with a fresh UID, sends an ACR with retry backoff, and requires
    `response != nil`.
  - It runs combined validation, then checks that the UID matches and that the returned type is in
    `PossibleDecisions()`. Every failure returns `FailureDecision()` with reason "failed closed".
- `(*WebhookAuthorizer).Authorize` (legacy path) now also handles an unrequested `status.conditionalDecision`. Order:
  both allowed and denied → Deny+error; denied → Deny; `conditionalDecision != nil` → `FailureDecision()` + error
  "returned unrequested conditional decision"; allowed → Allow; otherwise NoOpinion.
- Caching (`sendSARWebhook`): `authorizedTTL` now also applies when `handlesConditional && conditionalDecision != nil`.
  The cache key is the JSON of `r.Spec`, which now includes `authorizationOptions`.
- `newWithBackoff` drops the ACR reviewer unless the gate is on.
- New unexported: `authorizationConditionsReviewer` interface, `authorizationConditionsReviewV1Alpha1Client`,
  `authorizationConditionsClientGW`, `authorizationConditionsReviewInterfaceFromConfig` (supports only version
  `v1alpha1`), `convertToAuthenticationExtra`, `conditionsAwareFailureDecision`, `sendSARWebhook`.

client-go (generated):
- `Interface.AuthorizationV1alpha1()`, `Clientset.AuthorizationV1alpha1()`, `typed/authorization/v1alpha1`:
  `AuthorizationV1alpha1Interface`, `AuthorizationConditionsReviewsGetter`, `AuthorizationConditionsReviewInterface`
  (create only), and the fakes.

kube-apiserver:
- `pkg/features/kube_features.go`: registers `genericfeatures.ConditionalAuthorization` in the versioned gates and in
  the dependency map (no dependencies).
- `pkg/kubeapiserver/authorizer/reload.go`: when the gate is on and `webhook.conditionsReview` is set, it loads the
  kubeconfig with `kubeConfigContextName`, copies the webhook timeout, and passes the ACR config and version to
  `webhook.New`.
- `pkg/registry/authorization/{subject,selfsubject,localsubject}accessreview/rest.go` `Create`: now **clears the posted
  `Status`** before validation (to keep 1.37 leniency) and **nils `Spec.AuthorizationOptions` when the gate is off**.

**(c) API fields (path, Go type, enum values)**

`authorization.k8s.io/v1` (`staging/src/k8s.io/api/authorization/v1/types.go`), mirrored in `pkg/apis/authorization/types.go`:

| Field path | Go type | JSON / proto | Gate tags |
|---|---|---|---|
| `SubjectAccessReview.spec.authorizationOptions` (also LSAR) | `*AuthorizationOptions` | `authorizationOptions,omitempty` / proto 7 | `+featureGate`, `ifEnabled=optional`, `ifDisabled=forbidden` |
| `SelfSubjectAccessReview.spec.authorizationOptions` | `*AuthorizationOptions` | proto 3 | same |
| `SubjectAccessReview.status.conditionalDecision` (all three SAR kinds) | `*ConditionsAwareDecision` | `conditionalDecision,omitempty` / proto 5 | same |
| `AuthorizationOptions.handledDecisionTypes` | `[]ConditionsAwareDecisionType` | proto 1 | `+k8s:required`, `listType=set`, `maxItems=32`, `eachVal=opaqueType` |
| `Condition.id` | `string` | 1 | required, `format=k8s-prefixed-label-key` |
| `Condition.condition` | `string` | 2 | optional, `maxBytes=10240` |
| `Condition.type` | `string` | 3 | optional, `format=k8s-prefixed-label-key`; doc names `authorizer.kubernetes.io/cel` |
| `Condition.description` | `string` | 4 | optional, `maxBytes=1024` |
| `ConditionsMap.{denyConditions,noOpinionConditions,allowConditions}` | `[]Condition` | 1/2/3 | `listType=map`, `listMapKey=id`, `maxItems=128` each |
| `ConditionsAwareDecision.type` | `ConditionsAwareDecisionType` | 1 | `unionDiscriminator`, required |
| `ConditionsAwareDecision.{deny,noOpinion,allow}` | `*UnconditionalDecision` | 2/3/4 | `unionMember` |
| `ConditionsAwareDecision.conditionsMap` | `*ConditionsMap` | 5 | `unionMember` |
| `ConditionsAwareDecision.union` | `[]NamedConditionsAwareDecision` | 6 | `unionMember`, `listType=map`, `listMapKey=authorizerName` |
| `NamedConditionsAwareDecision.authorizerName` | `string` | 1 | required, `format=k8s-long-name` |
| `NamedConditionsAwareDecision.decision` | `ConditionsAwareDecision` | 2 | required |
| `UnconditionalDecision.{reason,evaluationError}` | `string` | 1/2 | optional |

`ConditionsAwareDecisionType` (string enum, `+k8s:enum`) has exactly these values: `"Deny"`, `"Allow"`, `"NoOpinion"`,
`"ConditionsMap"`, `"Union"`. The consts are `ConditionsAwareDecisionTypeDeny`, `…Allow`, `…NoOpinion`,
`…ConditionsMap` and `…Union`.

`authorization.k8s.io/v1alpha1` (`staging/src/k8s.io/api/authorization/v1alpha1/types.go`):

| Field path | Go type | Notes |
|---|---|---|
| `AuthorizationConditionsReview.metadata` | `metav1.ObjectMeta` | must be empty (hand-written validation) |
| `AuthorizationConditionsReview.request` | `*AuthorizationConditionsRequest` | optional |
| `AuthorizationConditionsReview.response` | `*AuthorizationConditionsResponse` | optional |
| `request.decision` | `authorizationv1.ConditionsAwareDecision` | must be ConditionsMap or Union |
| `request.admissionRequest` | `*admissionv1.AdmissionRequest` | `+k8s:required`, but JSON is `omitempty` |
| `response.uid` | `types.UID` | required; must echo `request.admissionRequest.uid` |
| `response.decision` | `authorizationv1.ConditionsAwareDecision` | must be Allow, Deny or NoOpinion |

`apiserver.config.k8s.io/v1` AuthorizationConfiguration (`staging/src/k8s.io/apiserver/pkg/apis/apiserver/v1/types.go`):

| Field path | Go type | Validation |
|---|---|---|
| `authorizers[].webhook.conditionsReview` | `*ConditionsReviewConfiguration` | gate must be on; requires `subjectAccessReviewVersion: v1` |
| `…conditionsReview.version` | `string` | required; only `"v1alpha1"` |
| `…conditionsReview.kubeConfigContextName` | `string` | optional; only allowed when `connectionInfo.type=KubeConfigFile` |

The field is not present in `apiserver.config.k8s.io/v1alpha1` or `v1beta1`: conversion drops it.

**(d) Feature-gate checks added (post-image `path:line`)**
- `pkg/features/kube_features.go:2232` (gate spec), `:2795` (dependencies).
- `staging/src/k8s.io/apiserver/pkg/features/kube_features.go:90` (const), `:366` (spec).
- `pkg/kubeapiserver/authorizer/reload.go:185` loads the ACR kubeconfig only when the gate is on.
- `pkg/registry/authorization/subjectaccessreview/rest.go:76`, `selfsubjectaccessreview/rest.go:77` and
  `localsubjectaccessreview/rest.go:78` nil `spec.authorizationOptions` when the gate is off.
- `staging/src/k8s.io/apiserver/pkg/apis/apiserver/validation/validation.go:759` forbids `conditionsReview` when the
  gate is off.
- `staging/src/k8s.io/apiserver/pkg/apis/authorization/validation/validation.go:313` passes the gate to declarative
  validation (`ifEnabled`/`ifDisabled` on the three new SAR fields).
- `staging/src/k8s.io/apiserver/pkg/authorization/cel/compile.go:218` (CEL type gains `authorizationOptions`) and `:344`
  (value populated).
- `staging/src/k8s.io/apiserver/plugin/pkg/authorizer/webhook/webhook.go:160` keeps the ACR reviewer only when the
  gate is on.
- Declarative tags, read by the validation generator: `staging/src/k8s.io/api/authorization/v1/types.go:237-238`,
  `:270-271`, `:305-306`.

**(e) Tests added / changed**
- `staging/src/k8s.io/api/authorization/v1/util_test.go` (new): the `Supports*`/`GetHandledDecisionTypes` truth table;
  the accessors return fresh copies.
- `staging/src/k8s.io/api/roundtrip_test.go`: adds v1alpha1 to the round-trip groups.
- `staging/src/k8s.io/apiserver/pkg/apis/authorization/v1/encoding_test.go` (new): `From`/`To` for every variant,
  `Unconditional{Reason,EvaluationError}` on nil, encode→decode round trip.
- `staging/src/k8s.io/apiserver/pkg/apis/authorization/validation/validation_test.go`: new
  `TestValidateAuthorizationConditionsReview`, `TestValidateSARStatus`, `TestCombinedValidateSubjectAccessReviewCreate`
  and `TestCombinedValidateAuthorizationConditionsReviewCreate` (the last two include the panic guard).
- `staging/src/k8s.io/apiserver/pkg/apis/apiserver/validation/validation_test.go`: ConditionsReview cases in
  `TestValidateAuthorizationConfiguration` (gate on/off, InClusterConfig, SAR v1 only), plus new
  `TestValidateConditionsReviewConfiguration`.
- `staging/src/k8s.io/apiserver/pkg/authorization/cel/compile_test.go`: `request.authorizationOptions` compiles when the
  gate is on and is an undefined field when off. The type-reflection test covers the new type.
- `staging/src/k8s.io/apiserver/plugin/pkg/authorizer/webhook/webhook_conditional_test.go` (new, 1400 lines):
  - `TestConditionsAwareAuthorize`: all decision types and error cases.
  - `TestAuthorize_FoldDown`: the legacy path folds unrequested conditions.
  - `TestEvaluateConditions`: table of reviewer errors, response validation, UID and request content.
  - `TestConditionsAwareAuthorize_EndToEnd` and `TestEvaluateConditions_EndToEnd`: httptest server.
  - `TestConditionsAwareAuthorize_V1beta1Downgrade`: a v1beta1 webhook never yields conditions.
  - `TestConditionalResponseCaching`: TTL choice.
- `.../webhook/round_trip_test.go`: excludes the new fields from the v1↔v1beta1 round trip. `webhook_v1_test.go` and
  `webhook_v1beta1_test.go` get signature updates only.
- `pkg/apis/authorization/v1beta1/conversion_test.go` (new): the fold-down truth table (never `allowed=true`) and no
  input mutation.
- `pkg/registry/authorization/{subject,selfsubject,localsubject}accessreview/rest_test.go`: new
  `TestCreateIgnoresPostedStatus` (gate off: a bogus posted status is ignored and `authorizationOptions` is cleared).
  The LSAR and SSAR test files are new.
- `pkg/api/testing/validation_test.go`: `TestOmitErrorsForPaths`, plus omitted-paths wiring in the fuzz equivalence
  test. `pkg/api/testing/conversion_test.go`: the SAR kinds and ACR are exempted from memory-identical conversion.
- `test/declarative_validation/authorization/{subjectaccessreview,selfsubjectaccessreview,localsubjectaccessreview}/declarative_validation_test.go`:
  gate on/off, `handledDecisionTypes` rules, `conditionalDecision` shape and limits. `.../authorizationconditionsreview/`
  is new and covers ACR request/response rules. The generated `zz_generated.validations.*_test.go` files are also new.

**(f) Gate-off behaviour changes visible to callers**
1. Webhook `Authorize` is ungated. A webhook response with `status.conditionalDecision != nil` and `denied=false` used
   to be decided by `allowed` (Allow or NoOpinion). Now it returns `FailureDecision()` of the decoded decision plus an
   error. In 1.37 the field did not exist, so it was dropped on decode; now it decodes regardless of the gate. This is
   fail-closed hardening, but it is a visible change for any webhook that sets the field. Covered by
   `TestAuthorize_FoldDown`.
2. Exported Go API signature changes: `webhook.NewFromInterface` and `webhook.New` gained parameters, and
   `DelegatingAuthorizerConfig` gained a field. This is compile-level only.
3. `k8s.io/apiserver/pkg/apis/authorization/validation.Validate{,Self,Local}SubjectAccessReview` now also validate
   `status`, so `allowed && denied` is an error. These functions were introduced one PR earlier (#140714), so this is
   not a 1.37 regression for library users. kube-apiserver's REST handlers clear the posted status first, so API
   clients see no change.
4. SAR REST handlers: the posted status is now cleared before validation. The status in the response was already the
   authorizer's answer, so this is not observable.
5. Not a change, for completeness. With the gate off, `ConditionsAwareAuthorize` is not reached in kube-apiserver. The
   HEAD callers are `filters/authorization.go:164` (gated filter), the SAR REST handlers (gated through
   `ResolveAuthorizationOptions`), and the union/metrics/reload wrappers, which are only reached from those. So the
   webhook's new response validation on that path does not run with the gate off.

---

## PR #141959: [4/n] Conditional authz in kube-apiserver: filter, enforcer, SAR, integration tests (merge `bccf5c36113`)

**Summary.** This PR wires conditional authorization end to end in the generic apiserver and kube-apiserver:
- A new `WithConditionsAwareAuthorization` filter. Conditionally allowed requests (`PossibleDecisions` contains Allow)
  proceed with the decision and the authorizer stored in the request context.
- A new `AuthorizationConditionsEnforcer` validating admission plugin, ordered after VAP and before
  ValidatingAdmissionWebhook. It reads the context, calls `EvaluateConditions` on `VersionedAttributes`, and guards the
  return value against `PossibleDecisions`.
- A kube-apiserver request classifier: resource requests with verbs create, update, patch, delete or deletecollection
  that are not excluded from admission.
- SAR/SSAR/LSAR return `status.conditionalDecision` to clients that opt in.
- A `conditional` metrics label and audit annotations.
- The conditions-aware filter is used only when all three hold: gate on, classifier set, enforcer plugin enabled.
  Otherwise the legacy filter runs (with the gate on it attaches an unconditional Allow decision to the context).

Stat: 35 files, +5598/−275 (about 3070 lines are integration tests).

**(a) Packages touched (by area)**
- Generic apiserver: `k8s.io/apiserver/pkg/admission/plugin/authorizer/conditionsenforcer` (new),
  `k8s.io/apiserver/pkg/endpoints/filters` (authorization, metrics), `k8s.io/apiserver/pkg/endpoints/request` (context),
  `k8s.io/apiserver/pkg/server` (config, plugins), `k8s.io/apiserver/pkg/server/options` (admission),
  `k8s.io/apiserver/pkg/authorization/authorizer` (doc comments only).
- kube-apiserver: `pkg/controlplane/apiserver` (config classifier, the generic sample's default-off plugins),
  `pkg/kubeapiserver/options/plugins.go`, `pkg/registry/authorization/{subjectaccessreview,selfsubjectaccessreview,localsubjectaccessreview,rest,util}`.
- Tests: `test/integration/apiserver/conditionalauthorization` (new), `staging/src/k8s.io/apiextensions-apiserver/test/integration/conversion/webhook.go`
  (test helper: closes the response body).
- Docs: `hack/tools/instrumentation/documentation/documentation-list.yaml` (metric help text).

**(b) New / changed exported symbols**
- `staging/src/k8s.io/apiserver/pkg/admission/plugin/authorizer/conditionsenforcer/conditionsenforcer.go` (new):
  - `const PluginName = "AuthorizationConditionsEnforcer"` (HEAD `:38`).
  - `func Register(*admission.Plugins)` (`:44`).
  - `func NewConditionalAuthorizationEnforcer() *conditionsEnforcer` (`:55`). This exported constructor returns an
    unexported type.
  - Methods `InspectFeatureGates`, `ValidateInitialization` (errors if `InspectFeatureGates` was not called), `Handles`
    (true only when the gate is on) and `Validate` (`:63`–`:78`).
  - Unexported `evaluateWithReturnGuard` (`:145`).
  - `Validate`:
    - missing context decision → error;
    - Deny, NoOpinion, or Allow not possible → `InternalError`;
    - Allow → nil;
    - ConditionsMap or Union → `NewVersionedAttributes(a, a.GetKind(), o)`, then `EvaluateConditions`, then the guard.
      The result is Allow, `InternalError` on error, or `ForbiddenStatusError`.
- `staging/src/k8s.io/apiserver/pkg/endpoints/filters/authorization.go`:
  - New type `ConditionalAuthorizationRequestClassifier func(attrs authorizer.Attributes) bool` (HEAD `:55`).
  - New `WithConditionsAwareAuthorization(handler, auth authorizer.Authorizer, s runtime.NegotiatedSerializer, classifier) (http.Handler, error)`
    (`:135`). It errors unless the gate is on and the classifier is non-nil.
  - Constants previously unexported are now exported: `DecisionAnnotationKey`, `ReasonAnnotationKey`, `DecisionAllow`,
    `DecisionForbid`, `ReasonError`. New unexported `isConditionalAuthorizationKey = "authorization.k8s.io/is-conditional-decision"`.
  - `WithAuthorization` keeps its signature. With the gate on, after Allow it stores
    `ConditionsAwareDecisionAllow(reason, err)` with `AuthorizerFunc(a.Authorize)` in the context.
  - The unexported `recordAuthorizationMetricsFunc` signature changed to take a result label.
- `staging/src/k8s.io/apiserver/pkg/endpoints/filters/metrics.go`: new label value `conditional`. New unexported
  `authorizationMetricsLabelForAuthorize` and `authorizationMetricsLabelForAuthorizeConditionsAware`; {Deny,NoOpinion}
  maps to `denied`.
- `staging/src/k8s.io/apiserver/pkg/endpoints/request/context.go`: new
  `WithConditionallyAuthorizedDecision(parent, authorizer.Authorizer, authorizer.ConditionsAwareDecision) (context.Context, error)`
  (HEAD `:92`; errors if a decision is already set) and
  `ConditionallyAuthorizedDecisionFrom(ctx) (authorizer.Authorizer, authorizer.ConditionsAwareDecision, bool)` (`:103`).
  The doc comment says "ConditionallyAuthorizedDecisionsFrom" (nit).
- `staging/src/k8s.io/apiserver/pkg/server/config.go`: new fields
  `AuthorizationInfo.ConditionalAuthorizationRequestClassifier genericapifilters.ConditionalAuthorizationRequestClassifier`
  and `AuthorizationInfo.ConditionsEnforcerPluginEnabled bool` (HEAD `:405`, `:408`). `DefaultBuildHandlerChain`
  chooses the filter and logs a warning when the gate is on but the plugin is off.
- `staging/src/k8s.io/apiserver/pkg/server/options/admission.go`: `RecommendedPluginOrder` gains
  `AuthorizationConditionsEnforcer` between VAP and ValidatingAdmissionWebhook. `ApplyTo` sets
  `c.Authorization.ConditionsEnforcerPluginEnabled`.
- `staging/src/k8s.io/apiserver/pkg/server/plugins.go`: `RegisterAllAdmissionPlugins` registers the enforcer.
- `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/interfaces.go`: doc only. `ConditionsData.GetObject/GetOldObject`
  "should be versioned in the external version corresponding to GetKind()".
- `pkg/controlplane/apiserver/config.go`: unexported `conditionalRequestClassifier` (HEAD `:299`), set at `:249` when
  the gate is on. It returns true only for resource requests, not in `exclusion.Excluded()`, with verb in {create,
  update, patch, delete, deletecollection}. A TODO notes that aggregated APIs and connect are not handled.
- `pkg/kubeapiserver/options/plugins.go`: `AllOrderedPlugins` gains the enforcer after VAP. It is in
  `DefaultOffAdmissionPlugins`, so it is **default-off in kube-apiserver**.
- `pkg/controlplane/apiserver/samples/generic/server/admission.go`: the enforcer is default-off in the sample generic
  server.
- `pkg/registry/authorization/{subject,selfsubject,localsubject}accessreview/rest.go`: `REST.authorizer` and the
  `NewREST(...)` parameter change type from `authorizer.UnconditionalAuthorizer` to `authorizer.Authorizer`. This is an
  exported signature change. `Create` branches on `ResolveAuthorizationOptions`: conditions-aware calls
  `ConditionsAwareAuthorize` then `ConditionsAwareDecisionToSARStatus`; unconditional calls `Authorize` (as before);
  anything else returns 400 BadRequest. Also fixes the "LocaLocalSubjectAccessReview" typo.
- `pkg/registry/authorization/rest/storage_authorization.go`: `RESTStorageProvider.Authorizer` changes type to
  `authorizer.Authorizer`.
- `pkg/registry/authorization/util/helpers.go`: new
  `ResolveAuthorizationOptions(*authorizationapi.AuthorizationOptions) (versionedAO *authorizationv1.AuthorizationOptions, supportsConditional, supportsUnconditional bool, err error)`
  (HEAD `:251`; gate off or nil → `(nil, false, true, nil)`) and
  `ConditionsAwareDecisionToSARStatus(ctx, authorizer.AttributesRecord, authorizer.ConditionsAwareDecision) authorizationapi.SubjectAccessReviewStatus`
  (`:265`). Unconditional decisions go in top-level fields; others go in `ConditionalDecision`. If conversion fails it
  folds to `FailureDecision`.

**(c) API fields.** No new fields. Behavioural API change: SAR/SSAR/LSAR now **populate** `status.conditionalDecision`
when the gate is on and `spec.authorizationOptions.handledDecisionTypes` ⊇ {Allow, Deny, NoOpinion, ConditionsMap,
Union}. A set that is not a superset of {Allow, Deny, NoOpinion} gets 400. New metric label value:
`authorization_attempts_total{result="conditional"}` (also used for the latency metric). New audit annotation:
`authorization.k8s.io/is-conditional-decision: "true"`.

**(d) Feature-gate checks added (post-image `path:line`)**
- `pkg/controlplane/apiserver/config.go:247` sets the classifier only when the gate is on.
- `pkg/registry/authorization/util/helpers.go:252` (`ResolveAuthorizationOptions`). The SAR handlers depend on it at
  `subjectaccessreview/rest.go:94`, `selfsubjectaccessreview/rest.go:105` and `localsubjectaccessreview/rest.go:103`.
- `staging/src/k8s.io/apiserver/pkg/admission/plugin/authorizer/conditionsenforcer/conditionsenforcer.go:64` (reads the
  gate in `InspectFeatureGates`), `:75` (`Handles`) and `:80` (`Validate` safety check).
- `staging/src/k8s.io/apiserver/pkg/endpoints/filters/authorization.go:101` (legacy filter attaches the Allow decision
  when the gate is on) and `:136` (precondition of `WithConditionsAwareAuthorization`).
- `staging/src/k8s.io/apiserver/pkg/server/config.go:1077` (filter selection) and `:1089` (warning).
- `pkg/kubeapiserver/options/plugins.go:193` is a comment only (default-off note).

**(e) Tests added / changed**
- `staging/src/k8s.io/apiserver/pkg/admission/plugin/authorizer/conditionsenforcer/conditionsenforcer_test.go` (new):
  `TestConditionsEnforcerInitialization` (gate on/off, `InspectFeatureGates` not called) and
  `TestConditionsEnforcerEndToEnd` (filter, then enforcer, over decision shapes; the return guard; audit annotations).
- `.../conditionsenforcer/context_invariant_test.go` (new): `TestConditionsEnforcerContextInvariant`. With the gate on,
  every path through the legacy and new filters leaves a decision in the context for the enforcer.
- `staging/src/k8s.io/apiserver/pkg/endpoints/filters/authorization_test.go`: `TestWithAuthorization` rewritten into a
  table over both filters. It covers allow/deny/no-opinion/error and conditional allow with the classifier true, false
  or nil, plus deny-only conditional.
- `.../filters/metrics_test.go`: label mapping for both filters, including `conditional`.
- `staging/src/k8s.io/apiserver/pkg/endpoints/request/context_test.go`: `TestConditionallyAuthorizedDecisionContext`
  (set/get, double-set error).
- `staging/src/k8s.io/apiserver/pkg/server/options/admission_test.go`: expected plugin order includes the enforcer.
- `pkg/kubeapiserver/options/plugins_test.go`: expected ordered suffix includes the enforcer after VAP.
- `pkg/controlplane/apiserver/config_test.go`: `TestConditionalRequestClassifier`. URL→RequestInfo→attributes table for
  write and read verbs, excluded resources and non-resource paths.
- `pkg/registry/authorization/util/helpers_test.go`: `TestConditionsAwareDecisionToSARStatus` (six decision shapes).
- `pkg/registry/authorization/subjectaccessreview/rest_test.go`: `TestCreate` reworked into a gate × client-options ×
  decision matrix with a conditions-aware fake. The LSAR and SSAR `rest_test.go` fakes gain
  `ConditionsAwareAuthorize`/`EvaluateConditions`.
- `test/integration/apiserver/conditionalauthorization/` (new):
  - `conditionalauthorization_test.go`: `TestConditionalAuthorizationEnabled`, `…Disabled` and `…EnforcerDisabled`.
    It uses a real kube-apiserver plus a SAR/ACR webhook server. Cases: unconditional and conditional
    allow/deny/no-opinion; CEL-by-name, label, data and operation; deny > noopinion > allow; update-to-create; compound
    authorization; namespaceObject; SAR/SSAR/LSAR conditional versus unconditional clients; fold-down for GET and for
    SAR create (excluded from admission).
  - `crd_conversion_test.go`: conditions are evaluated against the request-version CR (v1 versus v2 schema through a
    conversion webhook), on create and update.
  - `hpa_conversion_test.go`: the same for HPA v1 versus v2.
  - `vap_ordering_test.go`: VAP rejects before conditions are evaluated; conditions are evaluated after VAP admits.
  - `main_test.go`: etcd test main.

**(f) Gate-off behaviour changes visible to callers**
1. With the gate off, the filter, SAR and enforcer behaviour matches 1.37. `DefaultBuildHandlerChain` uses
   `WithAuthorization`, and the legacy filter attaches nothing. The SAR handlers take the `Authorize` path, with the same
   status fields; `EvaluationError` is now set inside the struct literal, with the same value. The enforcer's
   `Handles()` returns false.
2. **Generic apiservers (k8s.io/apiserver `NewAdmissionOptions`) now register and enable `AuthorizationConditionsEnforcer`
   by default.** `RecommendedPluginOrder` includes it and the generic `DefaultOffPlugins` is empty. Only kube-apiserver
   and the sample generic server mark it default-off. With the gate off it is a no-op, but it is visible:
   - It appears in the enabled plugin list (`TestEnabledPluginNames` was updated for this).
   - It needs the generic initializer to call `InspectFeatureGates`, or `ValidateInitialization` fails.
   - The generic initializer always calls `InspectFeatureGates(i.featureGates)`
     (`staging/src/k8s.io/apiserver/pkg/admission/initializer/initializer.go:78-79`). I did not check whether any
     downstream server passes a nil feature gate there, which would panic at `features.Enabled`.
3. Exported Go API changes:
   - `NewREST` and `RESTStorageProvider.Authorizer` now require `authorizer.Authorizer` instead of
     `UnconditionalAuthorizer`.
   - The five audit constants are exported.
   - New fields in `server.AuthorizationInfo`.
   - The metric help text changed.

---

## PR #143024: [5/n] In-process CEL evaluation (OPEN, not merged; single commit `f410163f598`)

**Status: unmerged.** It exists only on the review branch, on top of `origin/master`.

**Summary.** It adds an in-process evaluator for conditions of type `authorizer.kubernetes.io/cel`, using the
ValidatingAdmissionPolicy CEL machinery (`object`, `oldObject`, `request`, `namespaceObject`, optional `authorizer`
with per-request caching, runtime cost budget). It defines the generic `BuiltinConditionsEvaluatorBuilder` and
`BuiltinConditionsEvaluator` interfaces and plugs them into the webhook authorizer's `EvaluateConditions`:
1. It partially evaluates the decision in-process (`PartiallyEvaluateConditionsAwareDecision`). Builtin errors are
   treated as unevaluatable, which defers them to the webhook to handle version skew.
2. If the result is unconditional, it returns that.
3. Otherwise it sends the **refined** decision, with false conditions removed, over ACR.

kube-apiserver constructs the builder only when the gate is on **and** the webhook has `conditionsReview` configured.
That requires passing a client through `BuildAuthorizer`/`ToAuthorizationConfig`.

Stat: 20 files, +1098/−246.

**(a) Packages touched**
- `k8s.io/apiserver/pkg/admission/plugin/cel` (new `authorization_conditions.go`)
- `k8s.io/apiserver/pkg/authorization/authorizer` (interfaces), `.../authorizerfactory` (delegating)
- `k8s.io/apiserver/plugin/pkg/authorizer/webhook`
- `k8s.io/api/authorization/v1alpha1` (doc only), `pkg/apis/authorization` (doc only)
- kube-apiserver: `pkg/controlplane/apiserver/config.go`, `pkg/kubeapiserver/authorizer/{config,reload}.go`,
  `pkg/kubeapiserver/options/authorization.go`
- `test/integration/apiserver/conditionalauthorization` (three files)

**(b) New / changed exported symbols**
- `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/interfaces.go` (post-image `:347`–`:375`):
  - `const ConditionTypeAuthorizationCEL = "authorizer.kubernetes.io/cel"`
  - `type BuiltinConditionsEvaluatorBuilder interface { EvaluatorForData(ctx, data ConditionsData, apiServerAuthorizer Authorizer) (BuiltinConditionsEvaluator, error) }`
  - `type BuiltinConditionsEvaluator interface { EvaluateCondition(ctx, condition Condition) ConditionEvaluationResult }`
- `staging/src/k8s.io/apiserver/pkg/admission/plugin/cel/authorization_conditions.go` (new):
  - `func NewAuthorizationConditionsEvaluatorBuilder(informerFactory informers.SharedInformerFactory, client kubernetes.Interface, runtimeCELCostBudget int64) (authorizer.BuiltinConditionsEvaluatorBuilder, error)`.
    Errors on a nil informer factory or client.
  - Unexported: `celAuthorizationConditionsEvaluatorBuilder` (`EvaluatorForData` requires `*admission.VersionedAttributes`,
    resolves the namespace through `namespacematcher.Matcher`, wraps `apiServerAuthorizer` in
    `admissionauthorizer.NewCachingAuthorizer`); `celAuthorizationConditionsEvaluator.EvaluateCondition` (unevaluatable
    for nil, a non-CEL type or an empty expression; compiles **on every call** with the `StoredExpressions` env;
    returns error or Boolean); `validationCondition` (return type bool); and a lazily initialised env template
    (`DefaultCompatibilityVersion`).
- `staging/src/k8s.io/apiserver/plugin/pkg/authorizer/webhook/webhook.go`:
  - `NewFromInterface(..., authorizationV1Alpha1Interface, builtinConditionsEvaluatorBuilder authorizer.BuiltinConditionsEvaluatorBuilder)`
    and `New(..., conditionsReviewConfig, conditionsReviewVersion, builtinConditionsEvaluatorBuilder)`: each gains a new
    trailing parameter (exported signature change). New struct field `builtinConditionsEvaluatorBuilder`.
  - `EvaluateConditions` (post-image `:429`) now calls `tryEvaluateUsingBuiltins` (`:951`), then either
    `UnconditionalPartsOrError()` or `webhookEvaluateConditions` (`:453`). The latter is the previous ACR logic, now
    receiving the refined decision. `tryEvaluateUsingBuiltins` gets the API server's authorizer from
    `request.ConditionallyAuthorizedDecisionFrom(ctx)`.
  - The `PossibleDecisions` check in `webhookEvaluateConditions` now runs against the **refined** decision. Per the doc
    comment, its FailureDecision may drop from Deny to NoOpinion when every Deny condition evaluated false.
- `staging/src/k8s.io/apiserver/pkg/authorization/authorizerfactory/delegating.go`: new field
  `DelegatingAuthorizerConfig.BuiltinConditionsEvaluatorBuilder authorizer.BuiltinConditionsEvaluatorBuilder`.
  `k8s.io/apiserver/pkg/server/options` does not set it, so delegated (aggregated) apiservers have no builtin evaluator.
- `pkg/kubeapiserver/authorizer/config.go`: new field `Config.KubeClient kubernetes.Interface`.
- `pkg/kubeapiserver/options/authorization.go`: `ToAuthorizationConfig(versionedInformerFactory, client kubernetes.Interface)`
  gains a parameter (exported signature change).
- `pkg/controlplane/apiserver/config.go`: `BuildAuthorizer(ctx, s, egressSelector, apiserverID, versionedInformers, client clientgoclientset.Interface)`
  gains a parameter (exported signature change). `BuildGenericConfig` passes `clientgoExternalClient`.
- `pkg/kubeapiserver/authorizer/reload.go`: calls
  `plugincel.NewAuthorizationConditionsEvaluatorBuilder(VersionedInformerFactory, KubeClient, apiscel.RuntimeCELCostBudget)`.
  On error it logs a warning and continues without builtins.

**(c) API fields.** No new fields. Doc changes only:
- `Condition.type` (internal `pkg/apis/authorization/types.go`) mentions `authorizer.kubernetes.io/cel`; the v1 type
  already had this text from #137633.
- `AuthorizationConditionsRequest.decision` (v1alpha1, internal, proto, swagger): "The API server may refine the
  decision before sending it, by evaluating some of the conditions in-process, e.g. removing conditions that evaluated
  to false."
- New well-known condition type string (not an API enum): `authorizer.kubernetes.io/cel`.

**(d) Feature-gate checks added.** None new. The builder is constructed inside the existing gate check at
`pkg/kubeapiserver/authorizer/reload.go:189` (f410 tree; the same `if` as #137633's `:185`). The webhook builtin path is
reached only through `EvaluateConditions`, which the gated enforcer calls. Test-only gate settings:
`webhook_conditional_test.go:1429`, `:1531`.

**(e) Tests added / changed**
- `staging/src/k8s.io/apiserver/pkg/admission/plugin/cel/authorization_conditions_test.go` (new):
  - `TestAuthorizationConditionsEvaluator_EvaluateCondition`: skip/unevaluatable cases, true/false and errors over
    object, oldObject, request and namespaceObject.
  - `TestNewAuthorizationConditionsEvaluatorBuilder`: nil-argument errors.
  - `TestAuthorizationConditionsEvaluatorBuilder_EvaluatorForData`: data type requirement, namespace lookup.
  - `TestAuthorizationConditionsEvaluator_CachesAuthorizerChecks`: one authorizer call per identical check.
- `staging/src/k8s.io/apiserver/plugin/pkg/authorizer/webhook/webhook_conditional_test.go`: new
  `TestEvaluateConditions_Builtins` (fully in-process versus refined-then-webhook; builtin error defers to the webhook)
  and `TestEvaluateConditions_BuiltinsWithoutContextAuthorizer`. Existing tests get signature updates.
  `webhook_v1_test.go` and `webhook_v1beta1_test.go` get signature updates only.
- `test/integration/apiserver/conditionalauthorization/conditionalauthorization_test.go` (+403/−~250):
  - Reactivates the CEL compound-authorization and `namespaceObject` cases, which were TODO-disabled in #141959
    ("Reactivate this when we support in-tree evaluation").
  - Moves the condition type from `"k8s.io/authorization-cel"` to `builtinCELConditionType`.
  - Adds a webhook-fallback authorizer and an ACR-count-per-user helper, to show when ACR is skipped.
- `crd_conversion_test.go` and `hpa_conversion_test.go`: adapt to the condition-type and helper changes.

**TODO/FIXME added by #143024** (two, both non-test):
- `staging/src/k8s.io/apiserver/pkg/admission/plugin/cel/authorization_conditions.go:52`: "TODO(luxas): Right now the
  budget is per-condition, not per-evaluator. Should we have two knobs or just that one?"
- `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/interfaces.go:356`: "TODO(luxas): Add a
  RecognizesCondition(Condition) bool method to the builder … so callers can skip EvaluatorForData … when only opaque
  condition types are used."

TODOs **removed** by #143024: `webhook.go` "TODO(luxas): Use builtin evaluators to resolve as much as possible…", and
three "Reactivate this when we support/add support for in-tree evaluation" in the integration test.

**(f) Gate-off behaviour changes.** None at runtime. The builder is built only when the gate is on and
`conditionsReview` is set, and `EvaluateConditions` is unreachable with the gate off. Compile-level changes:
`webhook.New`, `webhook.NewFromInterface`, `BuildAuthorizer` and `ToAuthorizationConfig` gain parameters, and
`DelegatingAuthorizerConfig` and `authorizer.Config` gain fields.

---

## Cross-PR observations from this inventory (input for Stage 2; not yet severity-rated)

1. **The ACR endpoint is not served, but the generic delegating authorizer is given an ACR client.**
   - #137633 makes `DelegatingAuthorizationOptions` always pass `client.AuthorizationV1alpha1()`, and the reviewer is
     kept whenever the gate is on.
   - kube-apiserver serves no `authorizationconditionsreviews` resource, so `EvaluateConditions` from an aggregated
     server would always fail closed.
   - It is reached only if that server also uses `WithConditionsAwareAuthorization`, which needs a classifier. The
     generic server does not set one; kube-apiserver sets it in `pkg/controlplane/apiserver/config.go:249`.
   - Kind: Question (code).
2. **In-process CEL is tied to webhook ACR configuration.** #143024 builds the evaluator only when
   `webhook.conditionsReview` is set (`reload.go`, f410 tree `:189`–`:211`). A webhook that wants in-process CEL only,
   with no ACR endpoint, cannot get it. Kind: Question (KEP/code).
3. **The CEL expression is recompiled on every `EvaluateCondition` call** (`authorization_conditions.go`, f410 tree,
   `EvaluateCondition`). The cost budget is per condition (it has a TODO). Relevant to the Stage 3a DoS check.
4. **The generic apiserver enables the enforcer by default** (see #141959 (f)2). kube-apiserver is default-off.
5. **Validation of ACR `request.admissionRequest`.** It is `+k8s:required` in v1alpha1 but has JSON `omitempty`, and
   the hand-written ACR request validation explicitly does not validate `AdmissionRequest`
   (`staging/src/k8s.io/apiserver/pkg/apis/authorization/validation/validation.go:263` onward on HEAD).
6. **#140714's title promises defaults; none moved.** It is a description mismatch only.
