# Update `kep.md` to Match Implementation of KEP‑5681 Conditional Authorization

## Context

The KEP at `/Users/luxas/upbound/kubernetes-push/kep.md` (2779 lines) describes the *designed* shape of KEP‑5681 (Conditional Authorization). During implementation across the commits listed in `changes.md`, several design decisions changed materially. The goal of this plan is to bring `kep.md` back in sync with what actually ships in the tree — while preserving the KEP's structure, background material, alternatives, and long‑form reasoning.

Focus of the edit: **the "Proposal" chapter through "Authorizer requirements" is where the bulk of the divergence sits.** Background/Alternatives/PRR/Appendices are mostly untouched.

## Cross‑cutting terminology changes (do these globally first)

Apply these replacements across the whole KEP; then handle the section‑specific rewrites below.

| Old (KEP‑only) term | New (implemented) term | Notes |
|---|---|---|
| `ConditionSet` | `ConditionsMap` | It is a struct with three private slices `denyConditions`, `noOpinionConditions`, `allowConditions` — not one flat set with a per‑condition `Effect`. |
| `ConditionSetChain` (in SAR / ACR) | `Union` variant of `ConditionsAwareDecision` (`[]NamedConditionsAwareDecision`) | The chain is a tree of decisions, not a flat slice. Each leaf is `Deny`/`Allow`/`NoOpinion`/`ConditionsMap`. |
| `ConditionSetEvaluator` interface | `EvaluateConditions(ctx, decision, data) (Decision, reason, error)` method on `Authorizer` | No separate embedded interface. See §Core interface changes below. |
| `ConditionEffect` enum (`Allow`/`Deny`/`NoOpinion`) | Removed. Effect is expressed by which slice a `Condition` lives in on the `ConditionsMap`. |  |
| `ConditionData` | `ConditionsData` (plural, richer) | See §Core interface changes for the exact method set. |
| `ConditionsMode` / `ConditionalAuthorizationConfiguration.Mode` (`""`/`HumanReadable`/`Optimized`) | `AuthorizationOptions.HandledDecisionTypes []ConditionsAwareDecisionType` | The client opts in per‑decision‑type (set semantics) instead of picking a serialisation format. |
| `SubjectAccessReviewCondition{Effect,...}` | `Condition{ID,Type,Condition,Description}` — no `Effect` field. |  |
| `Decision` (KEP: opaque struct with methods) | Two distinct types: pre‑existing `Decision` int enum (**unchanged** — still `DecisionDeny=0, DecisionAllow, DecisionNoOpinion`) **plus** new `ConditionsAwareDecision` struct that wraps the discriminated variants. | Every place the KEP says "Decision struct with private fields and IsAllowed/etc." must be reworded to talk about `ConditionsAwareDecision`. |
| `DecisionAllow("reason")` etc. as constructors of the new struct | `ConditionsAwareDecisionAllow(reason string, err error)` etc.; and `ConditionsAwareDecisionFromParts(Decision, string, error)` for lifting a legacy decision. | Signatures now take `(reason, err)`. |
| `DecisionConditional(*ConditionSet)` | `ConditionsAwareDecisionConditionsMap(deny, noOpinion, allow []Condition)` | Constructor lives in `conditionsmap.go`. |
| `ChainedDecisions([]Decision, ...Authorizer)` free function | `ConditionsAwareDecisionUnion` builder (`.Add(name, d)` then `.ToDecision()`) | Union is now a tree node, built stepwise. |
| `Decision.Evaluate(...)` method | Top‑level `PartiallyEvaluateConditionsAwareDecision(ctx, d, data, evalFn)`; and `ConditionsMap.Evaluate(ctx, data, evalFn)` for a single leaf. | Two functions, not one method. `PartiallyEvaluate…` supports leaving unevaluated leaves in place; `ConditionsMap.Evaluate` yields a final `Decision`. |
| `Decision.AllConditionSets()` method | Removed. Walk `ConditionsAwareDecision.Union` / `ConditionsMap` yourself; there is no aggregation helper. |  |

## Section‑by‑section rewrite plan

### 1. Table of contents (top of file)
Regenerate anchors that follow renamed headings, especially:
- `Condition and ConditionSet data model` → `Condition and ConditionsMap data model`
- `Computing a concrete decision from a ConditionSet` → `Computing a concrete decision from a ConditionsMap`

### 2. §Glossary (~line 441)
Replace the three bullets. Reference implementation types from `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/`:
- **Concrete/Unconditional decision** — one of `Decision{Deny, Allow, NoOpinion}` (int enum), or a `ConditionsAwareDecision` whose `Type` is `Deny`/`Allow`/`NoOpinion`.
- **Residual** — as before.
- **Conditional Allow** — a `ConditionsMap` whose `PossibleDecisions()` set includes `DecisionAllow`. In practice: at least one Allow condition present and no unavoidable Deny.
- **Conditional Deny** — a `ConditionsMap` whose `PossibleDecisions()` is `{Deny, NoOpinion}` (no Allow conditions).
- New: **`ConditionsAwareDecision`** — the top‑level wire/internal type. Discriminated by `Type`; variants: `Deny`, `Allow`, `NoOpinion`, `ConditionsMap`, `Union`. Union nodes hold `[]NamedConditionsAwareDecision`. Zero value is `Deny`.
- New: **`ConditionsMap`** — leaf conditional decision holding three ordered slices (`denyConditions`, `noOpinionConditions`, `allowConditions`); at least one Allow *or* one Deny condition is required; max 128 conditions total.

### 3. §Proposal (bullet list ~line 454)
Rewrite the bullet block:
- The `authorizer.Authorizer` interface is **split** into `UnconditionalAuthorizer` (single `Authorize` method — legacy) and `Authorizer` (embeds `UnconditionalAuthorizer` **and** adds `ConditionsAwareAuthorize(...) ConditionsAwareDecision` and `EvaluateConditions(...) (Decision, reason, error)`).
- Callers that don't need conditions accept `UnconditionalAuthorizer`; the conditions‑aware admission plugin and `WithConditionsAwareAuthorization` filter take the full `Authorizer`.
- SAR API adds `spec.authorizationOptions.handledDecisionTypes` (client opt‑in) and `status.conditionalDecision` (single `ConditionsAwareDecision`, mutually exclusive with `allowed=true`/`denied=true`).
- HTTP filter is a **separate** function `WithConditionsAwareAuthorization(handler, auth, s, conditionsEnforcerEnabled bool, classifier ConditionalAuthorizationRequestClassifier)` in `staging/src/k8s.io/apiserver/pkg/endpoints/filters/authorization.go`. It only engages when the `ConditionalAuthorization` feature gate is on **and** the enforcer plugin is enabled **and** a classifier is set; otherwise it delegates to legacy `WithAuthorization`.
- Admission plugin `AuthorizationConditionsEnforcer` (`staging/src/k8s.io/apiserver/pkg/admission/plugin/authorizer/conditionsenforcer/`) is registered in the recommended plugin order **after** `MutatingAdmissionWebhook` and **before** `ValidatingAdmissionPolicy` (not "first validating plugin"). It observes the decision from the request context (`request.ConditionallyAuthorizedDecisionFrom`), calls `authz.EvaluateConditions` with a versioned attributes wrapper (`versioned_attrs.go`), and enforces the resulting `Decision`.
- **The built‑in CEL conditions evaluator is deferred.** No production `BuiltinConditionSetEvaluator` exists in this branch (`staging/src/k8s.io/apiserver/pkg/authorization/cel/compile.go` only extends the AuthorizationConfig matcher CEL environment to include `authorizationOptions`; there is a test‑only CEL evaluator in `test/integration/apiserver/conditionalauthorization/`). Update the KEP to say this is planned but not present.
- Section footnote `[^3]` about `kube-apiserver` being required to serve the review API stays valid, but points at `authorization.k8s.io/v1alpha1 AuthorizationConditionsReview`.

### 4. §Technical Requirements
No structural changes — verify wording still holds. Reword "conditions are part of the returned authorization decision" to reference `ConditionsAwareDecision`.

### 5. §Core interface changes (~line 558) — LARGEST REWRITE
Replace the Go code blocks with the actual shapes (verbatim from `interfaces.go`, `conditions.go`, `conditionsmap.go`, `conditionsunion.go`, `evaluate.go`). Concretely:

- Show the split:
  ```go
  type UnconditionalAuthorizer interface {
      Authorize(ctx context.Context, a Attributes) (Decision, string, error)
  }
  type Authorizer interface {
      UnconditionalAuthorizer
      ConditionsAwareAuthorize(ctx context.Context, a Attributes) ConditionsAwareDecision
      EvaluateConditions(ctx context.Context, decision ConditionsAwareDecision, data ConditionsData) (Decision, string, error)
  }
  var ErrorConditionEvaluationNotSupported = errors.New("condition evaluation not supported")
  ```
- Explain the "downscoped" `UnconditionalAuthorizer` pattern and why we did **not** collapse the legacy `Decision int` enum into a struct (backwards compatibility + zero‑value semantics — `Decision{} == DecisionDeny` still holds via `Decision(0)`).
- Delete the whole `ConditionsMode` block (`ConditionsModeNone`, `ConditionsModeHumanReadable`, `ConditionsModeOptimized`) and delete `Attributes.ConditionsMode()`. Replace with a subsection explaining the shift to `AuthorizationOptions.HandledDecisionTypes` on `SubjectAccessReviewSpec.authorizationOptions` (an unordered set of decision‑type strings the client can consume; conditions‑unaware clients pass only `{Allow, Deny, NoOpinion}`). Reference `staging/src/k8s.io/api/authorization/v1/util.go`'s `SupportsConditionalAuthorization` / `SupportsUnconditionalAuthorization` helpers and `ConditionalAuthorizationDecisionTypes` / `UnconditionalAuthorizationDecisionTypes` sets.
- Show the actual `ConditionsAwareDecision` struct and its constructors + methods (from `conditions.go`):
  ```go
  type ConditionsAwareDecision struct { /* internal fields */ }

  func ConditionsAwareDecisionDeny(reason string, err error) ConditionsAwareDecision
  func ConditionsAwareDecisionAllow(reason string, err error) ConditionsAwareDecision
  func ConditionsAwareDecisionNoOpinion(reason string, err error) ConditionsAwareDecision
  func ConditionsAwareDecisionFromParts(d Decision, reason string, err error) ConditionsAwareDecision
  func ConditionsAwareDecisionConditionsMap(deny, noOpinion, allow []Condition) ConditionsAwareDecision
  // (Union is built via ConditionsAwareDecisionUnion below.)

  func (d ConditionsAwareDecision) IsAllow() bool
  func (d ConditionsAwareDecision) IsDeny() bool
  func (d ConditionsAwareDecision) IsNoOpinion() bool
  func (d ConditionsAwareDecision) IsUnconditional() bool
  func (d ConditionsAwareDecision) IsConditionsMap() bool
  func (d ConditionsAwareDecision) IsUnion() bool
  func (d ConditionsAwareDecision) ConditionsMap() ConditionsMap
  func (d ConditionsAwareDecision) UnionedDecisions() iter.Seq2[string, ConditionsAwareDecision]
  func (d ConditionsAwareDecision) UnconditionalParts(expectConditional bool) (Decision, string, error)
  func (d ConditionsAwareDecision) PossibleDecisions() sets.Set[Decision]
  func (d ConditionsAwareDecision) FailureDecision() Decision
  func (d ConditionsAwareDecision) ContainsUnconditionalAllowOrDeny() bool
  func (d ConditionsAwareDecision) Reason() string
  func (d ConditionsAwareDecision) Error() error
  ```
  Explain that the internal enum has five variants (Deny/Allow/NoOpinion/ConditionsMap/Union); zero value is Deny.
- Explain `UnconditionalParts(expectConditional bool)`: pass `true` to fail‑closed to `FailureDecision()` when the decision is still conditional; pass `false` to error out. This is the primary bridge from the new type back to the classic `(Decision, string, error)` return.
- Replace the `ConditionData` block with the actual `ConditionsData` interface (from `interfaces.go` lines 311–343). Enumerate all 11 methods: `GetName`, `GetNamespace`, `GetResource() schema.GroupVersionResource`, `GetSubresource`, `GetOperation() AdmissionOperation`, `GetOperationOptions() runtime.Object`, `IsDryRun`, `GetObject`, `GetOldObject`, `GetKind() schema.GroupVersionKind`, `GetUserInfo() user.Info`. Note the KEP's TODO about "might need to change to something more generic" is now resolved (this interface *is* the generic subset of `admission.Attributes`).

### 6. §Condition and ConditionsMap data model (~line 705) — LARGE REWRITE
- Rename heading and TOC.
- Replace the `ConditionEffect` const block with a paragraph: "Effect is expressed structurally by which slice a `Condition` lives in on `ConditionsMap` (`denyConditions`, `noOpinionConditions`, `allowConditions`); there is no `Effect` field on `Condition` itself." Preserve the semantic explanation of what each effect means.
- Replace `type Condition struct { ID, Condition, Effect, Description }` with the *interface* `Condition` from `interfaces.go` (`GetID`, `GetType`, `GetCondition`, `GetDescription`, `Evaluate(ctx, data) ConditionEvaluationResult`). Add the reference impl `GenericCondition` struct (from `conditionsmap.go`) that authorizers typically use.
- Add a new subsection on `ConditionEvaluationResult` (from `evaluate.go` lines 28–97): explains the four states — True / False / Error / Unevaluatable — and why partial evaluation needs the fourth state.
- Replace `ConditionSet` block with the on‑the‑wire `ConditionsMap` struct (three `[]Condition` fields plus limits) **and** the in‑process `authorizer.ConditionsMap` type. Include the concrete limits from `conditionsmap.go`:
  - `MaxConditionsPerMap = 128`
  - `MaxConditionBytes = 10240` (condition body)
  - `MaxConditionDescriptionBytes = 1024`
- Add a "Validation" subsection describing constraints from `staging/src/k8s.io/apiserver/pkg/apis/authorization/validation/validation.go`:
  - `Condition.ID` and `Condition.Type` must be **domain‑qualified label keys** (e.g. `acme.io/foo`); enforced by `validateDomainPrefixSeparator`.
  - Length limits above are enforced.
  - `authorizerName` in a `Union` (see below) must be a DNS‑1123 subdomain.
  - The SAR‑level `spec.authorizationOptions` / `status.conditionalDecision` fields are behind `+featureGate=ConditionalAuthorization` and forbidden when the gate is off.

### 7. §Computing a concrete decision from a ConditionsMap (~line 801)
- Rename heading; update TOC.
- Keep the Deny > NoOpinion > Allow evaluation ladder — semantics match. Cross‑reference the actual implementation: `ConditionsMap.Evaluate(ctx, data, evalFn)` in `evaluate.go` and the `EvaluateConditionFunc` / `MaybeEvaluateConditionFunc` types (300–302 in `interfaces.go`).
- Add a note on partial vs. concrete evaluation: `MaybeEvaluateConditionFunc` returns `ConditionEvaluationResult` (with `Unevaluatable`), used by `PartiallyEvaluateConditionsAwareDecision`; `EvaluateConditionFunc` returns `(bool, error)`, used by `ConditionsMap.Evaluate` to reach a final `Decision`.
- The KEP's remarks about `&&`/`||` short‑circuit ordering are still valid, keep them.

### 8. §Computing a concrete decision from a conditional authorization chain (~line 852) — LARGE REWRITE
- Rewrite the chain to a **tree**: a `ConditionsAwareDecision` of type `Union` holds `[]NamedConditionsAwareDecision`, evaluated depth‑first.
- Describe the `ConditionsAwareDecisionUnion` builder in `conditionsunion.go` (`Add(name, d)`, short‑circuits once an unconditional Allow/Deny is added, `ToDecision()` returns either a single unconditional if the tree collapses or a Union node otherwise). Validation of `authorizerName` (DNS‑1123 subdomain, uniqueness within a union). `FailureDecision()` on a Union returns Deny if any leaf can Deny, else NoOpinion.
- Explain that `WithConditionsAwareAuthorization` is a **new** filter (not a rewired `WithAuthorization`). Show the *actual* signature verbatim from `staging/src/k8s.io/apiserver/pkg/endpoints/filters/authorization.go` L119:
  ```go
  func WithConditionsAwareAuthorization(
      hhandler http.Handler,
      auth authorizer.Authorizer,
      s runtime.NegotiatedSerializer,
      conditionsEnforcerEnabled bool,
      conditionalAuthzClassifier ConditionalAuthorizationRequestClassifier,
  ) http.Handler
  ```
  And the classifier type (L52–54):
  ```go
  type ConditionalAuthorizationRequestClassifier func(attrs authorizer.Attributes) bool
  ```
- Note the fallthrough behaviour: when the feature gate is off or the enforcer plugin isn't enabled, `WithConditionsAwareAuthorization` delegates to legacy `WithAuthorization`. When engaged, it always attaches a `ConditionsAwareDecision` to `ctx` via `request.WithConditionallyAuthorizedDecision(ctx, authz, d)` (see `staging/src/k8s.io/apiserver/pkg/endpoints/request/context.go` L91–102) — even for classifier=false requests, in which case the plugin sees an unconditional decision and short‑circuits.
- Update the audit annotation list: the actual keys are `authorization.k8s.io/decision`, `authorization.k8s.io/reason`, and the new `authorization.k8s.io/is-conditional-decision` (L44 of `authorization.go`) — set to `"true"` when the request is let through as conditional allow.
- Update the classifier‑applicability bullets:
  - The classifier is provided by `kube-apiserver` and stored on `server.Config.Authorization.ConditionalAuthorizationRequestClassifier` (see `staging/src/k8s.io/apiserver/pkg/server/config.go` L399–403 and L1046–1047). It is set from `pkg/controlplane/apiserver/config.go` and depends on the request being `create`/`update`/`patch`/`delete`/`deletecollection` for a resource served by the same API server, or a Connect handler, or an aggregated‑API‑served group. (Confirm the exact policy by re‑reading `pkg/controlplane/apiserver/config.go` before finalising the wording — the KEP text should match the *actual* predicate.)
- Add a section on `PartiallyEvaluateConditionsAwareDecision` (evaluate.go L227–279) — the top‑level function that walks the decision DAG, short‑circuits on unconditional Allow/Deny, and stops partial eval at the first still‑conditional leaf, leaving downstream leaves untouched.

### 9. §`AuthorizationConditionsEnforcer` admission controller (~line 963)
- Update the plugin **position**: not "first validating plugin"; the recommended order is `[lifecycle, mutatingadmissionpolicy, mutatingwebhook, AuthorizationConditionsEnforcer, validatingadmissionpolicy, validatingwebhook]` (`staging/src/k8s.io/apiserver/pkg/server/options/admission.go` L97). Rationale: it must run before validating webhooks so they don't fire unnecessarily, but it needs the fully‑mutated object, so it runs after mutating webhooks. Rewrite the "It is proposed that the AuthorizationConditionsEnforcer is the first validating admission plugin to run" sentence.
- Update the "must not start up misconfigured" paragraph: the current implementation does **not** hard‑error when the feature gate is on but the plugin is disabled. Instead:
  - `AdmissionOptions` records `Authorization.ConditionsEnforcerPluginEnabled = slices.Contains(pluginNames, conditionsenforcer.PluginName)` (`admission.go` L183).
  - `WithConditionsAwareAuthorization` only engages when *both* the gate and this bool are true (`config.go` L1046 and `authorization.go` L120). Otherwise, the plain `WithAuthorization` runs and no conditional decision is ever attached.
  - The plugin itself gates on the feature gate (`conditionsenforcer.go` L65–67) and skips work when the context has no conditional decision.
  - Rewrite this section to describe the actual "correlated feature gate + plugin flag" enablement, and adjust the "misconfigured start‑up" paragraph accordingly. Consider whether to *also* propose an options‑validation error as a future hardening; if so, mark it as a TODO / follow‑up rather than something the current code enforces.
- Note that the enforcer consumes the decision via `request.ConditionallyAuthorizedDecisionFrom(ctx)`, converts admission `Attributes` into a `ConditionsData`‑compatible view via `versioned_attrs.go`, and calls `authz.EvaluateConditions(ctx, decision, data)` — where `authz` is the original `Authorizer` interface stored alongside the decision, giving the enforcer access to the authorizer's `EvaluateConditions` regardless of authorizer chain topology.

### 10. §Changes to `(Self)SubjectAccessReview` (~line 981) — LARGE REWRITE
- Replace the `SubjectAccessReviewStatus.ConditionSetChain` block with the actual shape (from `staging/src/k8s.io/api/authorization/v1/types.go` L270–302):
  - New `Denied bool` field promoted from v1beta1.
  - New `ConditionalDecision *ConditionsAwareDecision` field — a single decision (which itself may be a `Union` variant); mutually exclusive with `Allowed=true` and `Denied=true`.
  - Feature‑gated: `+featureGate=ConditionalAuthorization`, `+k8s:ifDisabled("ConditionalAuthorization")=+k8s:forbidden`.
- Replace `SubjectAccessReviewCondition{ID,Effect,Condition,Description}` with the actual `Condition{ID, Condition, Type, Description}` (L418–453). Note the removal of `Effect`.
- Replace the wire `ConditionsMap` (L461–494) — three slices `DenyConditions`, `NoOpinionConditions`, `AllowConditions`, each `+listType=map` on `id`, `+k8s:maxItems=128`.
- Add the new discriminated union types:
  - `ConditionsAwareDecisionType` string enum (L496–522): `Deny`, `Allow`, `NoOpinion`, `ConditionsMap`, `Union`.
  - `ConditionsAwareDecision` (L524–578): discriminator `type`, plus mutually‑exclusive `deny`/`noOpinion`/`allow`/`conditionsMap`/`union` union members. Explain the union‑discriminator pattern (`+k8s:beta=+k8s:unionDiscriminator`, `+k8s:unionMember`).
  - `NamedConditionsAwareDecision` (L580–594): `authorizerName` (`+k8s:format=k8s-long-name`) and inner `decision`.
  - `UnconditionalDecision` (L596–609): `reason`, `evaluationError`.
- Replace `SubjectAccessReviewSpec.ConditionalAuthorization *ConditionalAuthorizationConfiguration` with the actual `AuthorizationOptions *AuthorizationOptions` field (L229–235). Show `AuthorizationOptions.HandledDecisionTypes []ConditionsAwareDecisionType` (L398–416) with its semantics: a client that omits the field or lists only `{Allow, Deny, NoOpinion}` is conditions‑unaware; a conditions‑aware client lists all five types. The authorizer that would have returned conditions folds back to `FailureDecision()` when the client can't handle them.
- Also apply to `SelfSubjectAccessReviewSpec` (L249–268) — same field.
- Remove all remaining references to `ConditionsMode` and `ConditionalAuthorizationConfiguration.Mode`.

### 11. §Supporting webhooks through the `AuthorizationConditionsReview` API (~line 1117) — LARGE REWRITE
Replace the sketch with the actual v1alpha1 shape (from `staging/src/k8s.io/api/authorization/v1alpha1/types.go`):

```go
type AuthorizationConditionsReview struct {
    metav1.TypeMeta
    metav1.ObjectMeta  // must be empty
    Request  *AuthorizationConditionsRequest
    Response *AuthorizationConditionsResponse
}

type AuthorizationConditionsRequest struct {
    Decision         authorizationv1.ConditionsAwareDecision  // required
    AdmissionRequest *admissionv1.AdmissionRequest            // optional
}

type AuthorizationConditionsResponse struct {
    UID      types.UID                                // required, copied from request
    Decision authorizationv1.ConditionsAwareDecision  // required
}
```

Key points to add / correct:
- The request carries the **exact `ConditionsAwareDecision` the authorizer previously returned** (not a bespoke `ConditionSetChain` slice). This is how correlation happens — the authorizer sees back its own conditions, verbatim, and evaluates them against the `AdmissionRequest`.
- The response includes a `UID` that the authorizer must copy from the request. The webhook authorizer (`staging/src/k8s.io/apiserver/plugin/pkg/authorizer/webhook/webhook.go` L439–551) generates a UUID per outgoing review, sends it in the request, and verifies it on the response before trusting the returned decision.
- The response's `Decision` is expected to be **unconditional** (`Allow`/`Deny`/`NoOpinion`) after evaluation, but the type allows any variant.
- **Configuration:** replace the KEP's `conditionsEndpointKubeConfigContext` / `authorizationConditionsReviewVersion` YAML fields with the actual shape from `staging/src/k8s.io/apiserver/pkg/apis/apiserver/types.go` L405–431:
  ```yaml
  webhook:
    connectionInfo:
      type: KubeConfigFile
      kubeConfigFile: /kube-system-authz-webhook.yaml
    subjectAccessReviewVersion: v1
    conditionsReview:
      version: v1alpha1
      kubeConfigContextName: authorization-conditions  # optional
  ```
  Note: the SAR and ACR endpoints may share a URL (when `kubeConfigContextName` is unset) and be disambiguated by `TypeMeta`, or use a distinct context in the same kubeconfig file.
- Update the webhook fanout table (`Webhooks during phase`) to reflect that in the current branch there is **no built‑in condition evaluator**, so the "Condition Type Supported" column is not yet reachable in production code — mark as future work.

### 12. §Composite / Union Authorizer Support (~line 1257)
- Rework the YAML examples so they use the actual API shape:
  - `status.conditionalDecision.type: Union` at the top, with `union: [ {authorizerName, decision}, ... ]`.
  - Leaves use `type: ConditionsMap` with `conditionsMap: { denyConditions:[…], noOpinionConditions:[…], allowConditions:[…] }`; each `Condition` has `id`, `type`, `condition`, `description` — no `effect`.
- The step‑by‑step walk‑through still holds semantically. Update the `AuthorizationConditionsReview` payloads in that walkthrough to carry `decision:` (a `ConditionsAwareDecision`) plus `admissionRequest:` instead of `conditionSetChain:` + inline object metadata.
- Update the description around "kube-apiserver can correlate what authorizer authored what condition through the authorizerName field" — this is now expressed by the `Union` tree structure: each `NamedConditionsAwareDecision` has an `authorizerName`.

### 13. §Built‑in CEL conditions evaluator (~line 1511) — MAJOR REWORK
- Reframe this section explicitly as *proposed / deferred*. State that at the time of writing, no `BuiltinConditionSetEvaluator` interface or CEL condition evaluator is wired into the API server. Refer to the TODO markers in `test/integration/apiserver/conditionalauthorization/conditionalauthorization_test.go` (the commented‑out `in-process-eval-only` and `if-in-process-fails-call-webhook` test variants) for the intended future shape.
- Note what *did* land in the CEL area: `staging/src/k8s.io/apiserver/pkg/authorization/cel/compile.go` extends the CEL environment used by `AuthorizationConfiguration.MatchConditions` to include `authorizationOptions.handledDecisionTypes` (guarded by the feature gate). This is a *matcher* CEL environment, not a condition evaluator — clarify the distinction to avoid reader confusion.
- Move `BuiltinConditionSetEvaluator` and the version‑skew discussion into a "Future work" subsection or clearly mark it as "not yet implemented".

### 14. §Feature availability and version skew (~line 1583)
- Replace the "authorizer implementation supports conditions" bullets with the current criteria:
  - `ConditionalAuthorization` feature gate on.
  - `AuthorizationConditionsEnforcer` admission plugin enabled (participates in `AllOrderedPlugins`).
  - Kube‑apiserver has installed a `ConditionalAuthorizationRequestClassifier` that returns `true` for the request.
  - Client opted in by populating `spec.authorizationOptions.handledDecisionTypes` with the full conditional set.
- Replace the version‑skew matrix with a `HandledDecisionTypes`‑based explanation: old clients don't send `HandledDecisionTypes`, so authorizers/servers must not return `ConditionalDecision`. New authorizers see the set and fold to `FailureDecision()` when needed.

### 15. §Other Kubernetes authorization enforcement points (~line 1612)
- **Compound Authorization for Connectible Resources** (~line 1626): the current implementation in `pkg/registry/core/pod/rest/authorize.go` `ensureAuthorizedForVerb` still takes `authorizer.UnconditionalAuthorizer`, so the compound `create` check on `pods/exec`, `pods/attach`, `pods/portforward` is **not yet conditions‑aware**. Rewrite this bullet to describe the current state and mark conditions‑awareness as follow‑up work.
- **Compound Authorization for update/patch → create** (~line 1655): `staging/src/k8s.io/apiserver/pkg/endpoints/handlers/update.go` has **no** conditional‑authz wiring in this branch (grep is empty). Mark as not‑yet‑implemented and clarify that the current PR set covers the framework but not this specific enforcement site.
- **Constrained Impersonation through Conditional Authorization** (~line 1662): the design section stands; nothing is implemented in this branch. Keep the discussion but mark clearly as future work; also update the example SAR YAML to use `status.conditionalDecision.type: ConditionsMap` with `allowConditions:`, dropping `conditionsType` for `type` (per‑condition, not per‑set).
- **Node authorizer** (~line 1794): mark as future work.
- **ValidatingAdmissionPolicies / deletecollection / Complete list of Authorize calls** (~lines 1809–1907): keep as design guidance; note that none of the specific enforcement sites are yet updated except for the primary `WithAuthorization` path and the `AuthorizationConditionsEnforcer` admission plugin. Update the `k8s.io/apiserver/pkg/endpoints/filters` bullet to also mention the new `WithConditionsAwareAuthorization` sibling function.

### 16. §Authorizer requirements (~line 1908)
- Replace every mention of `ConditionsMode`/`None` with `HandledDecisionTypes` — a set. The rule becomes: if the client's `HandledDecisionTypes` does not include `ConditionsMap` (and by transitive requirement, `Union`), the authorizer must fold to `FailureDecision()` (Deny if any Deny conditions were present, else NoOpinion). Reference `authorizationv1.SupportsConditionalAuthorization` and `AuthorizationOptions.HandledDecisionTypes` for the concrete check.
- Keep the "only produce a conditional response if unconditional is not possible", "must be API‑version aware", "must be safe and performant" bullets; they still apply.
- Add a bullet on the new hard limits (128 conditions / 10240 bytes / 1024 bytes description) and the domain‑qualified `id`/`type` requirement.

### 17. §Test Plan (~line 2014)
- Update the Integration tests bullet: the actual location is `test/integration/apiserver/conditionalauthorization/` (not `test/integration/apiserver/cel/conditionalauthz`). List the test files that landed: `conditionalauthorization_test.go`, `main_test.go`, `crd_conversion_test.go`, `hpa_conversion_test.go`.
- Add a short bullet acknowledging the "only webhook‑only variant is exercised" caveat (in‑process CEL evaluation variants are commented out awaiting the built‑in CEL evaluator).

### 18. §Production Readiness Review (~line 2119)
- Under "How can an operator determine if the feature is in use": mention the audit annotation `authorization.k8s.io/is-conditional-decision=true`.
- Under Monitoring: mention the `authorizationMetricsLabelForAuthorizeConditionsAware` label and its `AuthorizationConditionsEnforcer` counterparts (if you want to add a metrics bullet, verify names by reading `staging/src/k8s.io/apiserver/pkg/endpoints/filters/metrics.go`).

### 19. §TODOs (~line 2518)
- Remove or update TODOs that are now resolved by the implementation:
  - "One might be able to infer the admission‑time operation…" — resolved: `ConditionsData.GetOperation()` returns an `AdmissionOperation` explicitly.
  - Consider adding new TODOs: build the CEL condition evaluator; wire conditional authz into `ensureAuthorizedForVerb` and update→create; harden misconfiguration (gate on + plugin off) into an `AdmissionOptions.Validate` error; expose ConditionsMap `Type` at the map level if useful.

### 20. §Alternatives / Drawbacks / Appendices (~lines 2526–end)
- Only touch the "Only one ConditionSet exposed" alternative to rename to `ConditionsMap`, and the "Do nothing" alternative reasoning if it now needs to reference `ConditionsAwareDecision`. The rest can stay as historical design context.

## Critical files to cite / quote

When rewriting, cite these authoritative sources (all under `/Users/luxas/upbound/kubernetes-push/`):

- `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/interfaces.go` — `UnconditionalAuthorizer`/`Authorizer`, `Attributes`, `Condition` interface, `ConditionsData`.
- `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/conditions.go` — `ConditionsAwareDecision`, constructors, methods.
- `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/conditionsmap.go` — `ConditionsMap`, `GenericCondition`, size limits.
- `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/conditionsunion.go` — `ConditionsAwareDecisionUnion` builder.
- `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/evaluate.go` — `PartiallyEvaluateConditionsAwareDecision`, `ConditionsMap.Evaluate`, `ConditionEvaluationResult`.
- `staging/src/k8s.io/api/authorization/v1/types.go` L199–609 — SAR spec/status, `AuthorizationOptions`, `Condition`, `ConditionsMap`, `ConditionsAwareDecision`, `NamedConditionsAwareDecision`, `UnconditionalDecision`, `ConditionsAwareDecisionType`.
- `staging/src/k8s.io/api/authorization/v1/util.go` — `SupportsConditionalAuthorization`, `HandledDecisionTypes` helpers.
- `staging/src/k8s.io/api/authorization/v1alpha1/types.go` — `AuthorizationConditionsReview`, `Request`, `Response`.
- `staging/src/k8s.io/apiserver/pkg/apis/authorization/v1/encoding.go` — `SerializeConditionsAwareDecision` / `DeserializeConditionsAwareDecision`.
- `staging/src/k8s.io/apiserver/pkg/apis/authorization/validation/validation.go` — validation constraints.
- `staging/src/k8s.io/apiserver/pkg/apis/apiserver/types.go` L405–431 — `WebhookConfiguration.ConditionsReview`.
- `staging/src/k8s.io/apiserver/pkg/endpoints/filters/authorization.go` — `WithAuthorization` and new `WithConditionsAwareAuthorization` + classifier type.
- `staging/src/k8s.io/apiserver/pkg/endpoints/request/context.go` L91–102 — `WithConditionallyAuthorizedDecision` / `ConditionallyAuthorizedDecisionFrom`.
- `staging/src/k8s.io/apiserver/pkg/admission/plugin/authorizer/conditionsenforcer/conditionsenforcer.go` — plugin logic.
- `staging/src/k8s.io/apiserver/pkg/admission/plugin/authorizer/conditionsenforcer/versioned_attrs.go` — versioned attrs adapter.
- `staging/src/k8s.io/apiserver/pkg/server/options/admission.go` L97, L183 — recommended plugin order + `ConditionsEnforcerPluginEnabled` propagation.
- `staging/src/k8s.io/apiserver/pkg/server/config.go` L399–403, L1046–1047 — filter wiring.
- `staging/src/k8s.io/apiserver/pkg/authorization/cel/compile.go` L218, L344 — CEL matcher env extension.
- `staging/src/k8s.io/apiserver/pkg/features/kube_features.go` L84–90 — feature gate definition.
- `pkg/kubeapiserver/options/plugins.go` L113, L190 — plugin registration.
- `pkg/registry/core/pod/rest/authorize.go` L38 — compound authz still on `UnconditionalAuthorizer` (evidence of unfinished work).
- `test/integration/apiserver/conditionalauthorization/*.go` — integration test surface, including commented‑out in‑process‑CEL variants.

## Suggested execution sequence

Do the edits in this order to keep intermediate states of the KEP consistent:

1. Update the Table of Contents and rename headings first (mechanical, prevents anchor drift).
2. Do the cross‑cutting terminology sweep (find/replace of the term table above), noting places that need more than a rename.
3. Rewrite §Core interface changes and §Condition and ConditionsMap data model — this establishes the vocabulary the rest of the KEP uses.
4. Rewrite §Changes to (Self)SubjectAccessReview and §Supporting webhooks through AuthorizationConditionsReview — these are the two big API‑surface sections.
5. Rewrite §Computing a concrete decision from a conditional authorization chain and §AuthorizationConditionsEnforcer admission controller — the runtime wiring.
6. Update §Built‑in CEL conditions evaluator to "deferred / future work".
7. Update §Composite/Union walkthrough YAMLs to the new API shape.
8. Update §Feature availability and version skew, §Authorizer requirements, §Test Plan, §PRR, §TODOs.
9. Skim §Other Kubernetes authorization enforcement points and §Alternatives to remove stale references / add "not yet implemented" markers.

## Verification

After the edit:
- `grep -n "ConditionSet\|ConditionsMode\|ConditionalAuthorizationConfiguration\|conditionsEndpointKubeConfigContext\|ChainedDecisions\|DecisionConditional" kep.md` should be empty except for historical mentions in the Alternatives section.
- Every Go code block should compile‑align to the actual types (spot check by re‑opening the cited files).
- Every YAML example under §Composite / Union Authorizer Support should use `type:` (per‑decision discriminator) and `denyConditions/noOpinionConditions/allowConditions`, never `effect:` on a per‑condition basis or `conditionsType:` at the set level.
- The section rename in the TOC matches the anchor generated from the heading (`Condition and ConditionsMap data model` → `#condition-and-conditionsmap-data-model`).
