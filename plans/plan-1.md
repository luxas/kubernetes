# Implementation Plan: KEP-5681 Conditional Authorization

**KEP:** [KEP-5681: Conditional Authorization](kep-5681.md)
**Target:** Alpha in Kubernetes v1.36
**Feature Gate:** `ConditionalAuthorization`

---

## Executive Summary

This plan describes the implementation of conditional authorization for Kubernetes, where authorizers can return conditions (residual expressions) that depend on the request/stored object. These conditions are enforced during the validating admission phase via the `AuthorizationConditionsEnforcer` admission plugin. This lets authorizers express fine-grained policies spanning both authorization and admission without needing direct access to resource data.

The existing proof-of-concept branch (`luxas:conditional_authz_4`) has already landed significant scaffolding. This plan identifies what exists, what remains to be done, and the order in which changes should be merged.

The 

---

## Phase 0: Preparatory Refactoring (no behavior change)

These changes have zero functional impact and can be merged independently, reducing the size of later PRs.

### 0.1 Refactor `authorizer.Decision` from `int` enum to value struct

Already implemented in branch `authorizer-decision-to-struct`, and on the current branch you're working on.

### 0.2 Add `ConditionsMode` to `Attributes` interface

**Action:** Add `ConditionsMode() ConditionsMode` to the `Attributes` interface and `AttributesRecord` struct. Default is `ConditionsModeNone` (empty string). No caller sets it to anything else yet.

**Files affected:**
- `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/interfaces.go` — add field and method to `AttributesRecord`
- other places which reference the interface, e.g. the caching authorizer and constrained impersonation

---

## Phase 1: Core Conditional Authorization Framework

### 1.1 Feature gate registration

**Current state:** The `ConditionalAuthorization` feature gate already exists in the PoC at alpha, default=false.

**File:** `staging/src/k8s.io/apiserver/pkg/features/kube_features.go`

**Action:** Ensure it's registered correctly:
```go
ConditionalAuthorization: {
    {Version: version.MustParse("1.36"), Default: false, PreRelease: featuregate.Alpha},
},
```

### 1.2 Core types: `Condition`, `ConditionSet`, `ConditionEffect`, `ConditionType`

**Current state:** Already implemented in `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/conditional.go`. Types exist: `Condition`, `ConditionSet`, `ConditionType`, `ConditionEffect` with `ConditionEffectAllow`, `ConditionEffectDenyRequest`, `ConditionEffectDenyNoOpinion`.

**Action — refine naming to match KEP:**
- Rename `ConditionEffectDenyRequest` → `ConditionEffectDeny` (maps to "if true, Deny")
- Rename `ConditionEffectDenyNoOpinion` → `ConditionEffectNoOpinion` (maps to "if true, NoOpinion")
- Add validation to `NewConditionSet()`:
  - Validate `ID` as a Kubernetes label (`(<DNS1123 subdomain>/)[-A-Za-z0-9_.]{1,63}`)
  - Validate `Condition` string is max 10240 bytes
  - Validate `Type` is a valid label key
  - Reject IDs with `k8s.io/` prefix (reserved for Kubernetes)
- Add a maximum number of conditions per set (e.g., 128)

**File:** `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/conditional.go`

### 1.3 Core interfaces: `ConditionsResolver`, `ConditionalAuthorizer`, `ConditionsEnforcer`

**Current state:** Already defined in `conditional.go`:
- `ConditionsResolver` (to be renamed `ConditionSetEvaluator` per KEP)
- `Authorizer` should embed `ConditionSetEvaluator`
- `BuiltinConditionsResolver` should embed `ConditionSetEvaluator` and add a `SupportedConditionsType` method

**Action — improvements over PoC:**
1. Rename `ConditionsResolver` to `ConditionSetEvaluator` to match KEP terminology. The method `ResolveConditions` becomes `EvaluateConditions`.
2. Add `ConditionAttributes` interface refinement — the existing interface already has the right methods. Confirm it matches the KEP's `ConditionData` interface.
3. Add `ConditionsMode` parameter propagation through `Attributes` so authorizers know if/how conditions should be returned.

**Files:**
- `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/conditional.go`

### 1.4 `AuthorizeWithConditionalSupport` function

**Current state:** Already implemented. The function:
1. Creates a `conditionsEnforcer` and stores it in context
2. Calls `authorizer.Authorize()`
3. Validates the conditional response (feature gate, verb restrictions, GVR qualification)
4. Returns `(Decision, string, ConditionsEnforcer, error)`

**Action — improvements over PoC:**
1. Add `deletecollection` to `conditionalAuthorizationVerbs` (KEP specifically calls for it)
2. Add support for connect requests (when the `supportsAuthorizationConditions` function indicates support)
3. Improve error handling: if an authorizer returns `Conditional` but the feature gate is off, fold to `Deny` if there were any `effect=Deny` conditions, otherwise `NoOpinion`
4. Add audit annotation recording when a conditional decision is made

**File:** `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/conditional.go`

### 1.5 `ConditionSet` evaluation logic

**Current state:** `enforceConditions()` in the PoC delegates to `ConditionsResolver.ResolveConditions()`. The evaluation ordering described in the KEP (Deny conditions first, then NoOpinion, then Allow) is implemented by the individual resolver, not centrally.

**Action:** Implement the canonical evaluation algorithm from the KEP as a standalone function `EvaluateConditionSet(conditions []Condition, evaluator func(Condition) (bool, error)) (Decision, string, error)`:

1. Evaluate all `effect=Deny` conditions. If any is `true`, return `Deny`. If any errors, return error (FailureMode determines Deny vs NoOpinion).
2. If all Deny conditions are `false`, evaluate `effect=NoOpinion` conditions. If any is `true`, return `NoOpinion`. If any errors, return `NoOpinion` (fail closed) + error for logging.
3. If all NoOpinion conditions are `false`, evaluate `effect=Allow` conditions. If any is `true`, return `Allow`. Errors are ignored.
4. If no Allow condition is `true`, return `NoOpinion`.

**File:** `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/conditionset_evaluation.go` (new)

### 1.6 `conditionsEnforcer.EnforceConditions` chain evaluation

**Current state:** Already implemented with the ordered ConditionSet walk + lazy authorizer chain evaluation.

**Action — confirm correctness against KEP semantics:**
1. The precomputed ConditionSets are evaluated in order. If a set evaluates to `Allow` or `Deny`, short-circuit.
2. If `NoOpinion`, continue to next set. If a set is `UnconditionallyAllowed`, return Allow.
3. After exhausting precomputed sets, lazily evaluate the remaining authorizer chain.
4. Each lazily-evaluated authorizer can itself return conditional responses, which must be recursively enforced.

**File:** `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/conditional.go`

---

## Phase 2: Union Authorizer Conditional Support

### 2.1 Union authorizer changes

**Current state:** The union authorizer in `staging/src/k8s.io/apiserver/pkg/authorization/union/union.go` already has conditional support in the PoC:
- On `DecisionConditionalAllow`: registers remaining authorizers via `RegisterAuthorizerChainAfterConditionalResponse` and short-circuits
- On `DecisionConditionalDeny`: continues to next authorizer. If a later authorizer returns `Allow`, calls `UnconditionalAllowAfterConditionalDeny`

**Action — verify and test:**
1. Confirm the lazy evaluation semantics match the KEP: when a conditional allow is seen, the rest of the chain is saved for later (not eagerly evaluated).
2. Confirm that a `ConditionalDeny` followed by a concrete `Allow` yields `ConditionalAllow` (the deny conditions still need evaluation).
3. Confirm that a `ConditionalDeny` followed by another `ConditionalAllow` works correctly (both sets of conditions need evaluation).
4. Add comprehensive unit tests for all chain decision combinations described in the KEP's "authorizer chain computation" diagram.

**File:** `staging/src/k8s.io/apiserver/pkg/authorization/union/union.go`

**Test file:** `staging/src/k8s.io/apiserver/pkg/authorization/union/union_test.go`

---

## Phase 3: `WithAuthorization` HTTP Filter Integration

### 3.1 Modify the `WithAuthorization` filter

**Current state:** The filter in `staging/src/k8s.io/apiserver/pkg/endpoints/filters/authorization.go` already calls `AuthorizeWithConditionalSupport` when the feature gate is enabled, and stores the `ConditionsEnforcer` in the request context on `DecisionConditionalAllow`.

**Action — improvements:**
1. Add the `supportsAuthorizationConditions func(ctx context.Context) bool` parameter to `WithAuthorization`, so that connect requests can be conditionally authorized.
2. Fail closed if a conditional response is received for a request that doesn't support conditions.
3. Add audit annotations: `authorization.k8s.io/conditional=true` when a conditional decision is propagated.
4. Add metrics: `apiserver_authorization_conditional_decisions_total` counter with labels for `decision` (allow/deny) and `authorizer_type`.

**Files:**
- `staging/src/k8s.io/apiserver/pkg/endpoints/filters/authorization.go`
- `staging/src/k8s.io/apiserver/pkg/endpoints/filters/authorization_test.go`

### 3.2 Wire up `supportsAuthorizationConditions` for kube-apiserver

**Action:** In the kube-apiserver's generic API server setup, provide a `supportsAuthorizationConditions` function that returns `true` when:
- The verb is `create`, `update`, `patch`, `delete`, `deletecollection` and the GVR is served locally
- The request maps to a connect handler (e.g., `pods/exec`, `pods/attach`, `pods/portforward`)
- The GVR belongs to an aggregated API server (conditions propagated via SAR)

**File:** `staging/src/k8s.io/apiserver/pkg/server/config.go` or `pkg/controlplane/apiserver/server.go`

---

## Phase 4: `AuthorizationConditionsEnforcer` Admission Plugin

### 4.1 Admission plugin implementation

**Current state:** The admission plugin already exists at `staging/src/k8s.io/apiserver/pkg/admission/plugin/authorizer/conditionsenforcer/`. It retrieves the `ConditionsEnforcer` from context and calls `EnforceConditions()`.

**Action — improvements:**
1. Ensure the plugin is registered as the **first** validating admission plugin.
2. Wire the `SetExternalKubeClientSet` to initialize the CEL conditions resolver correctly.
3. Add `Handles()` gating: return `true` only when `ConditionalAuthorization` feature gate is enabled.
4. Add AdmissionOptions validation: if the `ConditionalAuthorization` feature gate is enabled but the `AuthorizationConditionsEnforcer` admission plugin is disabled, error during API server startup.
5. Add metrics for conditions enforcement latency and outcomes.

**Files:**
- `staging/src/k8s.io/apiserver/pkg/admission/plugin/authorizer/conditionsenforcer/enforcer.go`
- `staging/src/k8s.io/apiserver/pkg/server/options/admission.go` — validation

### 4.2 Enable the admission plugin by default (when feature gate is on)

**Action:** Register the plugin in the default admission plugin chain. The plugin's `Handles()` method returns `false` when the feature gate is off, so it's a no-op in that case.

**File:** `staging/src/k8s.io/apiserver/pkg/admission/plugin/authorizer/conditionsenforcer/enforcer.go` (init registration)

---

## Phase 5: Built-in CEL Conditions Evaluator

### 5.1 CEL conditions environment

**Action:** Create a CEL-based `BuiltinConditionsResolver` that can evaluate conditions of type `k8s.io/cel` (or `k8s.io/authorization-cel`, name TBD).

The CEL environment should be similar to `ValidatingAdmissionPolicy`, providing:
- `object` — the new/request object
- `oldObject` — the existing object (for updates/deletes)
- `request` — request metadata (user, verb, resource, etc.)
- `params` — operation options

Reuse the existing CEL compilation and evaluation infrastructure from `staging/src/k8s.io/apiserver/pkg/cel/`.

**Key implementation details:**
- Parse CEL expressions from the `Condition.Condition` string field
- Compile and evaluate against the `ConditionAttributes` data
- Cache compiled programs where possible (conditions from cached SAR responses will be re-evaluated)
- Respect CEL cost limits to prevent DoS
- Support the `authorizer` CEL function for secondary authorization checks

**Files:**
- `staging/src/k8s.io/apiserver/pkg/authorization/cel/conditions_evaluator.go` (new)
- `staging/src/k8s.io/apiserver/pkg/authorization/cel/conditions_evaluator_test.go` (new)

### 5.2 Register CEL evaluator in the admission plugin

**Action:** When the `AuthorizationConditionsEnforcer` admission plugin initializes, create the CEL conditions evaluator and register it as a `BuiltinConditionsResolver`. Pass it to the `ConditionsEnforcer` via `WithBuiltinConditionsResolvers()`.

**Current state:** The PoC already does this in `SetExternalKubeClientSet`, building an OpenAPI-aware type resolver.

**File:** `staging/src/k8s.io/apiserver/pkg/admission/plugin/authorizer/conditionsenforcer/enforcer.go`

---

## Phase 6: Webhook Authorizer Conditional Support

### 6.1 Webhook authorizer: return conditions from SAR

**Current state:** The webhook authorizer in `staging/src/k8s.io/apiserver/plugin/pkg/authorizer/webhook/webhook.go` already has PoC support for parsing `ConditionsChain` from `SubjectAccessReviewStatus`.

**Action — complete the implementation:**
1. Set `ConditionsMode` in the SAR spec when calling the webhook (only when the feature gate is enabled and the caller indicated support)
2. Parse `status.conditionalDecisionChain` from the webhook response
3. Convert the API types to internal `ConditionSet` objects
4. Return the appropriate `DecisionConditional*` via `NewConditionalDecision`
5. Cache conditional responses along with their conditions (same TTL semantics)
6. Implement `ConditionalAuthorizer` interface (add `FailureMode()` and `EvaluateConditions()`/`ResolveConditions()`)

**File:** `staging/src/k8s.io/apiserver/plugin/pkg/authorizer/webhook/webhook.go`

### 6.2 `AuthorizationConditionsReview` webhook client

**Current state:** The PoC has `authorizationConditionsClient` struct in the webhook package.

**Action — complete the implementation:**
1. The webhook authorizer's `ResolveConditions`/`EvaluateConditions` method should:
   - First check if any builtin evaluator can handle all condition types
   - If not, send an `AuthorizationConditionsReview` webhook to the authorizer
2. Read the `conditionsEndpointKubeConfigContext` from `AuthorizationConfiguration` to determine the webhook URL
3. Build the `AuthorizationConditionsReview` request with the condition set + condition data (object, oldObject, etc.)
4. Parse the response and return a concrete decision

**Files:**
- `staging/src/k8s.io/apiserver/plugin/pkg/authorizer/webhook/webhook.go`
- `staging/src/k8s.io/apiserver/plugin/pkg/authorizer/webhook/conditions_client.go` (new or existing)

### 6.3 `AuthorizationConfiguration` webhook config extension

**Action:** Add the following fields to `WebhookConfiguration`:
- `conditionsEndpointKubeConfigContext string` — the kubeconfig context for the `AuthorizationConditionsReview` endpoint
- `authorizationConditionsReviewVersion string` — the API version to use (e.g., `v1alpha1`)

Add validation: if `conditionsEndpointKubeConfigContext` is set, `authorizationConditionsReviewVersion` must also be set.

**Files:**
- `staging/src/k8s.io/apiserver/pkg/apis/apiserver/types.go`
- `staging/src/k8s.io/apiserver/pkg/apis/apiserver/v1/types.go`
- `staging/src/k8s.io/apiserver/pkg/apis/apiserver/validation/validation.go`

---

## Phase 7: API Changes — `SubjectAccessReview` and `AuthorizationConditionsReview`

### 7.1 `SubjectAccessReview` API changes

**Action — extend `SubjectAccessReviewSpec`:**
```go
type SubjectAccessReviewSpec struct {
    // existing fields...
    ConditionalAuthorization *ConditionalAuthorizationConfiguration `json:"conditionalAuthorization,omitempty"`
}

type ConditionalAuthorizationConfiguration struct {
    Mode ConditionsMode `json:"mode,omitempty"`
}
```

**Action — extend `SubjectAccessReviewStatus`:**
```go
type SubjectAccessReviewStatus struct {
    // existing fields...
    ConditionalDecisionChain []SubjectAccessReviewAuthorizationDecision `json:"conditionalDecisionChain,omitempty"`
}
```

Add the `SubjectAccessReviewAuthorizationDecision`, `SubjectAccessReviewCondition`, `SubjectAccessReviewConditionEffect` types as specified in the KEP.

**Files:**
- `staging/src/k8s.io/api/authorization/v1/types.go`
- `staging/src/k8s.io/api/authorization/v1alpha1/types.go` (new group version for the new fields, or add to v1 behind feature gate)
- `staging/src/k8s.io/api/authorization/v1/zz_generated.deepcopy.go` (regenerate)
- API conversion, defaulting, validation in `pkg/apis/authorization/`

### 7.2 SAR endpoint: return conditions in the response

**Action:** Modify the `SubjectAccessReview` request handler to:
1. Check if `spec.conditionalAuthorization.mode` is set
2. If so, set `ConditionsMode` on the authorization `Attributes`
3. Call `AuthorizeWithConditionalSupport` instead of plain `Authorize`
4. If the result is conditional, populate `status.conditionalDecisionChain` using `conditionsEnforcer.OrderedConditionSets()`
5. Set `status.allowed=false` and `status.denied=false` for conditional responses

**Files:**
- `pkg/registry/authorization/subjectaccessreview/rest.go`
- `pkg/registry/authorization/selfsubjectaccessreview/rest.go`
- `pkg/registry/authorization/localsubjectaccessreview/rest.go`

### 7.3 `AuthorizationConditionsReview` API

**Action:** Create a new API type in `authorization.k8s.io/v1alpha1`:

```go
type AuthorizationConditionsReview struct {
    metav1.TypeMeta
    Request  *AuthorizationConditionsRequest  `json:"request,omitempty"`
    Response *AuthorizationConditionsResponse `json:"response,omitempty"`
}
```

With `Request` containing `ConditionalDecisionChain` + object/metadata fields, and `Response` containing `Allowed`, `Denied`, `Reason`, `EvaluationError`, and optionally `ConditionalDecisionChain` for re-evaluation.

**Implementation:**
- This API is not stored in etcd; it's a virtual resource like SubjectAccessReview
- kube-apiserver must serve it (since aggregated API servers call kube-apiserver as a webhook)
- The handler routes the evaluation request to the appropriate authorizer based on `authorizerName`

**Files:**
- `staging/src/k8s.io/api/authorization/v1alpha1/types.go`
- `staging/src/k8s.io/api/authorization/v1alpha1/register.go`
- `pkg/apis/authorization/types.go` (internal types)
- `pkg/registry/authorization/authorizationconditionsreview/` (new package)

---

## Phase 8: Compound Authorization Integration

### 8.1 Compound authorization for connectible resources

**Current state:** `pkg/registry/core/pod/rest/authorize.go` has `ensureAuthorizedForVerb` for compound checks on pod exec/attach.

**Action:** Make both the initial (`get`) and compound (`create`) authorization checks conditional-aware. Pass `operation=CONNECT`, `object=<connect-data>` (e.g., `PodExecOptions`), `oldObject=nil`, `options=nil` as condition data.

**Files:**
- `pkg/registry/core/pod/rest/authorize.go`

### 8.2 Compound authorization for update/patch → create

**Current state:** `staging/src/k8s.io/apiserver/pkg/endpoints/handlers/update.go` performs a secondary authorization check when an update turns into a create.

**Action:** Make this compound check conditional-aware. The conditions from the original authorization should carry over and be re-evaluated with the actual operation (create).

**File:** `staging/src/k8s.io/apiserver/pkg/endpoints/handlers/update.go`

---

## Phase 9: Testing

### 9.1 Unit tests

- `authorizer/conditional.go`: Test all `NewConditionalDecision` paths, `ConditionSet` evaluation logic, error handling, feature gate behavior
- `authorizer/conditionset_evaluation.go`: Test the canonical evaluation algorithm with all combinations of Deny/NoOpinion/Allow effects, true/false/error outcomes
- `union/union.go`: Test all chain decision combinations (ConditionalAllow, ConditionalDeny, mixed, lazy evaluation)
- `webhook/webhook.go`: Test parsing conditional SAR responses, caching, `AuthorizationConditionsReview` client
- `filters/authorization.go`: Test the filter with conditional decisions, audit annotations, metrics
- `conditionsenforcer/`: Test the admission plugin with conditional contexts, CEL evaluation

### 9.2 Integration tests

**Location:** `test/integration/apiserver/cel/conditionalauthz/` (new)

Test scenarios:
1. Feature gate enabled: webhook authorizer returns conditional allow → object satisfying conditions is accepted → object violating conditions is rejected
2. Feature gate enabled: webhook authorizer returns conditional deny → request proceeds if deny condition is false
3. Feature gate disabled: conditional responses are folded to concrete decisions
4. Multiple authorizers in chain: first returns conditional, second returns Allow/Deny/Conditional
5. CEL builtin evaluator: `k8s.io/cel` condition type evaluated in-process
6. `AuthorizationConditionsReview`: opaque condition type evaluated via webhook
7. SAR endpoint returns conditions when `conditionalAuthorization.mode` is set
8. `deletecollection` with conditions: each object in the collection is evaluated
9. Compound authorization: update→create with conditions

### 9.3 E2E tests

Test scenarios:
1. End-to-end with a real webhook authorizer returning CEL conditions
2. `kubectl auth can-i` shows conditional authorization information
3. Aggregated API server scenario: conditions propagated from kube-apiserver to aggregated server and enforced there

---

## Phase 10: Observability and Documentation

### 10.1 Metrics

- `apiserver_authorization_conditional_decisions_total{decision, authorizer_type}` — counter for conditional decisions at authorization time
- `apiserver_authorization_conditions_enforcement_duration_seconds{authorizer_name}` — histogram for conditions enforcement latency
- `apiserver_authorization_conditions_enforcement_total{decision, authorizer_name}` — counter for enforcement outcomes

### 10.2 Audit annotations

- `authorization.k8s.io/conditional`: set to `"true"` when a request proceeds with conditional authorization
- `authorization.k8s.io/conditions-enforced`: set to the enforcement outcome (`allowed`/`denied`/`noopinion`)

### 10.3 Documentation

- Update `kube-apiserver` flag documentation for `--authorization-config`
- Document `AuthorizationConditionsReview` API
- Document `SubjectAccessReview` condition fields
- Write a guide for webhook authorizer implementors on how to return and evaluate conditions

---

## Implementation Order and PR Strategy

The PRs should be merged in this order to minimize risk:

| PR # | Phase | Description | Depends on |
|------|-------|-------------|------------|
| 1 | 0.2 | Add `ConditionsMode` to `Attributes` interface | — |
| 2 | 1.1–1.6 | Core conditional authorization framework (types, interfaces, evaluation logic, feature gate) | PR 1 |
| 3 | 2.1 | Union authorizer conditional support | PR 2 |
| 4 | 3.1–3.2 | `WithAuthorization` filter integration | PR 2, 3 |
| 5 | 4.1–4.2 | `AuthorizationConditionsEnforcer` admission plugin | PR 4 |
| 6 | 5.1–5.2 | Built-in CEL conditions evaluator | PR 5 |
| 7 | 6.3 | `AuthorizationConfiguration` webhook config extension | PR 2 |
| 8 | 6.1–6.2 | Webhook authorizer conditional support | PR 6, 7 |
| 9 | 7.1–7.2 | `SubjectAccessReview` API changes + SAR endpoint | PR 8 |
| 10 | 7.3 | `AuthorizationConditionsReview` API | PR 8 |
| 11 | 8.1–8.2 | Compound authorization integration | PR 4 |
| 12 | 9.1 | Unit tests | PR 2–11 |
| 13 | 9.2 | Integration tests | PR 12 |
| 14 | 9.3 | E2E tests | PR 13 |
| 15 | 10 | Metrics, audit annotations, documentation | PR 5, 8 |
| 16 | 0.1 | Decision struct migration (can be done in parallel, large mechanical change) | — |

**Note:** PR 16 (Decision struct migration) is large but mechanical and can proceed in parallel with the rest. It's not strictly required for alpha but is desirable for API cleanliness.

---

## Open Questions from KEP TODOs

1. **Condition type:** Go with per-set (instead of per-condition) for the implementation.

2. **NodeRestriction integration:** The KEP mentions the Node authorizer could be modelled using conditional authorization. This is a Beta goal, not Alpha.

3. **Constrained Impersonation integration:** The KEP sketches how impersonation could use conditions. This is a separate KEP (KEP-5284) that builds on this one. Not in scope for alpha.

4. **Binary CEL AST:** The KEP mentions an optimized mode for binary-encoded CEL ASTs. Defer to post-alpha.

5. **`ConditionsMode` honored by authorizer:** For alpha, `ConditionsModeNone` (empty) means "no conditions". The authorizer should fold to `NoOpinion`/`Deny` in this case. `HumanReadable` and `Optimized` modes are advisory and can be ignored by the authorizer.

6. **Maximum conditions per set:** The KEP leaves this as a TODO. **Recommendation:** Start with 64 conditions per set and 16 sets in the chain.
