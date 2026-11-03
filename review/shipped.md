# What shipped: KEP-5681 Conditional Authorization on HEAD (Stage 1)

HEAD `08974670a59` = `origin/master` `c5bdf2219ee` (2026-11-02) + PR #143024 (`f410163f598`,
unmerged) + review docs. Feature gate `ConditionalAuthorization`: Alpha, default off, 1.38.

This file is the synthesis. The detailed inventories are the appendices in `review/shipped/`:

| Appendix | Content |
|---|---|
| `A-prs-0-1-2-2.5-wantsauthorizer.md` | Landed delta of #138801, #137204, #137513, #140916, #140715 |
| `B-prs-3-4-5-validation-oldobject.md` | Landed delta of #140714, #142493, #137633, #141959, #143024 (one correction noted at its top) |
| `C-symbols-and-callsites.md` | Every exported symbol of the new packages with non-test callers; census of all 34 `Authorize`-family call sites vs the KEP list |
| `D-tests-gates-api.md` | Every test function touching the feature; all 20 hand-written gate sites + API tags; verbatim API types and the validation rules per layer |

Everything below cites HEAD `path:line` unless marked "at merge".

## 1. Architecture as built

```
request ──► WithConditionsAwareAuthorization (filters/authorization.go:135)        [kube-apiserver only, gate on,
             │ classifier(attrs)? ──yes──► Authorizer.ConditionsAwareAuthorize       classifier set, enforcer plugin on;
             │                              │ Allow ──────────────────────────► ctx    otherwise legacy WithAuthorization
             │                              │ PossibleDecisions∋Allow ───────► ctx    which, gate on, stores an Allow
             │                              │ else ─► 403 / 500                        decision in ctx (:101-110)]
             └─no──► Authorize (lifted FromParts) ─────────────────────────────► ctx
                                                                                  │
admission chain … MutatingAdmissionPolicy, MutatingWebhook, ValidatingAdmissionPolicy,
   AuthorizationConditionsEnforcer (conditionsenforcer.go; position 37/40; default-on; Handles()=gate)
     ctx decision: Allow → ok | Deny/NoOpinion/Allow-impossible → 500 | ConditionsMap/Union →
       Authorizer.EvaluateConditions(ctx, decision, VersionedAttributes(a, a.GetKind(), o))
       result guarded to PossibleDecisions, else Deny "failed closed" (:145-150)
   ValidatingAdmissionWebhook, ResourceQuota, AlwaysDeny
```

Authorizer stack (all implement `authorizer.Authorizer`): `reloadableAuthorizerResolver` →
`instrumentedAuthorizer` → `union` (named `NamedAuthorizer`s; superuser is
`system-privileged-group.authorizer.kubernetes.io`) → {RBAC, Node, ABAC, AlwaysAllow/Deny,
privileged-groups: all lift `Authorize` via `ConditionsAwareDecisionFromParts`; **webhook**: the only
authorizer that can return or evaluate conditions}.

Webhook `ConditionsAwareAuthorize` (`webhook.go:275+`): advertises
`spec.authorizationOptions.handledDecisionTypes = [Deny,Allow,NoOpinion,ConditionsMap,Union]` only
when an ACR reviewer is configured (gate on + `webhook.conditionsReview` in the authorization config;
`reload.go:189`); validates the response with `CombinedValidateSubjectAccessReviewCreate`; decodes
`status.conditionalDecision` via `ToAuthorizerConditionsAwareDecision`; fails closed per
`failurePolicy` (NoOpinion or Deny).

Webhook `EvaluateConditions` (`webhook.go:429+`), with #143024: (1) `tryEvaluateUsingBuiltins` runs
`PartiallyEvaluateConditionsAwareDecision` with the in-process CEL evaluator for conditions of type
`authorizer.kubernetes.io/cel`; builtin errors are treated as unevaluatable and deferred to the
webhook; (2) if the refined decision is unconditional, return it; (3) else send an
`AuthorizationConditionsReview` (v1alpha1) with the refined decision and an `admissionv1.AdmissionRequest`
(fresh UID) to the ACR endpoint, validate, check UID echo and `PossibleDecisions` of the **refined**
decision, fail closed otherwise.

SAR/SelfSAR/LocalSAR registries (`pkg/registry/authorization/*/rest.go`): gate off → clear
`spec.authorizationOptions`, legacy path. Gate on and client's `handledDecisionTypes` ⊇ the five
types → `ConditionsAwareAuthorize`, result encoded into `status.conditionalDecision`
(`util/helpers.go:265`); options present but not ⊇ {Allow,Deny,NoOpinion} → 400.

`authorization.k8s.io/v1alpha1` / `AuthorizationConditionsReview` is **a webhook wire type, not a served
resource**: registered in schemes and client-go, no REST storage (`storage_authorization.go:44-46`).

## 2. Per-PR one-liners (details in appendices A and B)

| PR | What landed | Gate checks added | Visible with gate off |
|---|---|---|---|
| #138801 | `UnconditionalAuthorizer` split out; ~90 secondary-check sites narrowed; `WantsAuthorizer` renamed to `WantsUnconditionalAuthorizer` | none | Out-of-tree plugins implementing `SetAuthorizer` silently stopped getting an authorizer until #140916 |
| #137204 | `Authorizer` gains `ConditionsAwareAuthorize` + `EvaluateConditions`; first `ConditionsAwareDecision` (3 variants); boilerplate on every authorizer; metrics label `conditional` | none | Go API break for out-of-tree `Authorizer` impls |
| #137513 | 5-variant `ConditionsAwareDecision`, `Condition`, `ConditionsMap` (+validation, 128 cap), `ConditionsAwareDecisionUnion`, `ConditionEvaluationResult`, `ConditionsMap.Evaluate`, `PartiallyEvaluateConditionsAwareDecision`; union authorizer rewritten on `NamedAuthorizer`, `union.New` returns error; `admission.Operation` becomes alias | none | **Union `Authorize` prefixes aggregated NoOpinion reasons with `<name>: `** (`union.go:88-89`; short-circuit Allow/Deny reason stays unprefixed, `:93`). Changes 403 messages. `union.New` signature |
| #140916 | Re-adds `initializer.WantsAuthorizer`; `initializer.New` takes `Authorizer` | none | restores 1.36 behaviour |
| #140715 | `UnconditionalPartsOrError` / `UnconditionalPartsOrFailClosed`; condition ID/type must be domain-prefixed; `MaxConditionBytes=10240`, `MaxConditionDescriptionBytes=1024`; union names DNS-1123; built-ins renamed `*.authorizer.kubernetes.io`; klog warning for user names under `kubernetes.io`/`k8s.io` | none | log warning; renamed prefixes in 403 reasons |
| #140714 | SAR validation moved to `k8s.io/apiserver/pkg/apis/authorization/validation`, rewritten on v1 types; DV for authorization/v1; five k/k exports removed. No defaults moved despite title | none | Go API break |
| #142493 | `(*VersionedAttributes).GetOldObject()` returns the versioned old object | none | ungated behaviour change for any caller holding a `*VersionedAttributes` |
| #137633 | API: SAR `spec.authorizationOptions`, `status.conditionalDecision`, `Condition`, `ConditionsMap`, `ConditionsAwareDecision{Type}`, `NamedConditionsAwareDecision`, `UnconditionalDecision`; v1alpha1 `AuthorizationConditionsReview`; `AuthorizationConfiguration.webhook.conditionsReview`; encoding, validation (handwritten + DV), v1beta1 fold-down; webhook `ConditionsAwareAuthorize`/`EvaluateConditions`; CEL matchConditions `request.authorizationOptions`; the gate | 11 sites | **Webhook legacy `Authorize` fails closed (500 at the filter) on an unrequested `conditionalDecision`**; `webhook.New`/`NewFromInterface` signatures |
| #141959 | `WithConditionsAwareAuthorization`, request classifier, request-context decision, `AuthorizationConditionsEnforcer`, SAR conditional responses, metrics/audit, 3 integration test files + VAP ordering | 9 sites | Enforcer plugin default-on everywhere (inert); `NewREST` signatures; exported audit constants |
| #143024 (open) | `BuiltinConditionsEvaluator[Builder]`, CEL evaluator in `admission/plugin/cel/authorization_conditions.go`, webhook builtin-first evaluation, reactivated integration rows | none new | signatures only |

## 3. Facts every later stage must know

1. **Fail-closed for conditions-unaware consumers is inline in the webhook, not via
   `UnconditionalPartsOrFailClosed`.** That method has zero production callers
   (`C` §1). `webhook.go:264-267` returns `FailureDecision()` + error for an unrequested
   `conditionalDecision`; at the legacy filter that error turns into a 500 (`authorization.go:115-118`).
2. **Only two call sites carry a conditional decision through a request**: filter
   `authorization.go:164` and enforcer `conditionsenforcer.go:146`. The three SAR registries return
   it to the client. The other 29 `Authorize` callers are unconditional by construction and ungated
   (`C` §2.2). Notable: create-on-update (`update.go:268`), pod connect (`authorize.go:55`), kubelet
   (`server.go:408`) are unconditional-only although the KEP said the last two "would be
   conditions-aware".
3. **Conditional evaluation requires three switches**: gate on, kube-apiserver's classifier
   (`pkg/controlplane/apiserver/config.go:299`: resource request, verb ∈ {create, update, patch,
   delete, deletecollection}, not admission-excluded), and the enforcer plugin enabled
   (`server/config.go:1077`). Disabling the plugin disables conditional authz with a warning.
4. **In-process CEL (#143024) exists only when `webhook.conditionsReview` is configured**
   (`reload.go:188-210`); delegated/aggregated apiservers never get a builtin evaluator and have no
   classifier, but do receive an ACR client that points at a resource kube-apiserver does not serve.
5. **Two validation layers with different limits**: DV allows 128 per list and ID uniqueness per
   list; the in-process constructor enforces 128 total and uniqueness across lists
   (`conditionsmap.go:154,191`). Webhook responses pass through the constructor, so they fail closed
   rather than being rejected (`D` §3.4). Reserved `*.k8s.io` / `*.kubernetes.io` IDs/types are
   documented but not enforced anywhere.
6. **Partial evaluation precedence** (`evaluate.go:121-195`): Deny > NoOpinion > Allow; within an
   effect true > error > unevaluatable > false; a true Deny gives Deny with nil error; a Deny-effect
   error gives Deny + errors; NoOpinion/Allow-effect errors give NoOpinion + errors.
7. **Union builder semantics** (`conditionsunion.go`): `Add` is a no-op after an unconditional
   Allow/Deny leaf; empty/duplicate/non-DNS-1123 names make `ToDecision` fail closed; a union whose
   `PossibleDecisions` is a singleton folds to that unconditional decision.
8. **`ConditionsData` is `admission.Attributes`-shaped**, passed as `VersionedAttributes`
   so `GetObject`/`GetOldObject` are in the request's external version (`interfaces.go:313`,
   #142493, `crd_conversion_test`/`hpa_conversion_test`).
9. **Integration coverage** (`D` §1.1): 34 table rows × up to 3 variants (webhook-only,
   in-process-only, in-process-fails-then-webhook), 24-case SAR matrix, VAP ordering, CRD and HPA
   conversion. Missing: DELETE, PATCH, apply, subresources, `failurePolicy: Deny`, top-level `Union`
   from a webhook, update-to-create (rows commented out at
   `conditionalauthorization_test.go:653-835` with a TODO). All need etcd.
10. **Doc/code nits already spotted** (collect in Stage 2): `context.go:102` plural name,
    `validation.go:88-89` wrong doc, `validation.go:307` stale line, `evaluate.go:70` plural
    `ConditionsEvaluationResultUnevaluatable`, `conditionsunion.go:131` doc starts with type name,
    `v1/util.go` doc on `UnconditionalAuthorizationDecisionTypes`, stale comment
    `conditionalauthorization_test.go:99`, `token.go:75` holds an `Authorizer` but only calls `Authorize`.
11. Commit `60a11890371` (not part of the series) changed `webhook.New` to take a compiled `Matcher`;
    #137633's signatures as merged are not the HEAD ones. #143024 is written against the HEAD form.

## 4. Questions raised by Stage 1 (to be settled in Stages 2-4, not here)

- Q1 (code/KEP): unrequested conditional webhook answer → 500 rather than 403 at the legacy filter. Intended?
- Q2 (code/KEP): in-process CEL only with an ACR endpoint configured; a webhook wanting CEL-only has no path.
- Q3 (code): CEL expression recompiled on every `EvaluateCondition`; cost budget per condition (TODO at
  `authorization_conditions.go:52`).
- Q4 (code): `PossibleDecisions` check in `webhookEvaluateConditions` runs against the refined decision;
  the doc says FailureDecision may drop from Deny to NoOpinion when all Deny conditions evaluated false.
- Q5 (KEP): the KEP's call-site list lacks 7 sites present in code (`C` §2.4) and has one wrong path.
- Q6 (code): generic apiservers get an ACR client but no classifier; the ACR kind is not served by kube-apiserver.
- Q7 (code): ACR `request.admissionRequest` is `+k8s:required` with JSON `omitempty`, contents unvalidated
  (`validation.go:281-282`).
- Q8 (code): secondary `create` check on update/patch-to-create is unconditional while the primary decision
  may be conditional (`update.go:268`).
- Q9 (test): the reason prefix asymmetry in the SAR matrix (`conditionalauthorization_test.go:1212` vs `:1256`).

## 5. Not determined in Stage 1

- Nothing was built or executed (no Go toolchain in the review sandbox). Stage 3b will add a toolchain
  in a scratch worktree for non-vacuity checks.
- Whether a misbehaving webhook can pass a conditional decision through `ValidateSubjectAccessReviewStatus`
  when `handlesConditional=false` (`webhook.go:327`); Stage 2 #137633 reviewer B must read that path.
- Character-level equivalence of `k8s-prefixed-label-key` (DV) vs `IsDomainPrefixedKey` (constructor).
- Out-of-tree and aggregated apiservers.
