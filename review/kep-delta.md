# KEP-5681 delta: `review/kep.md` vs HEAD (Stage 3c)

HEAD `57a6904a21a` (= origin/master `c5bdf2219ee` + #143024 `f410163f598` + review docs). This file is the
only source of truth for the Stage 5 rewrite of `review/kep.md`. Every code citation is HEAD `path:line`.
Evidence is cited as `pr-<n>.md:<line>` (a Stage 2 follow-up row that itself names the thread) or
"not discussed". Each Stage 2 lead was checked against HEAD before it was used here.

Path abbreviations:

| Abbrev | Path |
|---|---|
| `AZ/` | `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/` |
| `UN` | `staging/src/k8s.io/apiserver/pkg/authorization/union/union.go` |
| `WH` | `staging/src/k8s.io/apiserver/plugin/pkg/authorizer/webhook/webhook.go` |
| `FLT` | `staging/src/k8s.io/apiserver/pkg/endpoints/filters/authorization.go` |
| `CTX` | `staging/src/k8s.io/apiserver/pkg/endpoints/request/context.go` |
| `ENF` | `staging/src/k8s.io/apiserver/pkg/admission/plugin/authorizer/conditionsenforcer/conditionsenforcer.go` |
| `CEL` | `staging/src/k8s.io/apiserver/pkg/admission/plugin/cel/authorization_conditions.go` (#143024, unmerged) |
| `ENC` | `staging/src/k8s.io/apiserver/pkg/apis/authorization/v1/encoding.go` |
| `VAL` | `staging/src/k8s.io/apiserver/pkg/apis/authorization/validation/validation.go` |
| `APIv1` | `staging/src/k8s.io/api/authorization/v1/types.go` (`util.go` = same dir) |
| `APIa1` | `staging/src/k8s.io/api/authorization/v1alpha1/types.go` |
| `CFGv1` | `staging/src/k8s.io/apiserver/pkg/apis/apiserver/v1/types.go` |
| `SCFG` | `staging/src/k8s.io/apiserver/pkg/server/config.go` |
| `SADM` | `staging/src/k8s.io/apiserver/pkg/server/options/admission.go` |
| `CP` | `pkg/controlplane/apiserver/config.go` |
| `RL` | `pkg/kubeapiserver/authorizer/reload.go` |
| `PLG` | `pkg/kubeapiserver/options/plugins.go` |
| `IT` | `test/integration/apiserver/conditionalauthorization/conditionalauthorization_test.go` |

---

# PART 1: Terminology (KEP term → shipped name)

Stage 5 applies this table globally, then hand-checks each hit. "—" means the concept was removed.

| # | KEP term (kep.md line) | Shipped name | HEAD definition |
|---|---|---|---|
| T1 | `Decision` struct with private fields (566, 640-646) | `Decision int` (Deny=0, Allow, NoOpinion) for unconditional decisions, plus the separate struct `ConditionsAwareDecision` | `AZ/interfaces.go:231-242`; `AZ/conditions.go:60-68` |
| T2 | `Authorizer.Authorize(ctx, a) (Decision, error)` (571) | `UnconditionalAuthorizer.Authorize(ctx, a) (Decision, string, error)`, unchanged from 1.36 | `AZ/interfaces.go:86-88` |
| T3 | single `Authorizer` interface embedding `ConditionSetEvaluator` (568-579) | `Authorizer` = `UnconditionalAuthorizer` + `ConditionsAwareAuthorize` + `EvaluateConditions` | `AZ/interfaces.go:103-124` |
| T4 | `ConditionSetEvaluator.EvaluateConditions(ctx, *ConditionSet, ConditionData) (Decision, error)` (581-588) | `Authorizer.EvaluateConditions(ctx, ConditionsAwareDecision, ConditionsData) (Decision, string, error)` | `AZ/interfaces.go:123` |
| T5 | (none) | `ConditionsAwareAuthorize(ctx, a) ConditionsAwareDecision` | `AZ/interfaces.go:114` |
| T6 | `ConditionsMode` / `ConditionsModeNone` / `HumanReadable` / `Optimized`; `Attributes.ConditionsMode()` (589-610) | — in Go: the caller signals readiness by **which method** it calls (and statically by which interface it holds). On the wire: `AuthorizationOptions.handledDecisionTypes`. There is no presentation mode | `AZ/interfaces.go:109-113`; `APIv1:412-429`; `WH:287-292` |
| T7 | `DecisionAllow/Deny/NoOpinion(reason) Decision` (613-616) | `ConditionsAwareDecisionAllow/Deny/NoOpinion(reason, err)`; `ConditionsAwareDecisionFromParts(Decision, reason, err)`. Legacy constants `DecisionAllow` etc. stay | `AZ/conditions.go:71,82,91,102`; `AZ/interfaces.go:233-242` |
| T8 | `DecisionConditional(*ConditionSet)` (617) | `ConditionsAwareDecisionConditionsMap(deny, noOpinion, allow []Condition)` | `AZ/conditionsmap.go:138` |
| T9 | `ChainedDecisions([]Decision, authorizerChain...)` with lazily-registered authorizers (619-623) | `ConditionsAwareDecisionUnion` builder (`Add(name, d)`, `ToDecision()`), holding already-computed sub-decisions only | `AZ/conditionsunion.go:37,58,135` |
| T10 | `IsAllowed/IsDenied/IsNoOpinion/IsConditional/IsConcrete` (648-654) | `IsAllow/IsDeny/IsNoOpinion/IsConditionsMap/IsUnion/IsUnconditional` | `AZ/conditions.go:121-157` |
| T11 | `CanBecomeAllowed()` (658-660) | `PossibleDecisions().Has(DecisionAllow)` | `AZ/conditions.go:204`; used `FLT:202` |
| T12 | `Decision.Evaluate(ctx, data, builtin...)` (662-667) | enforcement: `Authorizer.EvaluateConditions` called by the enforcer; library: `PartiallyEvaluateConditionsAwareDecision` and `ConditionsMap.Evaluate` | `ENF:145-153`; `AZ/evaluate.go:235,102` |
| T13 | `AllConditionSets(ctx)` (669-674) | — (no lazy chain to expand). Nearest: `UnionedDecisions()` iterator | `AZ/conditions.go:246` |
| T14 | `ConditionData` (GetOperation/GetOperationOptions/GetObject/GetOldObject) (684-702) | `ConditionsData`, an `admission.Attributes`-shaped subset that adds GetName, GetNamespace, GetResource, GetSubresource, IsDryRun, GetKind, GetUserInfo. `GetOperation` returns `AdmissionOperation` | `AZ/interfaces.go:309,313-346` |
| T15 | `ConditionEffect` enum `Deny/NoOpinion/Allow` (712-735) | — The effect is **which slice** the condition is in: `denyConditions` / `noOpinionConditions` / `allowConditions` | `AZ/conditionsmap.go:34-43`; `APIv1:476-510` |
| T16 | Go `Condition` struct `{ID, Condition, Effect, Description}` (737-773) | `Condition` interface `{GetID, GetType, GetCondition, GetDescription, Evaluate}`; concrete `GenericCondition{ID, Condition, Type, Description, EvaluateFunc}` | `AZ/interfaces.go:262-296`; `AZ/conditionsmap.go:224-254` |
| T17 | `ConditionSet{unconditionalDecision *Decision; set []Condition}` (777-788) | `ConditionsMap` (conditions only). Unconditional entries are `Union` leaves, not part of a map | `AZ/conditionsmap.go:34-43` |
| T18 | `ConditionSet.Type()`, per-set condition type (790-799); SAR `conditionsType` (1042) | per-condition `Condition.GetType()` / API `Condition.type` | `AZ/interfaces.go:268-272`; `APIv1:452-460` |
| T19 | `Conditional` decision variant (glossary 446-452, 515) | two variants: `ConditionsMap` and `Union` | `AZ/conditions.go:31-47`; `APIv1:514-537` |
| T20 | "conditional allow" / "conditional deny" (446-452, 870, 915) | `PossibleDecisions` contains Allow / does not contain Allow | `AZ/conditions.go:204-218` |
| T21 | `ConditionSetChain` (Go concept, and SAR/ACR field) (1000-1018, 1060-1068) | `Union` variant of `ConditionsAwareDecision`; wire `union []NamedConditionsAwareDecision` | `AZ/conditionsunion.go:37`; `APIv1:584-593,597-610` |
| T22 | `SubjectAccessReviewConditionSet` (1020-1068) | `ConditionsAwareDecision` (discriminated union with `type`), `NamedConditionsAwareDecision`, `UnconditionalDecision` | `APIv1:541-594,597-610,613-627` |
| T23 | `SubjectAccessReviewConditionSet.Allowed/Denied` bools (1021-1026) | `type: Allow|Deny|NoOpinion` + `allow|deny|noOpinion: {reason, evaluationError}` | `APIv1:541-568,613-627` |
| T24 | `SubjectAccessReviewCondition{ID, Effect, Condition, Description}` (1071-1076) | `Condition{ID, Condition, Type, Description}` | `APIv1:434-467` |
| T25 | `SubjectAccessReviewConditionEffect{Allow,Deny,NoOpinion}` (1078-1084) | — (list membership) | `APIv1:476-510` |
| T26 | `SubjectAccessReviewConditionSet.FailureMode` (1028-1030) | — not stored. Derived: `FailureDecision()` (Deny iff Deny is possible) | `AZ/conditions.go:224-229` |
| T27 | "FailureMode of the ConditionalAuthorizer" (744-745, 754-755, 761-763, 793-795, 811-813) | webhook `failurePolicy` (`decisionOnError`), which governs SAR transport/validation errors only. Invalid maps and Deny errors use `FailureDecision()` | `WH:349-354`; `AZ/conditionsmap.go:141-146`; `AZ/evaluate.go:144-146` |
| T28 | `status.conditionSetChain` (1009) | `status.conditionalDecision *ConditionsAwareDecision` (top-level type only ConditionsMap or Union) | `APIv1:307`; `VAL:105-108` |
| T29 | `spec.conditionalAuthorization{mode}` / `ConditionalAuthorizationConfiguration` (1094-1114) | `spec.authorizationOptions{handledDecisionTypes}` on SAR/LocalSAR spec and SelfSAR spec | `APIv1:239,272,412-429` |
| T30 | ACR `request.conditionSetChain` + "all ConditionData fields" (1150-1170) | `request.decision` (may be refined in-process) + `request.admissionRequest *admissionv1.AdmissionRequest` | `APIa1:53-64` |
| T31 | ACR response `allowed/denied/reason/evaluationError/conditionSetChain` (1174-1208) | `response.uid` (must echo `request.admissionRequest.uid`) + `response.decision` (must be unconditional) | `APIa1:67-81`; `VAL:287-305`; `WH:541-543` |
| T32 | `POST /apis/authorization.k8s.io/v1alpha1/admissionconditionsreviews` (1213-1214) | kind `AuthorizationConditionsReview`, client resource `authorizationconditionsreviews`, **not served** (webhook wire type only) | `APIa1:33`; `pkg/registry/authorization/rest/storage_authorization.go:44-52` |
| T33 | webhook config `conditionsEndpointKubeConfigContext`, `authorizationConditionsReviewVersion` (1225-1231) | `webhook.conditionsReview{version (required, v1alpha1), kubeConfigContextName (optional)}`, in `apiserver.config.k8s.io/v1` only | `CFGv1:530,535-551` |
| T34 | condition types `k8s.io/cel`, `k8s.io/authorization-cel`, `-v1/-v2`, `k8s.io/node-authorizer` (1284, 1556-1563, 1702, 1801) | `authorizer.kubernetes.io/cel` (`ConditionTypeAuthorizationCEL`), unversioned. No node type exists | `AZ/interfaces.go:350` |
| T35 | `BuiltinConditionSetEvaluator{ConditionSetEvaluator; SupportedConditionTypes()}` (1530-1537) | `BuiltinConditionsEvaluatorBuilder.EvaluatorForData(ctx, data, apiServerAuthorizer)` → `BuiltinConditionsEvaluator.EvaluateCondition(ctx, cond)`; no type advertisement (TODO) | `AZ/interfaces.go:355-375`; `CEL:53` |
| T36 | `WithAuthorization(h, auth, s, supportsAuthorizationsConditions)` (888-890) | new `WithConditionsAwareAuthorization(h, auth Authorizer, s, ConditionalAuthorizationRequestClassifier)`; legacy `WithAuthorization(h, UnconditionalAuthorizer, s)` unchanged in signature | `FLT:55,61,135` |
| T37 | `supportsAuthorizationsConditions` func | `ConditionalAuthorizationRequestClassifier`; kube-apiserver impl `conditionalRequestClassifier` | `FLT:55`; `CP:299-321` |
| T38 | "Decision propagated using the context" (883-886) | `request.WithConditionallyAuthorizedDecision(ctx, authorizer, decision)` / `ConditionallyAuthorizedDecisionFrom(ctx)`, which store the authorizer too | `CTX:92,103` |
| T39 | union `New(...Authorizer)` | `union.New(...NamedAuthorizer) (Authorizer, error)`; `NamedAuthorizer{AuthorizerName, Authorizer}` | `UN:50-73` |
| T40 | `authorizerName` "unique within the server" (1033-1036) | unique per union (per tree level), DNS-1123 subdomain (`k8s-long-name`) | `AZ/conditionsunion.go:66-72`; `APIv1:604` |
| T41 | (none) | admission initializer `WantsUnconditionalAuthorizer` (in-tree plugins) and `WantsAuthorizer` (1.36-compatible, full interface) | `staging/src/k8s.io/apiserver/pkg/admission/initializer/interfaces.go:46-56` |
| T42 | truth value of a condition (bool or error) (805-806) | `ConditionEvaluationResult`: true / false / error / unevaluatable | `AZ/evaluate.go:42-98` |
| T43 | "AdmissionOptions.Validate will error" (1595-1599) | `Authorization.ConditionsEnforcerPluginEnabled`; with it false the legacy filter is used and a warning is logged | `SADM:183`; `SCFG:1077,1089-1091` |
| T44 | "Audit annotations" (2285-2286) | `authorization.k8s.io/is-conditional-decision`, plus existing `authorization.k8s.io/decision`/`reason`, which the enforcer also writes | `FLT:41-51,205`; `ENF:119-121,137-139` |
| T45 | "authorizer latency and error rate" metrics (2245-2248, 2328-2330) | only label value `conditional` on `apiserver_authorization_decisions_total` and on the filter's attempts counter | `staging/src/k8s.io/apiserver/pkg/authorization/metrics/metrics.go:110-114`; `staging/src/k8s.io/apiserver/pkg/endpoints/filters/metrics.go:49,139` |
| T46 | `AuthorizationConfigReview` (2111) | typo; means `AuthorizationConditionsReview` | `APIa1:33` |
| T47 | integration test dir `test/integration/apiserver/cel/conditionalauthz` (2039) | `test/integration/apiserver/conditionalauthorization/` | `IT:69,76,85` |
| T48 | `k8s.io/apiserver/plugin/pkg/admission/plugin/authorizer/caching_authorizer.go` (1891) | `staging/src/k8s.io/apiserver/pkg/admission/plugin/authorizer/caching_authorizer.go` | (path) |

---

# PART 2: Section-by-section table

Status values: unchanged / wording-only (terminology from Part 1 only) / rewrite / delete / new-section-needed.
Resolution "fix KEP" means the KEP follows the code. "fix code" means the KEP text stays and the item
goes to `followups.md` (Part 4).

## 2.1 Front matter and Background (status only)

| Heading | KEP lines | Status | Note |
|---|---|---|---|
| KEP-5681: Conditional Authorization (title + TOC) | 1-69 | rewrite | Regenerate the TOC. Lines 21-22 and 61 use the ConditionSet names (T17) |
| Release Signoff Checklist | 70-91 | unchanged | |
| Abstract | 92-153 | wording-only | `Conditional` → ConditionsMap/Union (T19). The claim at 115-117 that users learn their conditions "through `kubectl auth can-i`" is false on HEAD (Part 3, F1) |
| Example Use Cases | 154-171 | unchanged | |
| Goals | 172-202 | rewrite (one bullet) | 180-182: "enforcement of write **and connect** requests in the `WithAuthorization` HTTP filter". On HEAD, enforcement uses a separate filter and GET connects are not covered (`CP:316-320`). "Atomic set of policies … even with caching" (200-201): see F17 |
| Non-goals | 203-208 | unchanged | |
| Background and Major Considered Alternatives | 209-215 | unchanged | |
| Why not just give authorizers access to request and stored objects? | 216-242 | unchanged | |
| Why not just use `ValidatingAdmissionPolicies`? | 243-290 | unchanged | |
| What is partial evaluation? | 291-373 | unchanged | Matches `AZ/evaluate.go:177-195` (pr-137513.md, Part B KEP alignment) |
| Why propagate the conditions with the request? | 374-440 | wording-only | 382, 415: ConditionSet (T17). 409-411 says conditions are "unmodified enforced at admission". #143024 refines the decision in-process before the ACR (`WH:441-450`, `APIa1:54-56`). Change to "enforced as computed; the API server may only drop already-decided parts" |
| Glossary | 441-453 | rewrite | Replace Conditional Allow/Deny with `PossibleDecisions` terms (T20). Add: ConditionsMap, Union, ConditionsAwareDecision, FailureDecision, PossibleDecisions, unevaluatable, classifier, enforcer |

## 2.2 Proposal chapter (exhaustive)

| Heading | KEP lines | Status | What the code does instead (HEAD) | Resolution | Evidence it was deliberate |
|---|---|---|---|---|---|
| Proposal | 454-537 | rewrite | (a) 459-463: the `authorizer.Authorizer` interface is not "extended" in place. A split was added: `UnconditionalAuthorizer` + `Authorizer` (`AZ/interfaces.go:86-124`). (b) 464-467: `WithAuthorization` is unchanged; a new `WithConditionsAwareAuthorization` filter is used (`FLT:135-223`), selected only if three switches are on (`SCFG:1077`). (c) 468-471: the enforcer is **not** "always-on". It does run before ValidatingAdmissionWebhook, as the KEP says, but it runs after all mutating plugins, all built-in validators and VAP (`PLG:111-115`). (d) 472-475: "kube-apiserver must serve [ACR]" is false: it is not served (`storage_authorization.go:44-52`). (e) 476-478: the in-process CEL evaluator exists only inside the webhook authorizer, and only when `conditionsReview` is configured (`RL:188-212`, #143024). (f) 485-488: verbs. Connect requests are supported only when they arrive as POST (verb `create`); GET connects are classified unconditional (TODO `CP:316-317`). (g) 513-516 "`Decision` logical enum gets a new `Conditional` variant": it gets two (T19). (h) 525-528 "a condition also has an *effect*": the effect is the slice (T15) | fix KEP (a,b,d,g,h); fix KEP (c) and add the consequence (Part 5.4); fix KEP for alpha (f); fix code for (e) (Part 4, C5) | (a) pr-137204.md:58 (T13, enj), pr-138801.md:22-26; (b) pr-141959.md, filter design (no single thread; classifier = pr-137633.md:384); (c) pr-141959.md:40 (thread #3); (d) not discussed (pr-137633 KEP alignment "Is ACR served?"); (f) not discussed (code TODO); (h) pr-137513.md:59-60 |
| Technical Requirements | 538-557 | rewrite (two bullets) | "Must work with aggregated API servers" (553): not met. Aggregated servers get no classifier (`SCFG:1077` needs `ConditionalAuthorizationRequestClassifier`, set only in `CP:248-250`). Their delegating webhook calls only `Authorize`, so a conditional kube-apiserver answer fails closed. kube-apiserver classifies writes to aggregated groups as conditional (`CP:316-320`) but never enforces them, because admission runs in the aggregated server. "patch/update can turn into create" (549-552): create-on-update re-check is unconditional (`staging/src/k8s.io/apiserver/pkg/endpoints/handlers/update.go:258-283`). "`deletecollection` turns into `delete`": per-object admission, holds. Others hold: "only decode if it can become authorized" (`FLT:202-221`); DAG chains (`AZ/conditionsunion.go:135-185`) | fix KEP: state aggregated support as a beta goal and describe alpha (fails closed). Fix code for the classifier (Part 4, C3) | not discussed (aggregated); create-on-update: code TODO `IT:653` |
| Core interface changes | 558-704 | rewrite | Whole section. `Decision` stays `int`. `ConditionsAwareDecision` struct (5 variants) with constructors and accessors (`AZ/conditions.go:31-277`). Interface split (`AZ/interfaces.go:86-124`). No `ConditionsMode`. MUST rules: an unaware authorizer implements `ConditionsAwareAuthorize` as `FromParts(Authorize(...))` and `EvaluateConditions` as `Deny, "", ErrorConditionEvaluationNotSupported` (`AZ/interfaces.go:109-119,128`). Callers call only one of the two methods (`:112-113`). The zero value is still Deny for both types (`AZ/conditions.go:56-57,35`). Lines 676-680: the "fold to Deny/NoOpinion" rule for conditions-unaware clients is implemented as `FailureDecision()` (`AZ/conditions.go:224-229`). However, the webhook's legacy `Authorize` returns that **plus an error** for an unrequested conditional answer, which gives a 500 at the filter (`WH:264-267`, `FLT:115-118`). `UnconditionalPartsOrFailClosed` (`AZ/conditions.go:181-198`) would give 403, but has no production caller. Lines 684-702: replace `ConditionData` with `ConditionsData` as built (T14), and say both objects are in the external version of `GetKind()` after mutating admission (`AZ/interfaces.go:336-341`; `ENF:106`) | fix KEP | pr-137204.md:47 (T1 KEP-change), :54 (T9), :55 (T10, no encoding preference), :56 (T11), :58 (T13); pr-138801.md:22-26; pr-140916.md:30-32. 500-vs-403: not discussed (shipped.md Q1) |
| Condition and ConditionSet data model | 705-800 | rewrite | `Condition` interface without effect, with per-condition type and `Evaluate` (`AZ/interfaces.go:262-296`). `ConditionsMap` with three slices (`AZ/conditionsmap.go:34-43`). Limits: 128 conditions per map in total, 10240 bytes per condition, 1024 bytes per description (`:114-123`). ID and type are **domain-prefixed** label keys; the prefix is required (`:197,208`; API `k8s-prefixed-label-key` `APIv1:439,457`). The constructor rejects 0 conditions, >128, duplicate IDs across all three lists, and bad ID/type/size. It fails closed to Deny if any deny condition is present, else NoOpinion (`:141-176`), **regardless of failurePolicy**. A NoOpinion-only map folds to NoOpinion (`:160-162`). Reserved domains `*.k8s.io`/`*.kubernetes.io` are documented, not enforced (`AZ/interfaces.go:265-266,270-271`; `APIv1:437,454`). Unconditional entries live in a `Union` (`AZ/conditionsunion.go`) | fix KEP for shape, limits and ID format. Fix code for the failurePolicy contract (Part 4, C1) | pr-137513.md:59-60 (#5 deads2k "yes please", #6), :110,:111,:114 (tree vs flatten, neolit123); limits/prefix: #140715 commit `bb296278771`, pr-140715.md:45 (T2 liggitt); reserved names: not discussed |
| Computing a concrete decision from a ConditionSet | 801-851 | rewrite (rules 2, 5, 6) | Precedence Deny > NoOpinion > Allow; within an effect true > error > unevaluatable > false; the first `true` short-circuits (`AZ/evaluate.go:121-195,204-210`). Deny error → **always Deny** + aggregated errors, which is a 500 at the enforcer (`AZ/evaluate.go:144-146`; `ENF:126-129`); no FailureMode. NoOpinion error → NoOpinion + errors (`:162-164`), a 500 unless a later leaf allows. Allow error → **not ignored**: NoOpinion + errors (`:182-184`). A true Deny/NoOpinion returns nil error (`:139-142,157-160`). Add the 4th result "unevaluatable" (partial evaluation, `AZ/evaluate.go:69-74,147-149`). The `&&`/`||` pruning guidance (832-850) holds | fix KEP. Allow-error 500: fix KEP for alpha, open follow-up (Part 4, C2) | pr-137513.md:390 (#67, short-circuit), :392 (#69, errors returned "because we're not trying to avoid a 500", 403-vs-500 deferred, TODO `AZ/evaluate.go:140-141`) |
| Computing a concrete decision from a conditional authorization chain | 852-962 | rewrite | (a) Evaluation is **eager** at authorization time: the union calls every sub-authorizer until a leaf contains an unconditional Allow/Deny (`UN:104-127`; `AZ/conditionsunion.go:58-60`). The "lazy" design (870-876, 938-947) and its diagrams are not implemented. At evaluation time the union is lazy: it calls `EvaluateConditions` leaf by leaf and stops at the first Allow/Deny (`UN:144-183`), with a `PossibleDecisions` guard per leaf (`UN:162-165`). (b) Filter signature (888-890): T36. (c) 893-895 "fails closed": an unconditional answer to a non-classified request comes from the legacy `Authorize` (`FLT:163-167`), so no conditional decision reaches it. (d) Request classes (896-913): kube-apiserver classifies only `IsResourceRequest` && verb ∈ {create, update, patch, delete, deletecollection} && GR not admission-excluded (`CP:293-321`). Wildcards are **not** excluded (pass-through, `pkg/controlplane/apiserver/config_test.go:114-115`). The "served by the same API server" check is absent (`CP:316-320` TODO). Connect only via POST. Aggregated servers: see Technical Requirements. (e) Conditional-deny folding (915-927) matches `AZ/conditionsunion.go:144-162`. (f) The context carries `(authorizer, decision)` (`CTX:92`). With the gate on, the legacy filter also stores an Allow (`FLT:101-110`) | fix KEP (a,b,c,e,f); wildcard: fix KEP; "same API server": fix code (Part 4, C3); GET connect: fix KEP for alpha | eager: not discussed (pr-137513.md:185-188 found no thread); wildcard: pr-141959.md:65 (#28 liggitt); classifier wiring: pr-137633.md:384; GET connect: not discussed (code TODO) |
| `AuthorizationConditionsEnforcer` admission controller | 963-980 | rewrite | (a) Disabling the plugin with the gate on does **not** fail startup. `ConditionsEnforcerPluginEnabled` is false, so the legacy filter is installed and a warning logged (`SADM:183`; `SCFG:1077-1091`); no conditional allow can then reach admission. (b) Position: after mutating plugins, every built-in validator and VAP, and before ValidatingAdmissionWebhook, ResourceQuota and AlwaysDeny (`PLG:111-117`; generic `SADM:97`). (c) Default-on in kube-apiserver; inert when the gate is off (`Handles` `ENF:74-76`; `PLG:193`). (d) Behaviour: missing ctx decision → error (`ENF:84-88`); Allow → pass (`:97-98`); Deny/NoOpinion/Allow-impossible → 500 (`:92-94`); conditional → `EvaluateConditions` on `VersionedAttributes(a, a.GetKind(), o)` (`:106-112`), guarded to `PossibleDecisions`, else Deny "failed closed" (`:145-153`); error → 500; Deny/NoOpinion → 403 (`:126-141`). (e) Evaluated once per admission invocation; deletecollection → once per object; retries may run it more than once, and audit is first-writer-wins (`ENF:117-118`) | fix KEP (a,b,c,d,e). Add the consequences of (b) (Part 5.4) | (a) pr-141959.md:41 (#4), pr-137633.md:382,384 (#25,#28 liggitt); (b) pr-141959.md:40 (#3, VAP-first + `vap_ordering_test.go`) |
| Changes to `(Self)SubjectAccessReview` | 981-1116 | rewrite | `status.conditionalDecision` is a recursive tree (`APIv1:307,541-627`). When it is set, `allowed`/`denied`/`reason`/`evaluationError` must be zero and the top-level type is ConditionsMap or Union (`VAL:98-133`). `spec.authorizationOptions.handledDecisionTypes` (`APIv1:239,272,412-429`) uses superset semantics: conditional ⇔ ⊇ {Allow,Deny,NoOpinion,ConditionsMap,Union}; options set but not ⊇ {Allow,Deny,NoOpinion} → 400 (`APIv1 util.go:42-63`; `pkg/registry/authorization/subjectaccessreview/rest.go:94-115`). Gate off → options cleared, fields forbidden (`rest.go:78-80`; `APIv1:236-238`). An encoding failure gives `FailureDecision` with reason "failed closed" (`pkg/registry/authorization/util/helpers.go:278-285`). Applies to SAR, SelfSAR and **LocalSAR** (`localsubjectaccessreview/rest.go:103-123`). Old v1beta1 clients get `denied=true` when `FailureDecision()==Deny`, not "NoOpinion" (1089-1091 is false; `pkg/apis/authorization/v1beta1/conversion.go:79-86`). Duplicate JSON tag at 1042 disappears with the rewrite. No `HumanReadable`/`Optimized` | fix KEP. Disclosure: new subsection (Part 5.5) | pr-137633.md:40,41,43 (#2,#3,#5 luxas), :48 (#13 deads2k, typed options); gate clearing: pr-137633.md:51 (#17 deads2k) |
| Supporting webhooks through the `AuthorizationConditionsReview` API | 1117-1256 | rewrite | (a) ACR is a wire type, not served by kube-apiserver (`storage_authorization.go:44-52`). (b) Request: `decision` (possibly refined by in-process CEL) + embedded `admissionv1.AdmissionRequest` with a fresh UID per call (`APIa1:53-64`; `WH:459-516`). Objects must carry apiVersion/kind (`WH:466-481`). (c) Response: required `uid` echo and an **unconditional** `decision` (`APIa1:67-81`; `VAL:298`; `WH:541-543`); no further conditions (constrained impersonation at 1189-1191 is not supported). (d) The guard runs against the refined decision's `PossibleDecisions` (`WH:545-560`). (e) Config: T33. `kubeConfigContextName` unset → same endpoint, dispatch on TypeMeta (`CFGv1:542-550`); forbidden unless `KubeConfigFile` (`staging/src/k8s.io/apiserver/pkg/apis/apiserver/validation/validation.go:763-771`). (f) `failurePolicy` applies to SAR errors (`WH:349-354`), **not** to ACR errors, which use `FailureDecision()` (`WH:529-562`). (g) Caching of conditional SAR statuses (1240-1245) holds (`WH:356-418`; `webhook_conditional_test.go:1321`). (h) The cached/uncached webhook table (1251-1255) holds only when `conditionsReview` is configured; see Built-in CEL. (i) Webhook advertises `handledDecisionTypes` only when an ACR client exists (`WH:287-292`). (j) Delegating authorizers in generic apiservers are wired with an ACR client (`staging/src/k8s.io/apiserver/pkg/server/options/authorization.go:206`) that points at an unserved resource | fix KEP (a-i). (j): fix code (Part 4, C7) | (b) pr-137633.md:50 (#15 deads2k); UID + postponed AuditAnnotations/Warnings: pr-137633.md:64 (#44 liggitt); (e) pr-137633.md:56,376,386 (#16,#30); (d) #143024 API doc `APIa1:54-56`; (a) not discussed |
| Composite / Union Authorizer Support | 1257-1510 | rewrite | The worked example uses chains, per-set types, `k8s.io/cel` and effects; it must be redone with `union`/`ConditionsMap` YAML. Divergences: (a) already-evaluated sub-decisions are **kept** as `NoOpinion` leaves with reason and error, not omitted (1402-1404, 1426-1430 vs `AZ/evaluate.go:259-268`). (b) Within an effect, evaluation stops at the first true (1490-1497 vs `AZ/evaluate.go:204-210`). (c) The aggregated-server half (steps 1-2, 6-9, lazy resumption 1453-1462) does not work on HEAD: no classifier and no builtin evaluator in generic apiservers, and ACR is not served. (d) kube-apiserver-side behaviour holds: eager walk (`UN:107-122`), routing by `authorizerName` (`UN:188-194`), NoOpinion resumption at evaluation (`UN:170-182`). (e) Names: unique per union level, DNS-1123 (T40). Built-ins are `*.authorizer.kubernetes.io` and visible on the wire (`RL:119`; `IT:1082`). (f) No width or depth limit on the tree (`APIv1:584-593`) | fix KEP: replace the 3-server example with a single-server example that matches HEAD, and keep the aggregated flow as future/beta | (a) pr-137513.md:394 (#75); (b) pr-137513.md:390 (#67); tree: pr-137513.md:110-114; union bound deferred to beta: pr-137633.md:67 (#48) |
| Built-in CEL conditions evaluator | 1511-1582 | rewrite | (#143024, unmerged.) (a) Shape: `BuiltinConditionsEvaluatorBuilder` is injected **per webhook authorizer** (`WH:101,107,135`; `RL:204-212`). There is no global registry, no `Decision.Evaluate(…builtin…)` at the enforcement point, and no `SupportedConditionTypes()` (TODO `AZ/interfaces.go:355-358`). (b) Flow: `WH.EvaluateConditions` first runs `PartiallyEvaluateConditionsAwareDecision` with the CEL evaluator (`WH:441`, `:951-975`). If the result is unconditional it is returned (`:443-445`). Otherwise the **refined** decision goes to the ACR (`:450`). (c) Any builtin error is treated as unevaluatable and deferred to the webhook (`WH:968-971`), which is the skew fallback (1565-1581). (d) Type `authorizer.kubernetes.io/cel`, unversioned (T34). Compiled with `environment.StoredExpressions` (`CEL:163`). (e) Environment: VAP-like `object`, `oldObject`, `request`, `namespaceObject`, optional `authorizer`. The `authorizer` is the **root** authorizer from ctx, wrapped in a per-request caching authorizer, and calls it unconditionally (`CEL:99-106`; `WH:955-956`). No `params`. (f) The cost budget `RuntimeCELCostBudget` is **per condition**; there is no per-request total (TODO `CEL:52`). Expressions are compiled on every call (`CEL:163`); no binary AST mode (1539-1542). (g) Exists only if the gate is on **and** `webhook.conditionsReview` is configured (`RL:188-212`). A CEL-only webhook cannot get conditional types advertised (`WH:287`). (h) `namespaceObject`/`authorizer` are not in the ACR (`WH:484-516`), so the ACR-side evaluator cannot reproduce them | fix KEP (a-e,h). (f,g): fix code (Part 4, C5, C9, C10) | (a) pr-143024.md:77 (#18 luxas: avoid a global registry), :75-76 (registry removed); pr-137204.md:56 (T11b liggitt: drop the builtinEvaluators param); (c) code comment `WH:965-967`; (g) not discussed |
| Feature availability and version skew | 1583-1611 | rewrite | Conditions are effective only when **all** of the following hold: (1) gate on; (2) a classifier is set, which only kube-apiserver does (`CP:248-250`); (3) the enforcer plugin is enabled (`SCFG:1077`); (4) a webhook authorizer has `conditionsReview` (`RL:188-198`; `WH:287`); (5) the request is classified true (`CP:299-321`). The "AdmissionOptions.Validate will error" plan (1595-1599) is replaced by the fallback + warning (`SCFG:1089-1091`). The SAR selection rule (1600-1605): kube-apiserver SAR returns conditions **for any verb/resource** if the client opts in (`subjectaccessreview/rest.go:100-102`). The filter's classifier is what restricts enforcement, and it does not check "served by the current API server" or wildcards. Skew matrix: replace `ConditionsModeNone` with "no `authorizationOptions`". A new webhook that answers conditionally anyway causes a legacy-path 500 (`WH:264-267`) or an aware-path failurePolicy (`VAL:101-103` → `WH:327-329`) | fix KEP | enforcer fallback: pr-141959.md:41; pr-137633.md:382,384 |
| Other Kubernetes authorization enforcement points … | 1612-1625 | rewrite (add paragraph) | The statement "not mentioned here … do not support it, and will fail closed" (1614-1617) holds in-tree: every `Authorize` caller gets an unconditional answer (shipped/C §2.1 M1; `WH:261-267`). Add: in-tree admission plugins hold `UnconditionalAuthorizer` (`WantsUnconditionalAuthorizer`). `WantsAuthorizer` hands the full interface to out-of-tree plugins, and such a caller must evaluate or fail closed. `APIVersion="*"` note (1619-1624): unchanged | fix KEP | pr-140916.md:30-32 |
| Compound Authorization for Connectible Resources | 1626-1654 | rewrite | `ensureAuthorizedForVerb` holds `UnconditionalAuthorizer` (`pkg/registry/core/pod/rest/authorize.go:38,55`). The primary POST connect (`create pods/exec`) is classified conditional (`CP:320`). GET connect is not classified (`CP:316-317`). There is no general `create` check for `*/proxy` | fix KEP: mark as proposed for beta, and describe the alpha state | pr-138801.md (narrowing, KEP-alignment Nit); not discussed otherwise |
| Compound Authorization for update/patch → create | 1655-1661 | rewrite | The secondary `create` check is unconditional (`staging/src/k8s.io/apiserver/pkg/endpoints/handlers/update.go:268`, also used by `patch.go:245`). The ctx (update) decision is then evaluated by the enforcer against a CREATE operation with no old object (`ENF:106-112`). The integration rows are disabled (`IT:653-835`) | **fix code** (Part 4, C4). The KEP keeps the design sentence. Graduation/Beta lists it (Part 5.8) | code TODO `IT:653`; pr-141959.md KEP alignment |
| Constrained Impersonation through Conditional Authorization | 1662-1793 | wording-only | Future work. Not implemented: impersonation stays unconditional (`staging/src/k8s.io/apiserver/pkg/endpoints/filters/impersonation/mode.go:560`). Fix YAML (1705-1716: `conditionSetChain`/`conditionsSet`/`effect`/`k8s.io/authorization-cel`) and `AdmissionConditionsReview` (1756) per T21-T25, T32, T34. Note that ACR responses must currently be unconditional (`VAL:298`), so the "evaluation yields further conditions" step needs an API change | fix KEP (label "future") | not discussed |
| Node authorizer | 1794-1808 | wording-only | Future. The Node authorizer is unconditional (`plugin/pkg/auth/authorizer/node/node_authorizer.go:111` lifts `Authorize`). `k8s.io/node-authorizer` → a `*.authorizer.kubernetes.io` style type | fix KEP | not discussed |
| ValidatingAdmissionPolicies | 1809-1845 | unchanged (+1 sentence) | VAP/MAP secondary checks stay unconditional (`staging/src/k8s.io/apiserver/pkg/admission/plugin/authorizer/caching_authorizer.go:37-48`). Add: VAP runs **before** the enforcer (`PLG:113-114`) | fix KEP (one sentence) | pr-141959.md:40 |
| `deletecollection` support | 1846-1853 | rewrite | Conditions are evaluated **once per object**, through the per-object delete validation in admission; the enforcer is not "first" (`PLG:114`). Audit is first-writer-wins across objects (`ENF:117-118`). No integration test (`IT` has no delete/deletecollection rows) | fix KEP | not discussed |
| Complete list of all `Authorize` calls in `kube-apiserver` | 1854-1907 | rewrite | See Part 5.6 (corrections from shipped/C §2.4). Kubelet (`pkg/kubelet/server/auth.go:45`, `server.go:408`) and pod connect (`authorize.go:38,55`) are UA-only, so they are not "would support". caching_authorizer path wrong (T48). Missing: enforcer `ENF:146`, SA token attest `pkg/registry/core/serviceaccount/storage/token.go:323`, DRA `pkg/registry/resource/utils.go:303`, NodeRestriction PCR signer `plugin/pkg/admission/noderestriction/admission.go:974`, constrained impersonation `mode.go:560`, other `IsAuthorizedForSignerName` callers, #143024 CEL `authorizer` (`CEL:101-104`) | fix KEP | pr-138801.md (KEP-alignment Nit); shipped/C §2.4 |
| Authorizer requirements | 1908-1991 | rewrite | (a) Replace `ConditionsMode None` (1912-1915) with "no `authorizationOptions` / `Authorize` called". The fold is mandatory and specific: `FailureDecision()`, Deny iff Deny is possible (`AZ/conditions.go:224-229`). (b) Add the Go MUSTs: `FromParts` lifting; unaware `EvaluateConditions` = Deny + `ErrorConditionEvaluationNotSupported` (`AZ/interfaces.go:109-119`); call only one of the two authorize methods; pass-through wrappers implement all three methods (`RL:88-98`; `staging/src/k8s.io/apiserver/pkg/authorization/metrics/metrics.go:79-130`). A webhook without `conditionsReview` counts as unaware. (c) "Only produce conditional if unconditional is impossible" (1918-1934): the server normalises two cases only (NoOpinion-only map → NoOpinion `AZ/conditionsmap.go:160-162`; singleton-possibility union → unconditional `AZ/conditionsunion.go:143-174`). (d) "only evaluates its own conditions" (1972-1975): holds via routing by name (`UN:188-194`). (e) "must be able to evaluate any condition it authored, regardless of in-process evaluation" (1972-1975) conflicts with #143024: `namespaceObject` and `authorizer` are not in the ACR (`CEL:91-106`; `WH:484-516`). (f) Cost (1976-1980): the server-side bounds are size limits (`AZ/conditionsmap.go:114-123`) plus a per-condition CEL budget (`CEL:52`). (g) Version awareness (1939-1950): objects are in `GetKind()`'s external version, both new and old (`AZ/interfaces.go:336-341`; `staging/src/k8s.io/apiserver/pkg/admission/conversion.go:62-68`; `crd_conversion_test.go`, `hpa_conversion_test.go`). Delete `TODO(Lucas)` at 1947-1948, which is answered by those tests. (h) 1984-1985 "any user with `create authorizationconditionsreview`": the resource is not served | fix KEP (a-d,g,h). (e): fix KEP (restrict the variables, or specify ACR carriage). (f): fix code | (a) pr-140715.md K7; (b) pr-137204.md KEP-alignment Question; (g) #142493 (pr-142493.md KEP alignment); (e) not discussed |
| Risks and Mitigations | 1992-2013 | rewrite (add) | Add SAR/LocalSAR disclosure (Part 5.5) and "admission runs before authorization is final" (Part 5.4) | fix KEP | not discussed |

## 2.3 Test Plan, Graduation, Version Skew, PRR, TODOs

| Heading | KEP lines | Status | What is true on HEAD | Resolution | Evidence |
|---|---|---|---|---|---|
| Test Plan | 2014-2019 | unchanged | | | |
| Prerequisite testing updates | 2020-2024 | wording-only | The interface split avoided rewriting call sites, but every fake authorizer gained two stub methods (shipped/D §1.10) | fix KEP | pr-138801.md:22-26 |
| Unit tests | 2025-2035 | rewrite | Add the new packages: `AZ/` (conditions, conditionsmap, conditionsunion, evaluate tests), `union`, webhook `webhook_conditional_test.go`, `ENF` tests, `FLT` (`authorization_test.go`, `metrics_test.go`), `ENC`/`VAL` tests, `pkg/registry/authorization/*`, `CEL` tests (#143024), `pkg/controlplane/apiserver/config_test.go` (classifier), `PLG` order test. Refresh the coverage numbers | fix KEP | shipped/D §1.2-1.9 |
| Integration tests | 2036-2041 | rewrite | Path is `test/integration/apiserver/conditionalauthorization/` (T47). Three top-level runs: gate on, gate off, gate on + enforcer disabled (`IT:69,76,85`). 34 table rows × up to 3 evaluation variants (webhook-only, in-process-only, in-process-fails-then-webhook), a 24-case SAR matrix, VAP ordering, CRD and HPA conversion. Not covered: DELETE/deletecollection, PATCH/apply, subresources/connect, `failurePolicy: Deny` (only `NoOpinion` at `IT:180`), a top-level Union from the webhook, update→create (disabled `IT:653-835`), aggregated servers | fix KEP (describe what exists; list the gaps as beta test requirements) | shipped.md fact 9 |
| e2e tests | 2042-2048 | rewrite | None exist (no match under `test/e2e*`). Keep the plan as a beta requirement, including aggregated API servers | fix KEP | — |
| Graduation Criteria | 2049-2050 | unchanged | | | |
| Alpha | 2051-2056 | rewrite | "Refactoring of the authorizer interface completed": done as a split (#138801/#137204/#140916). Gated: yes, but some changes are ungated (Part 5.7). Integration tests: enabled, with the gaps above. #143024 (in-process CEL) is not merged; say whether alpha includes it | fix KEP | — |
| Beta | 2057-2072 | rewrite (add items) | Add concrete items (Part 5.8): union width/depth limit (16 promised); evaluation latency/error metrics; conditions-aware create-on-update; aggregated-server support (or explicit non-support); classifier exclusion for aggregated groups; GET connect; per-request CEL budget and compile cache; deletion/patch/subresource/failurePolicy=Deny integration coverage; enforcer/filter gate-source consistency; webhook response size limit | fix KEP | pr-137633.md:67 (#48), :63 (#37) |
| GA | 2073-2091 | unchanged | | | |
| Version Skew Strategy | 2092-2118 | rewrite | 2094-2097: "old clients … authorizer will fold": the opt-in signal is the absence of `authorizationOptions`. Folding is `FailureDecision()`; an authorizer that ignores this produces a 500 in kube-apiserver (`WH:264-267`). Add: ACR request UIDs are per call, so a request can be evaluated by a different replica than the one that authored the conditions. `AuthorizationConfigReview` → ACR (T46). Add a skew row for the CEL environment growing additively; skew errors fall back to the webhook (`WH:968-971`). Add: the reload TOCTOU, where conditions are evaluated against the **current** authorizer chain and not the authoring one (`RL:96-98`; `FLT:170` stores the reloadable resolver) | fix KEP (wording). Reload atomicity: fix code (Part 4, C8) | not discussed |
| Production Readiness Review Questionnaire | 2119-2142 | unchanged | | | |
| Feature Enablement and Rollback | 2143-2148 | unchanged | | | |
| How can this feature be enabled / disabled…? | 2149-2166 | rewrite | Components: kube-apiserver **and** the generic apiserver library: the gate lives in `k8s.io/apiserver` (`staging/src/k8s.io/apiserver/pkg/features/kube_features.go:100,404`; `pkg/features/kube_features.go:2156-2158`). Opt-in is the three switches + `webhook.conditionsReview` (Part 5.1). Disabling the enforcer plugin disables the feature | fix KEP | — |
| Does enabling the feature change any default behavior? | 2167-2175 | rewrite | "No" is false (Part 3, F14). With the gate on and **no** conditional webhook, kube-apiserver write requests go through `ConditionsAwareAuthorize`: (1) union reasons in 403s change format (`AZ/conditionsunion.go:144-173,192` vs `UN:88-93`); (2) webhook `denied` + `evaluationError` becomes a 500 instead of a 403 (`WH:337-340` → `FLT:211-214`, vs `WH:262-263`); (3) webhook SAR statuses are validated, and invalid ones go to failurePolicy (`WH:327-329`); (4) the enforcer runs for every admitted request | fix KEP (state these) | not discussed |
| Can the feature be disabled once enabled? | 2176-2190 | unchanged ("Yes") | True. Gate off clears `authorizationOptions` (`pkg/registry/authorization/*/rest.go:78-81`) and forbids the new fields (`APIv1:236-238,303-305`) | — | |
| What happens if we reenable…? | 2191-2194 | unchanged | Stateless; nothing persisted | | |
| Are there any tests for feature enablement/disablement? | 2195-2212 | rewrite | Name them: `TestConditionalAuthorizationEnabled/Disabled/EnforcerDisabled` (`IT:69,76,85`). Note: they assert outcome and zero ACRs, not byte-equality with 1.37 (pr-141959.md, Tests) | fix KEP | — |
| Rollout, Upgrade and Rollback Planning | 2213-2218 | unchanged | | | |
| How can a rollout or rollback fail? | 2219-2237 | rewrite | Replace the `/conditions` endpoint example with `conditionsReview.kubeConfigContextName`/same endpoint (`CFGv1:542-550`). Add: ACR failures fail closed to `FailureDecision()`, ignoring failurePolicy (`WH:529-562`); config reload changes the evaluating chain mid-request (`RL:96-98`) | fix KEP | |
| What specific metrics should inform a rollback? | 2238-2249 | rewrite | There is no latency or error metric for evaluation; only the `conditional` label (T45). State what exists, and move the rest to Beta | fix KEP + fix code (Part 4, C11) | pr-137204.md KEP alignment Nit |
| Were upgrade and rollback tested? | 2250-2259 | rewrite | "all code is feature-gated" is false (Part 5.7) | fix KEP | |
| Is the rollout accompanied by any deprecations…? | 2260-2267 | rewrite | No API removals. Go library breaks: `Authorizer` interface grew; `union.New`; `webhook.New`/`NewFromInterface`; registry `NewREST`; SAR validation moved to `k8s.io/apiserver` (#140714); `admission.Operation` is now an alias | fix KEP | |
| Monitoring Requirements | 2268-2276 | unchanged | | | |
| How can an operator determine if the feature is in use? | 2277-2287 | wording-only | Name `authorization.k8s.io/is-conditional-decision=true` (`FLT:45,205`) and the `conditional` metric label (T45) | fix KEP | pr-137633.md:378 (#21 liggitt) |
| How can someone … know that it is working? | 2288-2301 | wording-only | A SAR needs `spec.authorizationOptions.handledDecisionTypes` ⊇ five types; `kubectl auth can-i` does not send it (no match in `staging/src/k8s.io/kubectl`) | fix KEP | |
| What are the reasonable SLOs? | 2302-2321 | rewrite | "Same magnitude as VAP" is unmet: compile per evaluation (`CEL:163`) vs VAP's precompiled programs | fix code (Part 4, C9); keep the SLO | pr-143024.md (S2) |
| What are the SLIs…? | 2322-2332 | rewrite | No authorizer-evaluation latency/error metric exists | fix KEP to state the current state; Beta item | |
| Are there any missing metrics…? | 2333-2341 | rewrite | "N/A" is false: evaluation latency (enforcer, ACR, in-process), ACR errors, builtin-deferral count (`WH:968-971` logs nothing) | fix KEP | pr-143024.md KEP alignment |
| Dependencies | 2342-2349 | wording-only | Also: CEL needs the namespace informer/client for `namespaceObject` (`CEL:53-69,119-140`) | fix KEP | |
| Does this feature depend on any specific services? | 2350-2370 | wording-only | "some webhook authorizer" → a webhook with `conditionsReview`; the ACR endpoint is a dependency | fix KEP | |
| Scalability | 2371-2382 | unchanged | | | |
| Will enabling / using this feature result in any new API calls? | 2383-2401 | rewrite | Aggregated→kube-apiserver ACR traffic does not exist (not served). New calls: one ACR webhook call per conditionally-allowed admission when in-process evaluation does not finish; a namespace lookup per evaluation for CEL (`CEL:119-140`) | fix KEP | |
| … new API types? | 2402-2413 | wording-only | `AuthorizationConditionsReview` v1alpha1 is registered in schemes and client-go but **not served** (`storage_authorization.go:44-52`) | fix KEP | |
| … new calls to the cloud provider? | 2414-2423 | unchanged | | | |
| … increasing size or count of the existing API objects? | 2424-2434 | rewrite | SAR status can carry a `conditionalDecision` tree; ConditionsMap ≤128 conditions × 10 KiB, union unbounded (`APIv1:584-593`) | fix KEP + Beta bound | pr-137633.md:63,67 |
| … increasing time taken by any operations covered by existing SLIs/SLOs? | 2435-2447 | wording-only | Also admission latency (enforcer + ACR) | fix KEP | |
| … non-negligible increase of resource usage? | 2448-2461 | rewrite | "No" is too strong: an unbounded union decode, and per-call CEL compile | fix KEP | |
| … resource exhaustion of node resources? | 2462-2475 | unchanged | | | |
| Troubleshooting | 2476-2488 | unchanged | | | |
| How does this feature react if the API server and/or etcd is unavailable? | 2489-2494 | wording-only | Drop the aggregated-server remark, or mark it future | fix KEP | |
| What are other known failure modes? | 2495-2511 | rewrite | "Not known" is false. List: ACR unreachable → FailureDecision; misbehaving webhook → 500 (`WH:264-267`); invalid conditions → fail closed ignoring failurePolicy (`AZ/conditionsmap.go:141-146`); enforcer disabled → feature silently off (warning); builtin CEL errors → webhook fallback | fix KEP | |
| What steps should be taken if SLOs are not being met? | 2512-2517 | wording-only | Add audit annotation keys and the `conditional` metric | fix KEP | |
| TODOs | 2518-2525 | delete | (1) "conditional vs composite": covered by Union. (2) "ReferenceGrants": out of scope, delete. (3) "infer operation from objects": moot, `ConditionsData.GetOperation()` exists (`AZ/interfaces.go:327`). Also delete the inline TODO/TBD markers at 597, 686, 691, 730, 759, 772, 776, 1148, 1174, 1208 and 1949. Each is resolved by HEAD (Parts 1-3); 1208 AuditAnnotations/Warnings becomes "deferred" per pr-137633.md:64 | fix KEP | |

## 2.4 Alternatives, Drawbacks, Appendices (status only)

| Heading | KEP lines | Status |
|---|---|---|
| Alternatives Considered | 2526-2527 | unchanged |
| Expose all conditions in AdmissionReview … | 2528-2567 | unchanged |
| Propagate an API server-generated request UID … | 2568-2572 | wording-only (ACR now uses a per-call UID for correlation, not cross-phase) |
| Only one ConditionSet exposed as part of SubjectAccessReview status | 2573-2582 | wording-only (rename heading: "Only one ConditionsMap exposed …") |
| Require the client to annotate its write request … | 2583-2593 | unchanged |
| Extract label and field selectors … | 2594-2603 | unchanged |
| Do nothing, force implementers … | 2604-2630 | unchanged |
| Drawbacks | 2631-2635 | unchanged |
| Appendix A: Further resources | 2636-2656 | unchanged |
| Appendix B: Future addition sketch: Conditional Reads | 2657-2781 | wording-only (2700-2705, 2743-2744: `effect=` → list names) |

---

# PART 3: KEP statements that are FALSE on HEAD, and TRUE-but-UNTESTED

## 3.1 False on HEAD

| # | KEP quote (line) | What is true (HEAD) |
|---|---|---|
| F1 | "The end user thus becomes aware of what restrictions they are subject to through `kubectl auth can-i` self-lookups" (115-117) | kubectl never sends `authorizationOptions` (no match in `staging/src/k8s.io/kubectl`). Conditions are visible only to raw SAR clients that opt in (`APIv1:412-429`) |
| F2 | "change `authorizer.Decision` to be a struct" (560); `Authorize(ctx, a) (Decision, error)` (571) | `Decision int` (`AZ/interfaces.go:231`); `Authorize` returns `(Decision, string, error)` (`:87`) |
| F3 | "`Attributes` … `ConditionsMode() ConditionsMode`" (589-593, 676-680) | No such method or type; signalling is by method choice (`AZ/interfaces.go:109-113`) |
| F4 | "an authorizer is advised to return `Deny` … otherwise … `NoOpinion`" for unaware clients (676-680), implying a plain 403 | The webhook folds to `FailureDecision()` **with an error**, so an unrequested conditional answer is a 500 (`WH:264-267`; `FLT:115-118`) |
| F5 | "A new, always-on … `AuthorizationConditionsEnforcer` … (ordered before other validating webhooks)" (468-469); "the first validating admission plugin to run" (977-979) | Default-on but disable-able; it runs after mutating admission, built-in validators and VAP (`PLG:111-117`) |
| F6 | "If the … feature gate is enabled, but the user disables the `AuthorizationConditionsEnforcer` … the API server [won't] start" (966-971; 1595-1599) | It starts; the legacy filter is used and a warning is logged (`SCFG:1077-1091`) |
| F7 | "Any conditional authorizer must serve this API, which means that also `kube-apiserver` must serve it" (473-475, 1130-1131) | Not served (`pkg/registry/authorization/rest/storage_authorization.go:44-52`) |
| F8 | "The union authorizer short-circuits … in a 'lazy' way … the rest of the authorizer chain … must be saved" (870-876); "Thus is the lazy approach proposed" (947) | Eager until the first unconditional Allow/Deny leaf (`UN:107-122`) |
| F9 | "the GVR doesn't contain wildcards", "served by the same API server" (896-900) | The classifier checks neither (`CP:299-321`; `config_test.go:114-115`) |
| F10 | Connect requests, e.g. `get pods/exec`, are supported (487-489, 902-905) | GET connects are classified unconditional (`CP:316-317`) |
| F11 | "If there is at least one condition with `effect=Deny` that evaluates to an error … FailureMode … controls whether … `Deny` or `NoOpinion`" (811-813) | Always Deny + error, which is a 500 at the enforcer (`AZ/evaluate.go:144-146`; `ENF:126-129`) |
| F12 | "Any `effect=Allow` condition that evaluates to an error is ignored" (829-830) | NoOpinion + aggregated errors (`AZ/evaluate.go:182-184`), a 500 unless a later leaf allows |
| F13 | "Old implementers that do not recognize `Status.ConditionSetChain` will just safely assume it was a `NoOpinion`" (1089-1091) | v1beta1 fold-down sets `denied=true` when `FailureDecision()==Deny` (`pkg/apis/authorization/v1beta1/conversion.go:79-86`) |
| F14 | PRR "Does enabling the feature change any default behavior? No." (2173) | Yes: 403 reason format, Deny+evaluationError → 500, SAR status validation (Part 2.3 row) |
| F15 | PRR "should not be a problem as all code is feature-gated" (2257) | Ungated changes exist (Part 5.7) |
| F16 | ACR response "evaluating a ConditionSet might yield another ConditionSet" (1189-1191) | The response must be unconditional (`VAL:298`; `APIa1:78-80`) |
| F17 | "conditions evaluation *should not* have access to the policy store … *atomic*" (533-537); "the conditions are … unmodified enforced at admission" (409-411) | (a) Evaluation dispatches to the **current** reloaded chain (`RL:96-98`). (b) #143024 CEL `authorizer` calls the live root chain (`CEL:99-106`). (c) The ACR receives a refined decision (`APIa1:54-56`) |
| F18 | "the condition … max 1024 bytes" (758); "Users must not use IDs with the 'k8s.io/' prefix" (741); ID prefix optional (739-740) | 10240 bytes (`AZ/conditionsmap.go:119`); reservation is domain-based (`*.k8s.io`/`*.kubernetes.io`), documentation-only (`AZ/interfaces.go:265-266`); prefix required (`:197`) |
| F19 | Built-in type `k8s.io/cel` / `k8s.io/authorization-cel` (1284 …, 1702) | `authorizer.kubernetes.io/cel` (`AZ/interfaces.go:350`) |
| F20 | "`kube-apiserver` can correlate … through the `authorizerName`", "unique within the server" (1033-1036) | Unique per union level only (`AZ/conditionsunion.go:66-69`) |
| F21 | "A ConditionSet … already evaluated to NoOpinion, … is thus omitted" (1402-1404, 1426-1430) | Kept as a NoOpinion leaf (`AZ/evaluate.go:259-268`) |
| F22 | `ConditionData.GetObject` is the object "prior to default values being applied" (695-696) | The enforcer passes the post-mutation, post-defaulting object (validating phase, `ENF:106`) |
| F23 | Kubelet `InstallAuthFilter` "would support conditions"; `ensureAuthorizedForVerb` "would be conditions-aware" (1860-1862, 1871-1873) | Both hold `UnconditionalAuthorizer` (`pkg/kubelet/server/auth.go:45`; `pkg/registry/core/pod/rest/authorize.go:38`) |
| F24 | "This KEP also applies conditional authorization support for this compound authorization check" (update→create, 1659-1661) | Unconditional (`staging/src/k8s.io/apiserver/pkg/endpoints/handlers/update.go:268`). Code gap, KEP kept (Part 4, C4) |
| F25 | `deletecollection`: "the same admission chain … is run once for all objects" (1849-1852) | Once per object |
| F26 | "In the aggregated API server case, there is automatic configuration to evaluate the conditions through a `POST …admissionconditionsreviews`" (1212-1214) | A client is wired (`staging/src/k8s.io/apiserver/pkg/server/options/authorization.go:206`), but the resource name differs (T32), the endpoint is not served, and aggregated servers have no classifier |
| F27 | PRR "There might be a slight increase in traffic between aggregated API servers and the kube-apiserver" (2397-2400) | No such traffic on HEAD (F7, F26) |
| F28 | PRR "Are there any missing metrics…? N/A" (2339) and failure modes "Not known" (2509) | See Part 2.3 |
| F29 | "Conditional authorization is only supported for certain requests, namely whenever admission is invoked" (485-488), for SAR: verb limited (1600-1605) | The SAR registries return conditions for any verb or resource to an opted-in client (`pkg/registry/authorization/subjectaccessreview/rest.go:100-102`). Only the filter restricts enforcement. The KEP Goals (184-187) already allow this, so align 1600-1605 with them |

## 3.2 True on HEAD but untested

Each item: a test that would fail if the behaviour were removed does not exist (per the Stage 2 Tests
sections, re-checked by grep where noted).

| # | KEP statement (line) | HEAD location | Gap |
|---|---|---|---|
| U1 | Evaluation can only yield an outcome in the possible set ("conditional allow can turn into Allow/Deny/NoOpinion", 446-452) | `AZ/conditions.go:204`; `AZ/evaluate.go:121-195` | No soundness test of `PossibleDecisions` against evaluation (pr-137513.md:223, :292) |
| U2 | Lazy resumption: later authorizers are evaluated only if earlier ones give NoOpinion (1453-1455) | `UN:144-183` | `evaluateCondCalls` is counted but never asserted (pr-137513.md:536) |
| U3 | `deletecollection` works (1846-1853) | per-object delete admission | No DELETE/deletecollection integration row (shipped.md fact 9) |
| U4 | update/patch semantics (549-552) | `ENF:106-112` | No PATCH/apply rows; update→create rows disabled (`IT:653-835`) |
| U5 | Webhook `failurePolicy` governs failures (744-745 etc., in the narrowed sense of T27) | `WH:349-354` | Integration uses only `failurePolicy: NoOpinion` (`IT:180`); DV-valid but constructor-rejected responses under `Deny` are untested (pr-137633.md:225) |
| U6 | Only proceed (decode) if the request can become authorized (543-544) | `FLT:202-221` | Outcomes are asserted, but no test asserts that the body is not decoded or admission does not run for a no-Allow-possible decision (pr-141959.md, Tests: "a request classified true never completes without the enforcer") |
| U7 | Gate off ⇒ 1.37 behaviour (PRR 2167-2212) | `SCFG:1077`; registries `rest.go:78-81` | The Disabled runs assert outcome and zero ACRs, not equality with 1.37 (pr-141959.md, Tests `IT:974-1006`); legacy webhook `Authorize` with the gate off is untested (pr-137633.md:633) |
| U8 | An old client never receives conditions (1089-1091, as F13 rewritten) | `WH:264-267`; `VAL:101-103` | `allowed=true` + `conditionalDecision` on the legacy path is untested (pr-137633.md:625) |
| U9 | Per-call correlation (ACR UID, the replacement for 1148/1174 TODOs) | `WH:483,541-543` | UID echo untested; the fake makes it vacuous (pr-137633.md:620) |
| U10 | Refinement before ACR keeps the outcome (#143024, replacing 1402-1430) | `WH:441-450,545-560` | Refined-decision guard untested (pr-143024.md:245) |
| U11 | Fail closed when conditions cannot be evaluated (Proposal 507-510) | `ENF:145-153` | Covered for in-process cases; the enforcer's own `PossibleDecisions` guard is covered by unit tests only (shipped/D §1.7) — no integration row returns an impossible decision |
| U12 | Unconditional authorizers behave as before (Core interface: "the change is not huge", 660-663) | `UN:76-100` vs `:104-127` | `Authorize` and `ConditionsAwareAuthorize` disagree on reason text for unconditional chains; untested (pr-137513.md:585 P17) |
| U13 | Union names unique (1033) | `UN:57-68` | `union.New` empty/duplicate-name errors untested (pr-137513.md:529) |
| U14 | Classifier excludes non-admission requests (896-905) | `CP:299-321` | Unit-tested (`config_test.go`); the aggregated-group and excluded-GR cases have no integration test |

---

# PART 4: Code-wins list (KEP right, code wrong → `followups.md`, not the KEP)

Stage 5 rule 4: the KEP text for these stays as the target design, with no TODO. Where the target is
beta, Stage 5 lists it under Graduation/Beta (Part 5.8).

| # | Item (Stage 2 source) | KEP | Code (HEAD) | My verdict |
|---|---|---|---|---|
| C1 | Invalid conditions ignore the operator's failure policy (pr-137513 Security 1; pr-137633.md:117) | Operator's FailureMode governs invalid ID/size/type (744-745, 754-755) | Constructor fails closed by `FailureDecision` (`AZ/conditionsmap.go:141-146`), reached from webhook decode (`ENC:134-142` via `WH:341`). With `failurePolicy: Deny` and an allow-only invalid map, the result is NoOpinion and the chain continues | **Agree.** An operator who chose Deny expects a malformed webhook answer to stop the chain. Fix: decode with `w.conditionsAwareFailureDecision` when the constructor errors |
| C2 | Allow-condition errors give 500 (pr-137513 K2) | "ignored" (829-830) | NoOpinion + errors → 500 at the enforcer (`AZ/evaluate.go:182-184`; `ENF:126-129`) | **Disagree that the code is wrong.** Thread #69 (pr-137513.md:392) shows returning the errors was deliberate, and a 403-vs-500 follow-up was deferred (TODO `AZ/evaluate.go:140-141`). KEP follows code for alpha (Part 2.2); keep the open 403/500 question in followups |
| C3 | Aggregated-group writes classified conditional (pr-141959.md:75; pr-137633.md:438) | Only "served by the same API server" (899) | `CP:316-320` has no check; the TODO says the opposite | **Agree.** Conditions are never enforced in kube-apiserver for proxied requests. The aggregated server re-authorizes unconditionally and fails closed, so this is not a bypass, but the classification is wrong and its audit annotation misleads. Classify false until aggregated support exists |
| C4 | update/patch→create compound check unconditional (pr-141959 KEP alignment) | Conditions-aware (1659-1661) | `update.go:268` UA-only; enforcer evaluates update conditions as CREATE (`ENF:106-112`) | **Agree** (fails closed today). Beta item |
| C5 | In-process CEL only with an ACR endpoint (pr-143024 KEP alignment; shipped.md Q2) | No second webhook needed if conditions can be evaluated in-process (1247-1255, 1518) | Builder built only inside `if cr := …ConditionsReview; cr != nil` (`RL:189-212`); advertisement needs an ACR client (`WH:287`) | **Agree.** Decouple: build the evaluator whenever the gate is on, and advertise conditional types when either an ACR client or a builtin evaluator exists. Non-CEL conditions still fail closed at `WH:455-456` |
| C6 | 128 total vs 128 per list (pr-140715 K4) | (API doc) "cannot contain more than 128 conditions in total" (`APIv1:477-478`) | DV is per list (`+k8s:maxItems=128` ×3, `APIv1:483-507`); the total is enforced only in-process | **Agree.** Add a total-count check to `VAL`, or change the API doc. The KEP should state the total |
| C7 | Delegating authorizer wired with an ACR client for an unserved endpoint (pr-137633.md:468) | KEP says kube-apiserver serves ACR (contradicted; KEP will be rewritten) | `staging/src/k8s.io/apiserver/pkg/server/options/authorization.go:206` | **Agree as code.** Harmless today (no classifier → only `Authorize`), but any future classifier in a generic apiserver would advertise conditions that it cannot evaluate. Stop wiring it until ACR is served |
| C8 | Reload TOCTOU between authoring and evaluation (pr-137633.md:453; pr-141959 KEP Question) | Atomic (533-537) | Ctx stores the reloadable resolver (`FLT:170`), and `EvaluateConditions` uses `current` (`RL:96-98`) | **Agree for the reload part.** Store the concrete union snapshot in ctx. **Disagree for CEL `authorizer()`** (`CEL:99-106`): secondary checks evaluated at admission time are VAP semantics by design. KEP should state that this carve-out exists (fix KEP) |
| C9 | CEL compiled per call; VAP-magnitude SLO (pr-143024.md:106) | SLO 2319 | `CEL:163` | **Agree.** Cache compiled programs keyed by expression |
| C10 | Per-condition CEL budget, no per-request total (pr-143024.md:92) | Conditions must be within reasonable cost (1976-1980) | `CEL:52` TODO | **Agree.** Add a per-request budget across all conditions of a decision |
| C11 | No evaluation latency/error metrics (pr-137204 KEP Nit; pr-143024 KEP Nit) | PRR 2245-2248, 2328-2330 | Only the `conditional` label (T45) | **Agree, beta.** For alpha the KEP states what exists (Part 2.3); the metrics are a beta criterion |
| C12 | Filter and enforcer read the gate from different sources (pr-141959.md:105) | "there must not be a case where the feature would be enabled, but there would be no enforcement" (972-974) | `SCFG:1077` uses `utilfeature.DefaultFeatureGate`; `ENF:63-65` uses the injected gate | **Agree.** Low likelihood in kube-apiserver, but the invariant is the KEP's core safety claim |
| C13 | Unsafe corrupt-object delete skips admission (pr-141959.md:82) | Conditions are enforced in validating admission (105-107, 507-510) | `staging/src/k8s.io/apiserver/pkg/endpoints/handlers/delete.go:141-169` | **Agree.** A conditional `delete` must not complete without the enforcer. Fail closed when the decision in ctx is conditional |
| C14 | Audit first-writer-wins: a denied request can be audited `decision=allow` (pr-141959.md:124) | Audit surfaces the decision (2285-2286) | `ENF:116-121,137-139`; TODO `:117-118` | **Agree** (deletecollection/retry). Code fix |
| C15 | Explicit/implied Deny weakened to failurePolicy on the aware path (pr-137633.md:417) | The authorizer's Deny is final (858-866) | `WH:323-329,349-354`: a status with `denied=true` that fails validation becomes failurePolicy (possibly NoOpinion); the legacy path keeps Deny (`WH:262-263`) | **Agree.** Check `Denied` before validation, as the legacy path does |
| C16 | Union width/depth unbounded (pr-137633.md:122; pr-137513 Security 2) | KEP silent; 128 per map; thread #48 promised 16 for beta | `APIv1:584-593` no maxItems; recursion `ENC:143-148` | **Agree** (beta). Not strictly "KEP right", but it goes to followups and the Beta list, not the KEP body |
| C17 | Reserved `*.k8s.io`/`*.kubernetes.io` IDs/types unenforced (pr-140715 K2) | "must not use" (741, 790-791) | Documentation only | **Disagree that it is code-wins.** The webhook is expected to author `authorizer.kubernetes.io/cel` (`AZ/interfaces.go:350`), so a usage ban is wrong. Fix KEP: the reservation is about meaning, and is unenforced |
| C18 | Startup failure when enforcer disabled (pr-141959.md:41) | 966-971 | fallback | **Not code-wins**: deliberate (#4, #25, #28), and still safe. Fix KEP (Part 2.2) |
| C19 | Enforcer position (pr-141959.md:40) | first | after VAP | **Not code-wins**: deliberate (#3). Fix KEP and add the consequences (Part 5.4) |

---

# PART 5: New content the KEP needs

## 5.1 Enablement: three switches plus one per-webhook opt-in (new subsection under "Feature availability")

1. **Gate** `ConditionalAuthorization` (Alpha, default off, 1.38; `pkg/features/kube_features.go:2156-2158`;
   defined in `staging/src/k8s.io/apiserver/pkg/features/kube_features.go:100,404`).
2. **Classifier**: `Config.Authorization.ConditionalAuthorizationRequestClassifier`. Only kube-apiserver sets it, and only
   with the gate on (`CP:248-250`). The rule: resource request, verb ∈ {create, update, patch, delete, deletecollection},
   GroupResource not excluded from admission (`CP:293-321`).
3. **Enforcer plugin** `AuthorizationConditionsEnforcer` enabled: `ConditionsEnforcerPluginEnabled` is computed from the
   enabled plugin list (`SADM:183`). It is default-on in kube-apiserver (`PLG:193`).
   `DefaultBuildHandlerChain` installs `WithConditionsAwareAuthorization` iff 1∧2∧3 (`SCFG:1077-1085`). Otherwise
   it installs the legacy `WithAuthorization`, which with the gate on still stores an unconditional Allow in ctx
   (`FLT:101-110`). If 1 holds but 3 does not, it logs a warning (`SCFG:1089-1091`).
4. **Per webhook**: `authorizers[].webhook.conditionsReview{version: v1alpha1, kubeConfigContextName}`
   (`CFGv1:530-551`). Only then does the webhook advertise `handledDecisionTypes` (`WH:287-292`) and get the CEL
   evaluator (`RL:188-212`).
5. **SAR/SelfSAR/LocalSAR** need only the gate and a client opt-in (`pkg/registry/authorization/util/helpers.go:251-261`).

State the invariant this design keeps: a request classified conditional can only leave the filter
non-Allow if the enforcer is in the admission chain. Note the C12 caveat about gate sources.

## 5.2 `AuthorizationConditionsReview` is a wire type (rewrite of the ACR section intro)

Registered in schemes and client-go (`APIa1:29-33`, `+genclient:onlyVerbs=create`), validated (`VAL:244-305`), and
**not served** by any API server (`pkg/registry/authorization/rest/storage_authorization.go:44-52`). Webhook authorizers
send it to the URL from `conditionsReview`. The aggregated-server design (kube-apiserver evaluating on behalf of
aggregated servers) becomes future/beta. Quote `APIa1:33-81` verbatim. State `metadata` must be empty
(`VAL:253-257`), the UID echo (`WH:541-543`), the unconditional response (`VAL:298`), and the
`PossibleDecisions` guard on the refined decision (`WH:545-560`). Record that AuditAnnotations/Warnings were
deferred (pr-137633.md:64).

## 5.3 In-process CEL (#143024): how it refines the decision before the ACR

Rewrite "Built-in CEL conditions evaluator" around this sequence (`WH:429-451,951-975`):

1. The enforcer calls the root authorizer's `EvaluateConditions` (`ENF:146`). The union routes each leaf to its
   named authorizer (`UN:188-194`).
2. The webhook's `EvaluateConditions` builds an evaluator for this request (`CEL:79-117`). This does a namespace
   lookup and builds the activation, and the root authorizer from ctx is wrapped in a per-request caching authorizer.
3. `PartiallyEvaluateConditionsAwareDecision` evaluates each `authorizer.kubernetes.io/cel` condition
   (`AZ/evaluate.go:235-276`). Other types are unevaluatable. **Builtin errors count as unevaluatable** (`WH:968-971`).
4. If the result is unconditional, it is returned with no webhook call (`WH:443-445`).
5. Otherwise the **refined** decision goes in the ACR. Allowed refinements: drop false conditions; fold a map whose
   deny/allow sides are empty; turn decided union leaves into NoOpinion leaves that keep reason/error
   (`AZ/evaluate.go:259-268`); truncate after a leaf containing an unconditional Allow/Deny. The KEP must list these,
   because an authorizer cannot expect to receive back exactly the decision it issued (pr-143024 KEP Nit).
6. Conditions requirement conflict: CEL may reference `namespaceObject` and `authorizer`, which the ACR does not
   carry (`CEL:91-106`; `WH:484-516`). The KEP must either restrict which variables such conditions may use, or
   specify what the ACR evaluator receives (Part 2.2, Authorizer requirements (e)).
7. Availability limitation: C5.

## 5.4 Enforcer position: "admission runs before authorization is final"

New subsection under the enforcer section, plus a Risks entry. The enforcer is at `PLG:114`, after
MutatingAdmissionPolicy, MutatingAdmissionWebhook, every built-in validating plugin and ValidatingAdmissionPolicy. The
VAP-first order is deliberate, to avoid ACR webhooks for requests VAP rejects anyway (pr-141959.md:40;
`vap_ordering_test.go`). Consequences the KEP must state (pr-141959.md:88):
- Mutating webhooks, MAP and VAP see (and may log or act on) requests that the authorizer will deny. Webhook side
  effects happen before the authorization decision is final.
- An admission rejection earlier in the chain can disclose policy outcomes to a user who is not authorized.
- Conditions are evaluated against the **post-mutation** object, so mutation by other plugins can make a request
  satisfy or fail the conditions. This matches "operates on a fully-mutated request object … by design" (973-975),
  and authors must account for it.
- ResourceQuota and ValidatingAdmissionWebhook run after it.

## 5.5 SAR/SelfSAR/LocalSAR disclosure of conditions trees (Risks and Mitigations)

With the gate on, any client that can `create subjectaccessreviews` or `localsubjectaccessreviews` and opts in gets
**another user's** complete conditions tree: every ConditionsMap, condition text and description, and authorizer
names (`pkg/registry/authorization/subjectaccessreview/rest.go:100-102`, `localsubjectaccessreview/rest.go:109-111`,
`util/helpers.go:265-290`). The webhook cannot distinguish the asker, because the SAR it receives names the subject,
not the caller (pr-141959.md:96). Built-in authorizer names (`*.authorizer.kubernetes.io`) are wire-visible and must
stay stable (`RL:119`; `IT:1082`). The existing Risks text (1995-2011) covers only SelfSAR "security through
obscurity" and must be extended to cover SAR/LocalSAR.

## 5.6 Call-site list corrections (from `review/shipped/C-symbols-and-callsites.md` §2.4)

Rewrite 1854-1907 as a table: site | handle (UA/A) | method | conditions handling | gated. Corrections:
1. Kubelet `InstallAuthFilter` (`pkg/kubelet/server/server.go:408`, UA `auth.go:45`): unconditional in alpha.
2. Pod `ensureAuthorizedForVerb` (`pkg/registry/core/pod/rest/authorize.go:55`, UA `:38`): unconditional in alpha.
3. caching_authorizer path → `staging/src/k8s.io/apiserver/pkg/admission/plugin/authorizer/caching_authorizer.go`.
4. Add the enforcer `ENF:146` (the only `EvaluateConditions` enforcement point).
5. Add `pkg/registry/core/serviceaccount/storage/token.go:323` (attest; holds `Authorizer`, calls `Authorize`).
6. Add `pkg/registry/resource/utils.go:303` (DRA status/binding).
7. Add `plugin/pkg/admission/noderestriction/admission.go:974` (PodCertificateRequest signer).
8. Add constrained impersonation `staging/src/k8s.io/apiserver/pkg/endpoints/filters/impersonation/mode.go:560`.
9. `IsAuthorizedForSignerName` callers: also `pkg/registry/certificates/podcertificaterequest/strategy.go:180`
   and `plugin/pkg/admission/certificates/ctbattest/admission.go:119`.
10. Add the #143024 CEL `authorizer` variable (`CEL:101-104` via caching authorizer), unconditional.
11. `WithAuthorization` entry: split into legacy `FLT:81` and `WithConditionsAwareAuthorization` `FLT:164/166`.
12. `update.go:268` also reached from `patch.go:245` and CRD handlers.
13. Name the pass-through wrappers (`RL:88-98`, `metrics.go:79-130`, `UN:76-195`) in Authorizer requirements.
14. Note: kube-scheduler and controller-manager share the legacy filter (informational).

## 5.7 Release-note-worthy ungated changes (new PRR paragraph + Alpha notes)

| Change | HEAD | PR |
|---|---|---|
| Union `Authorize` prefixes NoOpinion reasons with `<authorizerName>: `, changing 403/SAR reason text (the short-circuit Allow/Deny reason stays unprefixed) | `UN:88-93,99` | #137513 |
| Built-in authorizer names renamed to `*.authorizer.kubernetes.io`; visible in reasons | `RL:119`; `staging/src/k8s.io/apiserver/pkg/server/options/authorization.go:182,193,213` | #140715 |
| klog warning for user authorizer names under `kubernetes.io`/`k8s.io` | `staging/src/k8s.io/apiserver/pkg/apis/apiserver/validation/validation.go:641-647` | #140715 |
| Webhook legacy `Authorize`: an unrequested `status.conditionalDecision` gives `FailureDecision` + error, so 500 | `WH:264-267` | #137633 |
| `(*VersionedAttributes).GetOldObject()` returns the versioned old object | `staging/src/k8s.io/apiserver/pkg/admission/conversion.go:62-68` | #142493 |
| `AuthorizationConditionsEnforcer` appears in the default-on plugin list and recommended order (inert) | `PLG:114,193`; `SADM:97` | #141959 |
| Go API: `Authorizer` +2 methods; `UnconditionalAuthorizer`; `union.New(...NamedAuthorizer) (…, error)`; `webhook.New`/`NewFromInterface` signatures; SAR `NewREST` signatures; `WantsAuthorizer` rename then restore; `admission.Operation` alias; SAR validation moved to `k8s.io/apiserver` | `AZ/interfaces.go:86-124`; `UN:50-56`; `WH:107,135` | #138801, #137204, #137513, #140916, #140714, #137633, #141959 |
| Union names must be non-empty and unique (startup error) | `UN:57-68` | #137513 |

## 5.8 Graduation/Beta additions (from Part 4 and the test gaps)

C1, C3, C4, C5, C8 (reload snapshot), C9, C10, C11, C12, C13, C14, C15, C16, C6; GET connect; aggregated API
servers (serve ACR or document non-support); integration coverage for U3-U5, U7-U10; e2e incl. aggregated.

## 5.9 Properties subsection pointer

Add a short "Properties" subsection at the end of Proposal. Its content: one sentence that the
machine-checkable invariants live in `review/properties.md` (Stage 3e), plus the five the KEP itself relies on:
(P1) fail-closed for unaware consumers via `FailureDecision`; (P2) soundness of `PossibleDecisions` w.r.t.
evaluation (U1); (P3) Deny > NoOpinion > Allow precedence and error rules (Part 2.2); (P4) a union of
unconditional leaves equals first-non-NoOpinion-wins (U12 notes the reason-text difference); (P5) gate off ⇒ no
new path reachable and the API fields are cleared. Partial-then-full evaluation confluence holds only when the
partial evaluator returns no errors (pr-137513.md:577 P9; `AZ/evaluate.go:182-187`). State that restriction,
not the unrestricted claim.

---

# PART 6: Simplification candidates

## 6.1 In the KEP text (mechanisms the implementation made unnecessary)

| # | KEP mechanism (lines) | Why unnecessary on HEAD | Requirement still satisfied by |
|---|---|---|---|
| S1 | Lazy chain: `ChainedDecisions` with registered authorizers, `AllConditionSets`, lazy-vs-eager discussion, the lazy diagram (619-623, 669-674, 870-876, 938-962) | The union is eager at authorize and lazy at evaluate (`UN:104-183`) | "Same final decision as one-phase" (540-543): eager authorize + ordered evaluation + `PossibleDecisions` guards (`UN:162-165`) |
| S2 | `ConditionsMode` HumanReadable/Optimized (589-610, 676-680, 1098-1113) | No presentation modes exist; a binary encoding was not built | Opt-in is `handledDecisionTypes` (`APIv1:412-429`) |
| S3 | Per-set `FailureMode`, `ConditionsType`, `Allowed/Denied` bools (1021-1047) | Derived (`FailureDecision`), per-condition type, discriminated union | Same information, no redundant state (`APIv1:541-627`) |
| S4 | Per-condition `Effect` enum (712-735, 1071-1084) | Effect = slice | Deny/NoOpinion/Allow semantics (`AZ/conditionsmap.go:124-137`) |
| S5 | Startup failure via `AdmissionOptions.Validate` (966-971, 1595-1599) | The filter selection already requires the plugin (`SCFG:1077`) | "No enabled feature without enforcement" (972-974) |
| S6 | kube-apiserver serving ACR + automatic aggregated config (473-475, 1130-1131, 1210-1214), 3-server worked example (1263-1510) | Not built for alpha | Move to "Future: aggregated API servers"; keep one single-server example |
| S7 | ACR response returning further conditions (1189-1191) | Responses are unconditional (`VAL:298`) | Constrained-impersonation flow stays in its own future section |
| S8 | Versioned CEL condition types `-v1/-v2` (1556-1563) | Additive environment + error→webhook fallback (`WH:968-971`) | Skew safety (1565-1581) |
| S9 | `WithAuthorization` signature change (888-890) | New filter, old one untouched | Classifier requirement (T37) |
| S10 | Inline TODO/TBD markers and the TODOs chapter (Part 2.3) | Resolved | — |
| S11 | Restating the evaluation algorithm in prose, picture and comments | One normative statement plus a quote of `AZ/conditionsmap.go:124-137` | Same semantics |

## 6.2 In the API and code (duplicate knobs or variants) — candidates for `summary.md`, not KEP edits

| # | Candidate | HEAD | Requirement it must still satisfy | Assessment |
|---|---|---|---|---|
| K1 | Remove `UnconditionalPartsOrFailClosed` or give it the webhook legacy caller | `AZ/conditions.go:181-198`; 0 production callers (`git grep`) | Fail-closed for unaware consumers | Pick one: using it at `WH:264-267` gives 403 (KEP F4); removing it follows liggitt's T21 rule (pr-137204.md:63). Escalate (403 vs 500) |
| K2 | Remove `ConditionsMap.Evaluate` + `EvaluateConditionFunc` | `AZ/evaluate.go:102-117`; `AZ/interfaces.go:299`; 0 production callers | Full evaluation API for in-process authorizers | `PartiallyEvaluateConditionsAwareDecision` + `UnconditionalPartsOrError` covers it |
| K3 | `Condition.Evaluate` / `GenericCondition.EvaluateFunc` | `AZ/interfaces.go:295`; `AZ/conditionsmap.go:229,249-254`; production conditions come from `ENC:154-165` with nil `EvaluateFunc`, so the result is always unevaluatable | Fast path for in-process authorizers with precompiled conditions (`AZ/interfaces.go:286-292`) | Keep only if an in-process conditional authorizer is planned for beta (Node, constrained impersonation); otherwise drop |
| K4 | Two evaluator shapes: `MaybeEvaluateConditionFunc` and `BuiltinConditionsEvaluator` | `AZ/interfaces.go:302,371-375` | Partial in-process evaluation | The builder could return a `MaybeEvaluateConditionFunc` directly |
| K5 | `FailureDecision` implemented three times | `AZ/conditions.go:224`, `AZ/conditionsmap.go:50`, `AZ/conditionsunion.go:98` | Deny iff Deny possible | One free function over `PossibleDecisions()` |
| K6 | `handledDecisionTypes` list (max 32) with only two meaningful values | `APIv1:412-429`; `util.go:42-63` | Extensible opt-in (pr-137633.md:48, deads2k) | Keep for extensibility; but the KEP should say only the two sets are meaningful today and explain the superset rule |
| K7 | Two validation layers with different limits (DV per list; constructor per map, cross-list unique) | `APIv1:483-507` vs `AZ/conditionsmap.go:149-185` | 128 total, unique IDs | Align DV with the constructor (C6); then webhook responses are rejected consistently |
| K8 | Three union-reason formats (`name: r`, `name: {r}`, nested `a: b: {r}`) and duplicated chain loops in `Authorize` / `EvaluateConditions` | `UN:88-89,180`; `AZ/conditionsunion.go:192` | Readable 403 reasons; first-non-NoOpinion-wins | One formatter shared by both paths (U12) |
| K9 | Classifier set whenever the gate is on, while filter selection separately checks the plugin | `CP:248-250`; `SCFG:1077` | Only enforce when the enforcer exists | Set the classifier only if the plugin is enabled (liggitt's thread, pr-137633.md:384), or keep the single check in `SCFG` and drop the comment that suggests otherwise |
| K10 | Builder coupled to `conditionsReview` | `RL:188-212` | Evaluate CEL without a second webhook | Decouple (C5); this removes a hidden knob |
| K11 | `union.New` name rules differ from `Add` (DNS-1123 only in `Add`) | `UN:57-68` vs `AZ/conditionsunion.go:70-72` | Unique, routable names | Validate DNS-1123 in `union.New` so misconfig fails at startup, not per request (pr-137513.md:466) |
| K12 | `kubeConfigContextName` optional with same-endpoint TypeMeta dispatch | `CFGv1:542-550` | Separate or shared endpoint | Keep; deliberate (pr-137633.md:386). Document it |

---

## Counts and limits of this review

- Part 1: 48 terminology rows. Part 2: every one of the 87 `#` headings of `review/kep.md` has a row
  (12 front-matter/background + 22 Proposal chapter through Risks + 43 Test/Graduation/Skew/PRR/TODOs + 10
  alternatives/drawbacks/appendices).
  Part 3: 29 false statements, 14 true-but-untested. Part 4: 19 rows. 14 are agreed code-wins (C1, C3-C7,
  C9-C16; C16 is a beta bound rather than a KEP disagreement). C8 is a partial agreement. 4 are rejected as
  code-wins (C2, C17, C18, C19). Part 5: 9 subsections. Part 6: 11 KEP-text + 12 code candidates.
- Not checked: nothing was built or run. Test existence was judged by grep and Stage 2 reports, not by execution.
  The thread text in `pr-<n>-review.json` was not re-read; evidence is cited through the Stage 2 follow-up rows,
  whose row lines I checked. `delete.go:141-169` (C13) and `pr-141959` metric/audit details were taken from Stage 2
  after spot-checking the enforcer and filter code, but I did not trace the unsafe-delete path myself.
  `review/properties.md` (Stage 3e) did not exist when this was written; 5.9 points to it by name.
- No instruction-like text was found in the KEP, Stage 2 files or code comments read for this task.
