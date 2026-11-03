# KEP-5681 Conditional Authorization: review summary (Stage 4)

Scope: nine PRs merged to `origin/master` for v1.38 alpha (gate `ConditionalAuthorization`, default
off) plus the open PR #143024. Evidence: `shipped.md` (what landed), `pr-<n>.md` (ten per-PR
reviews, sixteen reviewers), `security.md` (blind threat model), `tests.md` (859 baseline tests,
18 mutations, one 174-subtest integration run), `kep-delta.md`, `followups.md`, `properties.md`.
Identifiers below (S-n, T-n, R-n, D-n, P-n, C-n, K-n) refer to those files.

## 1. Verdict in one paragraph

The decision algebra (`ConditionsAwareDecision`, `ConditionsMap`, Union, partial evaluation) is
careful and fails closed wherever it is self-contained: `PossibleDecisions` is a sound
over-approximation, `FailureDecision` is never Allow, three independent clamps (union, webhook,
enforcer) bound any evaluator's answer, and mutations of these guards are killed by unit tests.
The weak point is architectural, and both the blind security review and the per-PR reviews found
it independently: enforcement is one validating admission plugin, and nothing verifies that it ran
for every request the filter classified as conditional. Two write bypasses exist today (aggregated
APIs, corrupt-object unsafe delete), the conditions-aware webhook path can weaken a Deny to
`failurePolicy`, and a config reload can swap the evaluating authorizer. None is reachable with the
gate off. Alpha behind the default-off gate is acceptable if S-1 (aggregated APIs) and S-3
(failurePolicy weakening) are fixed or documented as hard operational preconditions; the rest
blocks beta. #143024 is not ready to merge as is.

## 2. What is missing for the feature to work end to end (plan §Stage 4 Q1)

Beyond #143024, nothing is missing for the single-kube-apiserver, webhook-authorizer, built-in
resource case: the integration suite exercises it in three variants and passes. What is missing
for the feature to be *correct* in the general case:

| Gap | Where | Effect | Ref |
|---|---|---|---|
| Aggregated-API writes classified conditional, proxied without enforcement | `pkg/controlplane/apiserver/config.go:299-321`, kube-aggregator proxy | conditional Allow completes unenforced | S-1, R-1, F-52 (liggitt thread unresolved) |
| Corrupt-object unsafe delete skips admission | `handlers/delete.go:141-163`, `corrupt_obj_deleter.go:111,134` | conditional delete completes unenforced (needs a second, unconditional permission) | S-2, R-1 |
| Conditions-aware webhook path: validation failure of the server-built SAR → `failurePolicy` | `webhook.go:323-329` vs legacy `:262-267`; client-triggerable via `fieldSelector===x` on deletecollection | webhook Deny → NoOpinion under `failurePolicy: NoOpinion` | S-3, R-3, C15 |
| Constructor-rejected webhook response bypasses `failurePolicy=Deny` | `encoding.go:134-142` → `conditionsmap.go:141-174` | fail-closed, but to the tree's FailureDecision not the operator's policy | R-3, C1 |
| Reload between filter and enforcer swaps the evaluating authorizer | `reload.go:92-98`; ctx stores the resolver not a snapshot | different chain may evaluate; `PossibleDecisions` clamp is the only guarantee | R-5, P-72, C8 |
| Filter and enforcer read the gate from different sources | `server/config.go:1077` vs `conditionsenforcer.go:63-76` | latent fail-open if they disagree in exported wiring | R-11, C12 |
| Unbounded Union width/depth; DV allows what the constructor rejects | `types.go:584-593` (no maxItems), `conditionsmap.go:154,191` | DoS surface; inconsistent rejection | S-9, R-4, K7 |
| Audit annotations first-writer-wins; enforcer runs more than once per request | `conditionsenforcer.go:116-139`, `audit/context.go:351` | audit can record `allow` for a 403 | S-7, R-10 |
| Side-effecting admission (mutating webhooks, NamespaceAutoProvision, VAP messages) runs before authorization is final | `plugins.go:84-114` (enforcer at 37/40) | policy leaks and side effects for requests whose conditions deny | S-6, R-14, D-6 |
| Delegating (aggregated) authorizers advertise conditions to an ACR endpoint kube-apiserver does not serve | `options/authorization.go:206` | every conditional decision there fails closed; latent | R-13 |
| #143024: per-condition CEL budget, recompile per call, refined-guard untested, CEL only with ACR configured | `authorization_conditions.go:52,148+`, `webhook.go:545-560`, `reload.go:188-212` | ~128x VAP cost allowance; silent degradation | S-8, R-8 |

Also ungated and user-visible (release-note or revert): union reason prefix on NoOpinion 403s
(three formats, undiscussed; R-6, D-4); webhook legacy path failing closed with a 500 on an
unrequested `conditionalDecision`; `VersionedAttributes.GetOldObject` now versioned; removed Go
exports (`pkg/apis/authorization/validation`), `union.New`/`webhook.New`/`NewREST`/`initializer.New`
signature changes.

## 3. Is the test harness strong enough (Q2)

Baseline: 859 unit tests green across the twelve feature packages; integration
`TestConditionalAuthorizationEnabled` 174 subtests green (etcd downloaded by `hack/install-etcd.sh`).

Mutation results (`tests.md` Part 3): of 18 mutations, 12 were killed by unit tests, **6 survived
every test**, and 4 were killed only by a unit test while all 174 integration subtests passed.
Survivors, each an Important test gap:

- M6: ACR UID echo check removed (`webhook.go:541`): every fake copies the UID back. T1.
- M5b: legacy `Authorize` returns Allow when `allowed=true` arrives with an unrequested
  `conditionalDecision` (switch reordered): fail-open, no test. T2.
- H1: conditional metrics labels swapped (`metrics.go:112-128`): the only metrics test has a TODO. T3.
- H3: `union.New` empty/duplicate name checks removed. T8.
- H5: 128 cap ignores NoOpinion conditions; M2b: NoOpinion-list duplicate IDs. T8.

Integration-blind (unit-only coverage) for security-relevant behaviours: true Deny → NoOpinion
(T4: no deny-row user has an RBAC fallback, so NoOpinion and Deny are indistinguishable end to end),
old object replaced by new (T5), GET added to the classifier (T6), deny-only decision passing the
filter (T9). The enforcer return guard and the filter's deny-only rejection each rest on exactly one
subtest.

Not covered at all: DELETE, PATCH, apply, deletecollection, subresources, `failurePolicy: Deny`, a
top-level Union from a webhook, aggregated APIs, update-to-create (rows commented out). The
Disabled/EnforcerDisabled runs assert outcome and zero ACRs, not equivalence with 1.37.

Answer: the harness proves the happy paths and the core algebra; it does not guarantee the
properties in `properties.md` that matter most for security (P-68 "classified ⇒ enforced", P-44
clamps end to end, P-69 fold-down, P-53 UID, old-object direction). The ten priority tests are
listed in `tests.md` Part 5; the first four are T4, T2, T1 and an integration row where the old
object alone denies.

## 4. Follow-ups (Q3)

`followups.md` consolidates 65 non-addressed review threads and 20 root causes. Must-fix-before-beta
(in order): R-1 classifier holes, R-3 failurePolicy asymmetry, R-11 gate source, R-13 unserved ACR
advertising, R-5 reload TOCTOU, R-14 side-effect guard, R-4 tree bounds, R-8 (#143024, before its
merge), R-10 audit, R-15 create-on-update, R-7 confluence/soundness tests, R-18 security guards
pinned only by fakes. Ten threads remain genuinely unaddressed on HEAD; the author checklist is
`followups.md` Part 4, headed by liggitt's aggregated-API thread (#137633 #24).

## 5. Simplification candidates (Q4)

From `kep-delta.md` Part 6, judged against the requirement each must still meet:

Code/API (K-n):
- K1 `UnconditionalPartsOrFailClosed`: zero callers. Either wire it at the filter's reasonless 403
  (`authorization.go:208-221`) or delete it (D-2 decides).
- K2 `ConditionsMap.Evaluate` + `EvaluateConditionFunc`: zero production callers; covered by
  `PartiallyEvaluateConditionsAwareDecision` + `UnconditionalPartsOrError`. Remove.
- K3 `Condition.Evaluate` / `GenericCondition.EvaluateFunc`: every production condition has a nil
  func. Keep only if an in-process conditional authorizer (Node, constrained impersonation) is
  planned for beta.
- K4 Two evaluator shapes (`MaybeEvaluateConditionFunc`, `BuiltinConditionsEvaluator`): the builder
  could return the func directly.
- K5 `FailureDecision` implemented three times: one function over `PossibleDecisions()`.
- K7 Align DV with the constructor (total 128, cross-list unique IDs, non-empty, not NoOpinion-only).
- K8 One reason formatter for both union paths.
- K9 Set the classifier only when the enforcer plugin is enabled, or drop the duplicate check.
- K10 Decouple the builtin evaluator from `conditionsReview` (D-5).
- K11 Validate DNS-1123 names in `union.New` so misconfiguration fails at startup.
- K6 `handledDecisionTypes` (max 32, two meaningful sets): keep for extensibility, document the rule.

KEP text (S-n): drop the lazy-chain machinery, `ConditionsMode`, per-set `FailureMode`/flags,
per-condition `Effect`, startup-failure-when-plugin-disabled, kube-apiserver-serves-ACR and the
three-server worked example (move to Future), ACR responses carrying conditions, versioned CEL
types, the `WithAuthorization` signature change, the TODOs chapter, and the repeated prose
restatements of the algorithm.

## 6. Open decisions for the user (Q5)

Full option analysis in `followups.md` Part 5. Recommendations, which `kep.md` Stage 5 will
assume unless overridden:

| | Decision | Recommendation |
|---|---|---|
| D-1 | Aggregated APIs and unsafe delete | Refuse unless the ctx decision `IsAllow()`; aggregated pass-through is a future item once ACR is served |
| D-2 | Fold-down 403 vs 500 | 500 for a webhook protocol violation (answered conditionally when not asked); descriptive 403 via `UnconditionalPartsOrFailClosed` at the filter's non-Allow conditional branch; keep "possible outcomes" text in audit only |
| D-3 | Allow-effect condition errors | Ignore (KEP), log + audit annotation; keep Deny-effect errors as Deny (stricter than KEP; update KEP). Note `kep-delta.md` C2 argues the current 500 was deliberate (#137513 thread #69); the deferred 403-vs-500 TODO at `evaluate.go:140-141` must be resolved either way |
| D-4 | Ungated union reason prefix | Revert on the legacy path (gate off must equal 1.37; leaks chain topology to anonymous users); one formatter on the conditions-aware path |
| D-5 | CEL without an ACR endpoint | Explicit knob, after narrowing "builtin error ⇒ webhook" to compile errors only |
| D-6 | Enforcer position | First validating plugin (as the KEP says) plus a guard so side-effecting in-tree plugins skip unless `IsAllow()`; document that mutating admission still precedes evaluation |
| D-7 | SAR/LocalSAR disclosure of other users' trees | Return the folded unconditional status unless subject == requester |

Two decisions where the review disagrees with itself and the user must pick: D-3 (Stage 2
reviewers and `followups.md` say follow the KEP; `kep-delta.md` says the code's choice was
deliberate) and D-6 (the "after VAP" placement was deliberate per #141959 thread #3, but the blind
security review ranks its consequences fifth of ten).

## 7. Properties for the later Lean work

`properties.md` gives an abstract model of HEAD (Part 1) and a catalogue P-1..P-8x (Part 2). The
closed core worth modelling first: CAD + ConditionsMap + Union builder + `possibleDecisions` /
`failureDecision` + map evaluation + partial evaluation + fold, with Condition evaluation as an
oracle and "remote webhook and builtin CEL agree with the authorizer" as hypotheses. First theorems
in order: `possibleDecisions` basics; the NoOpinion lemma (`N ∈ PD ⟺ ¬containsUnconditionalAllowOrDeny`);
soundness (every full evaluation result is in PD, including against adversarial sub-authorizers);
fold correctness on singleton PD; monotone refinement; confluence with its counterexample (fails when
the partial evaluator returns errors on Allow conditions, `evaluate.go:182-187`) stated as a theorem;
the map characterisation; legacy union equivalence. Properties the KEP states and the code does not
satisfy are in `properties.md` 3.1 (P-K1..P-K11); the ones the code establishes but the KEP does not
state are in 3.2 and should enter the KEP's new Properties subsection.

## 8. Next step

Stage 5 rewrites `kep.md` from `kep-delta.md` (48 terminology rows, 87 heading statuses, 29 false
statements, 9 new subsections, 11 KEP-text simplifications), assuming the D-1..D-7 recommendations
above unless the user overrides them, then a blind verification pass against HEAD.
