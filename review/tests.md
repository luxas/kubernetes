# Stage 3b: test-harness adequacy and non-vacuity (executed)

HEAD `57a6904a21a` (origin/master `c5bdf2219ee` + #143024 `f410163f598` + review docs). Toolchain go1.27.3,
`GOFLAGS=-mod=vendor GOTOOLCHAIN=local`. Main tree used read-only for the baseline; all mutations and the
integration run were done in a scratch worktree (`git worktree add --detach $KIROCREW_SCRATCH/k8s-mut HEAD`),
removed at the end. Logs: `$KIROCREW_SCRATCH/t3b/{base,mut}/` (scratch, reclaimed with the session).

Counts are `=== RUN` lines from `go test -count=1 -v` (top-level tests plus subtests, every level).

Headline:
- Baseline: 12 package runs, **859 `=== RUN`, 0 failures**. Integration `TestConditionalAuthorizationEnabled`:
  **174 `=== RUN`, 174 PASS, 0 FAIL** (etcd 3.7.1 downloaded by `hack/install-etcd.sh`).
- Mutations: 10 mandatory/optional (M1-M10) + 3 variants (M2b, M5b, M8b) + 5 hypothesis checks from Stage 2
  (H1, H3, H4, H5, H7) = **18 mutants, 6 survived every unit test** (M6, M5b, M2b, H1, H3, H5). Of those 6,
  **none is caught by integration** (M6, M5b run against integration and survived; M2b, H1, H3, H5 are not
  reachable from the integration harness). A further 4 killed-by-unit mutants (M1, M8b, H4, H7) also survive
  integration, i.e. integration alone would miss them.
- Mandatory 8: 7 killed by unit tests, **M6 (ACR UID echo check) survived unit and integration**.
- Canary: M8 (inverted filter check) fails 105 integration subtests, so the integration binary is rebuilt from
  the mutated tree and a survival result is meaningful.

---

## PART 1: Coverage map

"Fails?" = would at least one test fail if the behaviour were removed or inverted. **yes (run)** = demonstrated by a
mutation in Part 3; yes = a named test asserts it (read, not mutated); no (run) = mutation survived; no = no test
references it (read); unknown = not determined. "Int." = integration row numbers from `review/shipped/D-tests-gates-api.md` §1.1.

### 1a. Core decision types (`staging/src/k8s.io/apiserver/pkg/authorization/authorizer/`)

| # | Behaviour | Unit test(s) | Int. | Fails? | Gap note |
|---|---|---|---|---|---|
| 1 | Zero `ConditionsAwareDecision` is Deny | `conditions_test.go:TestConditionsAwareDecision` (zero value), `:TestConditionsAwareDecisionUnconditionalParts` | n/a | yes (run, M9) | |
| 2 | `FromParts` unknown mode → Deny + error | `conditions_test.go:TestConditionsAwareDecision` | n/a | yes | |
| 3 | `FailureDecision` = Deny iff Deny ∈ PossibleDecisions else NoOpinion | `TestConditionsAwareDecision` (property loop), `union_test.go:TestUnionEvaluateConditions`, webhook `TestAuthorize_FoldDown`, `TestEvaluateConditions`, enforcer `TestConditionsEnforcerEndToEnd` | 5, 9 | yes (run, M9: 90+2+5+13 fails) | |
| 4 | `PossibleDecisions` per variant | `TestConditionsAwareDecision` (hand-written expectations) | — | yes | **No soundness test** that evaluated result ∈ PD for all T/F/E assignments (pr-137513 Tests). Hand-written expectations only. |
| 5 | ConditionsMap ≤128 conditions total | `TestConditionsAwareDecision` (128/129) | — | partial | **NoOpinion conditions do not count in any test**: H5 survived (`conditionsmap.go:154`). |
| 6 | Condition-ID uniqueness across deny/noOpinion/allow | `TestConditionsAwareDecision/duplicate_IDs` | — | partial | deny↔allow: yes (run, M2). **deny↔noOpinion / noOpinion↔allow: no (run, M2b survived)**. |
| 7 | ID/type domain-prefixed; byte limits 10240 / 1024 | `TestConditionsAwareDecision` (`:241-390`) | — | yes | |
| 8 | Invalid map fails closed: Deny if any Deny condition, else NoOpinion | same | — | yes | NoOpinion-only invalid map unpinned (`conditionsmap.go:160-162`). |
| 9 | NoOpinion-only map folds to NoOpinion | `TestConditionsAwareDecision/noopinion-only…` | 6 | yes (run, H5-first-attempt) | |
| 10 | Union builder: empty/duplicate/non-DNS names fail closed | `conditionsunion_test.go:TestConditionsAwareDecisionUnionAdd` | — | yes | Invalid name after an Allow/Deny leaf is silently ignored, unpinned. |
| 11 | Union `Add` no-op after unconditional Allow/Deny | `conditions_test.go` union Allow-before-Deny / Deny-before-Allow; `conditionsunion_test.go` Allow-leaf subtest | — | yes (run, M3: 7 fails) | **`conditionsunion_test.go:120-131` "Deny leaf short-circuits" is vacuous: it did not fail under M3** (only the Allow-leaf subtest did). |
| 12 | Singleton-PD union folds to unconditional | `TestConditionsAwareDecision` union cases | — | yes | |
| 13 | Input slices cloned | `TestConditionsAwareDecisionConditionsMap_ClonesInputSlices`, `TestConditionsAwareDecisionUnion_AddAfterToDecisionDoesNotMutate` | — | yes | Removing `slices.Clone(inner)` (`conditionsunion.go:180`) undetectable (pr-137513, read). |
| 14 | Partial evaluation: true Deny → Deny, nil error | `evaluate_internal_test.go:TestConditionsMapPartiallyEvaluate` | 5, 9, 13 | yes (run, M1: 28 fails) | **Integration cannot distinguish Deny from NoOpinion**: M1 survived all 174 integration subtests, because no conditional-deny user has an RBAC grant to fall through to. |
| 15 | Precedence Deny > NoOpinion > Allow; true > error > unevaluatable > false | `TestConditionsMapPartiallyEvaluate` (76 cases) | 13, 14 | yes | Allow-error + unevaluated Allow combo untested; stop-after-first-true untested (pr-137513). |
| 16 | Builtin evaluator used only for conditions that cannot self-evaluate | `TestConditionsMapPartiallyEvaluate` (panicking evaluateFunc) | — | yes | |
| 17 | `PartiallyEvaluateConditionsAwareDecision` over Unions | `evaluate_test.go:TestPartiallyEvaluateConditionsAwareDecision` (12) | — | yes | Flat unions only; nested-union recursion (`evaluate.go:262`) and name preservation untested. |
| 18 | `UnconditionalPartsOrError/OrFailClosed` | `TestConditionsAwareDecisionUnconditionalParts` | — | yes | `OrFailClosed` has no production caller (shipped.md fact 1); test pins dead code. |

### 1b. Union authorizer, metrics

| # | Behaviour | Unit test(s) | Int. | Fails? | Gap note |
|---|---|---|---|---|---|
| 19 | Union `ConditionsAwareAuthorize` short-circuits after Allow/Deny; empty → NoOpinion | `union_test.go:TestUnionConditionsAwareAuthorizeShortCircuit`, `…EmptyChain` | 1-3 | yes | |
| 20 | Union `EvaluateConditions` PD guard → sub-decision `FailureDecision` | `TestUnionEvaluateConditions` (`evaluate_error_propagated#01`, `impossible_sub-decision…`) | — | yes (run, M7: 3 fails) | |
| 21 | Union `EvaluateConditions` routes by authorizer name | `TestUnionEvaluateConditionsRoutesByAuthorizerName` | — | partial | Passes if everything is routed to the second authorizer (pr-137513, read). |
| 22 | Union `EvaluateConditions` lazy (no eval after decisive leaf) | none (`countingAuthz.evaluateCondCalls` never asserted) | — | no | |
| 23 | Union `EvaluateConditions` errors: non-Union input, unknown name, unrecognized sub-decision (`union.go:134,166,190`) | none | — | no | |
| 24 | `union.New` rejects empty/duplicate names (`union.go:59-65`) | none | — | **no (run, H3 survived)** | |
| 25 | Union `Authorize` NoOpinion reason prefix `<name>: ` (`union.go:88-89`) | none (mocks return "") | SAR matrix | integration-only (read) | |
| 26 | Metrics `conditional` / `allowed` / `denied` labels from `ConditionsAwareAuthorize`/`EvaluateConditions` (`metrics.go:97-131`) | `metrics_test.go:TestRecordAuthorizationDecisionsTotal` (1 RUN, legacy path only; TODO `:137`) | — | **no (run, H1 survived)** | |
| 27 | Filter-level `authorization_attempts_total` / annotations incl. `conditional` | `filters/metrics_test.go:TestRecordAuthorizationMetricsMetrics` | — | yes | |

### 1c. API, encoding, validation, SAR

| # | Behaviour | Unit test(s) | Int. | Fails? | Gap note |
|---|---|---|---|---|---|
| 28 | `SupportsConditionalAuthorization` superset rules | `api/authorization/v1/util_test.go:TestSupports` | SAR matrix | yes | |
| 29 | Encode internal → wire per variant | `encoding_test.go:TestFromAuthorizerConditionsAwareDecision` | SAR matrix | yes | No ConditionsMap/Union round trip. |
| 30 | Decode wire → internal; unknown type → `failClosed` | `encoding_test.go:TestToAuthorizerConditionsAwareDecision`; `v1beta1/conversion_test.go` | — | yes (run, M10: 2+2 fails) | Webhook tests do not catch M10 because DV rejects unknown types first; the decode fail-closed is defence in depth. |
| 31 | SAR status: `conditionalDecision` only when opted in; exclusivity with allowed/denied/reason | `validation_test.go:TestValidateSARStatus` | — | yes | |
| 32 | ACR request must be conditional, response unconditional | `TestValidateAuthorizationConditionsReview` | — | yes | |
| 33 | DV: ID uniqueness, limits, enum, member, gate-off forbidden | `test/declarative_validation/authorization/*` | — | yes (read) | Wrong-discriminator member untested. |
| 34 | v1beta1 fold-down never allows | `v1beta1/conversion_test.go` | — | yes (run, M10) | |
| 35 | SAR registry: gate off clears options; opt-in → conditional status; partial options → 400 | `subjectaccessreview/rest_test.go:TestCreate` (gate on+off), `util/helpers_test.go` | SAR matrix (gate on only) | yes (SAR) | SelfSAR/LocalSAR conditional path and gate-off clearing have no unit test; masked by `helpers.go:252` (pr-141959). |
| 36 | Posted status ignored (1.37 compat) | `*/rest_test.go:TestCreateIgnoresPostedStatus` | — | yes | |

### 1d. Webhook authorizer (`plugin/pkg/authorizer/webhook/webhook.go`)

| # | Behaviour | Unit test(s) | Int. | Fails? | Gap note |
|---|---|---|---|---|---|
| 37 | Advertise `handledDecisionTypes` only with ACR reviewer | `TestConditionsAwareAuthorize` (`:356-364`) | all conditional rows | yes | Gate-off reviewer drop (`webhook.go:155`) untested; every webhook test sets gate on. |
| 38 | Legacy `Authorize`: unrequested `conditionalDecision` → `FailureDecision` + error (`:264-267`) | `TestAuthorize_FoldDown`, `TestConditionalResponseCaching` | none (mock folds itself) | yes (run, M5: 5 fails) | Only deny-containing maps catch it; allow-only maps fold to NoOpinion == the `default` branch. |
| 39 | Legacy `Authorize`: `allowed=true` + `conditionalDecision` must not Allow | none | none | **no (run, M5b survived unit + integration)** | Moving `case r.Status.Allowed` above `:264` turns it into Allow. |
| 40 | Legacy: `denied` wins over conditional | `TestAuthorize_FoldDown` | — | yes | |
| 41 | Conditions-aware: response validated, fails closed per failurePolicy | `TestConditionsAwareAuthorize` | — | yes | `failurePolicy=NoOpinion` + deny-containing invalid response untested (S1, pr-137633). |
| 42 | Conditional response caching only for aware callers | `TestConditionalResponseCaching` | — | yes | Cache-key separation within one authorizer untested. |
| 43 | v1beta1 webhook never yields conditions | `TestConditionsAwareAuthorize_V1beta1Downgrade` | — | yes | |
| 44 | ACR response UID must echo request UID (`:541-543`) | none effective (fake overwrites UID `webhook_conditional_test.go:82-84`; e2e server echoes `:1121`) | none (mock echoes) | **no (run, M6 survived unit + integration)** | |
| 45 | ACR result guarded to PossibleDecisions of the (refined) decision (`:545-560`) | `TestEvaluateConditions` (`:936,958,987`, no builder) | — | yes (read) | Refined-vs-original decision distinction untested (pr-143024). |
| 46 | ACR request carries conditions, objects with GVK, typed-nil skipped | `TestEvaluateConditions`, `TestEvaluateConditions_EndToEnd` | conditional rows | yes | `AdmissionRequest.UserInfo/Kind/Resource/Operation/DryRun` contents never asserted. |
| 47 | Builtins first, fully in-process → no ACR; error → deferred | `TestEvaluateConditions_Builtins`, `…WithoutContextAuthorizer` | 15-18 (in-process-only variants), fallback variant | yes (run, M1: `fully_evaluated_in-process` fails) | |
| 48 | In-process CEL env: object/oldObject/request/namespaceObject/authorizer, budget | `cel/authorization_conditions_test.go` (300 RUN in package; 29 for `-run AuthorizationConditions`) | 15-18 | yes (read) | Namespace-kind special case (`authorization_conditions.go:126-128`) untested. |
| 49 | Builtin builder only with gate on + `conditionsReview` (`reload.go:188-211`) | none | Disabled run omits `conditionsReview` | no (read) | |

### 1e. Handler chain, enforcer, classifier

| # | Behaviour | Unit test(s) | Int. | Fails? | Gap note |
|---|---|---|---|---|---|
| 50 | Filter: conditional with Allow ∈ PD + classifier true → next handler | `filters/authorization_test.go:TestWithAuthorization`; enforcer `TestConditionsEnforcerEndToEnd` | 4, 7, 10 | yes (run, M8: 7 + 20 unit, 105 integration fails) | |
| 51 | Filter: conditional without Allow (deny-only map) → 403 at the filter | `TestWithAuthorization/conditional_deny-only_+_classifier_true` | none | yes (run, M8b: 3 unit fails) | **Single test.** Integration does not catch M8b (enforcer denies later); defence in depth guarded by one subtest. |
| 52 | Classifier false/nil → conditional folded (403 or NoOpinion) | `TestWithAuthorization`, `TestRecordAuthorizationMetricsMetrics` | GET fold-down, SAR-create fold-down | yes | |
| 53 | Classifier verbs = create/update/patch/delete/deletecollection, resource only, not excluded | `pkg/controlplane/apiserver/config_test.go:TestConditionalRequestClassifier` | GET fold-down | yes (run, H7: 2 unit fails) | **Integration does not catch adding `get`** (H7 survived 174 integration subtests): the GET fold-down user has RBAC `get`. Fail-open guarded by one unit table. |
| 54 | Legacy filter (gate on) stores Allow in ctx; enforcer fails a lost decision | `context_invariant_test.go:TestConditionsEnforcerContextInvariant` | — | yes (read) | |
| 55 | Enforcer: Allow ok; Deny/NoOpinion/impossible → 500; conditional → EvaluateConditions | `TestConditionsEnforcerEndToEnd`, `TestConditionsEnforcerInitialization` | 4-14 | yes | |
| 56 | Enforcer return guard (`conditionsenforcer.go:148-150`) | `TestConditionsEnforcerEndToEnd/…impossible_Deny_=>_internal_error` | — | yes (run, M4: 3 fails) | Single subtest; impossible-Allow cannot reach the enforcer by construction. |
| 57 | Evaluation sees request-version object and **oldObject** | `admission/conversion_test.go:TestObjectAccessors`, enforcer "versioned object inspection" | 23-26, 31-34 | yes (run, H4: 1 + 3 unit fails) | **Integration does not catch oldObject := newObject** (H4 survived 174 integration subtests): no row where the old object alone decides. |
| 58 | VAP before enforcer | `plugins_test.go`, `vap_ordering_test.go` | VAP subtests | yes (read) | |
| 59 | Enforcer disabled ⇒ legacy filter | none | `TestConditionalAuthorizationEnforcerDisabled` (not run here) | integration-only (read) | |
| 60 | Gate off ⇒ 1.37 behaviour | unit gate-off rows in filters/enforcer/registry/DV | `TestConditionalAuthorizationDisabled` (not run here) | partial | Asserts outcome and 0 ACRs only (pr-141959). |
| 61 | DELETE / PATCH / apply / subresource / connect / update-to-create / failurePolicy Deny / webhook top-level Union | none | none (rows `:653-835` commented out) | no | |

---

## PART 2: Baseline (main tree, read-only, `go test -count=1 -v`)

Wall time = whole `go test` invocation including compile (build cache warm from the orchestrator smoke test),
with the package-reported test time in brackets.

| Package | cwd | Args | `=== RUN` | PASS | FAIL | Wall (test) |
|---|---|---|---|---|---|---|
| `k8s.io/apiserver/pkg/authorization/authorizer` | staging/src/k8s.io/apiserver | | 333 | 333 | 0 | 1 s (0.021 s) |
| `…/pkg/authorization/union` | same | | 49 | 49 | 0 | 1 s (0.005 s) |
| `…/pkg/authorization/metrics` | same | | 1 | 1 | 0 | <1 s (0.013 s) |
| `…/pkg/apis/authorization/v1` | same | | 26 | 26 | 0 | 1 s (0.004 s) |
| `…/pkg/apis/authorization/validation` | same | | 70 | 70 | 0 | 2 s (0.013 s) |
| `…/plugin/pkg/authorizer/webhook` | same | | 138 | 138 | 0 | 8 s (0.627 s) |
| `…/pkg/admission/plugin/authorizer/conditionsenforcer` | same | | 60 | 60 | 0 | 12 s (0.027 s) |
| `…/pkg/endpoints/filters` | same | `-run 'Authorization\|Metrics'` | 67 | 67 | 0 | 2 s (0.046 s) |
| `…/pkg/endpoints/request` | same | | 13 | 13 | 0 | <1 s (0.004 s) |
| `…/pkg/admission/plugin/cel` | same | `-run AuthorizationConditions` | 29 | 29 | 0 | 6 s (0.121 s) |
| `k8s.io/kubernetes/pkg/registry/authorization/...` | repo root | | 62 | 62 | 0 | 8 s (lsar 0.012, ssar 0.010, sar 0.016, util 0.005) |
| `k8s.io/kubernetes/pkg/apis/authorization/...` | repo root | | 11 | 11 | 0 | <1 s (only `v1beta1` has tests, 0.004 s; 6 sub-packages `[no test files]`) |
| **Total** | | | **859** | **859** | **0** | |

Note: `pkg/apis/authorization/validation` in k/k has no test of its own (confirms pr-140714).
`metrics` has one test with no subtests.

---

## PART 3: Mutation spot-checks (scratch worktree)

Each mutation was applied with a single exact-match string replacement (Python, asserting exactly one match),
the listed packages were run with `-count=1 -v` (full package, no `-run` filter; `filters` = 237 RUN and
`cel` = 300 RUN when unfiltered), then `git checkout -- .`. "Integration" = `TestConditionalAuthorizationEnabled`
(174 RUN) re-run against the mutated tree.

Common packages: E = `pkg/admission/plugin/authorizer/conditionsenforcer` (60 RUN), W =
`plugin/pkg/authorizer/webhook` (138 RUN), A = `pkg/authorization/authorizer` (333 RUN),
U = `pkg/authorization/union` (49 RUN).

### Mandatory

| ID | Mutation (HEAD file:line) | Packages run (RUN) | Failed tests | Result |
|---|---|---|---|---|
| M1 | `evaluate.go:142` true Deny returns `ConditionsAwareDecisionNoOpinion(appliedReason, nil)` | A 333, U 49, E 60, W 138, cel 300; **integration 174** | A: 28 FAIL (`TestConditionsMapPartiallyEvaluate/deny:_at_least_one_deny_condition_matched/*`, `…_with_description/*`); W: 2 (`TestEvaluateConditions_Builtins/fully_evaluated_in-process:_webhook_not_called`); U, E, cel: 0; **integration: 0** | KILLED (unit). Integration-blind: see finding T4. |
| M2 | `conditionsmap.go:169,172` noOpinion and allow lists validated with fresh `sets.New[string]()` (no cross-list dup check) | A 333, apis/v1 26, E 60, W 138 | A: 3 (`TestConditionsAwareDecision/duplicate_IDs/0`) | KILLED |
| M3 | `conditionsunion.go:59` `if false && unionMap.ContainsUnconditionalAllowOrDeny()` | A 333, U 49, E 60, W 138 | A: 7 (`TestConditionsAwareDecision/union:_Allow_before_Deny…`, `…/union:_Deny_before_Allow…`, `TestConditionsAwareDecisionUnionAdd/Allow_leaf_short-circuits_subsequent_Adds`) | KILLED. `…/Deny_leaf_short-circuits` did **not** fail: vacuous (T7). |
| M4 | `conditionsenforcer.go:148` `if false && !decisionToEvaluate.PossibleDecisions().Has(decision)` | E 60, W 138 | E: 3 (`TestConditionsEnforcerEndToEnd/conditional_allow_+_eval_returns_impossible_Deny_=>_internal_error/enabled`) | KILLED (single subtest) |
| M5 | `webhook.go:264` `case false && r.Status.ConditionalDecision != nil` | W 138, E 60 | W: 5 (`TestAuthorize_FoldDown/ConditionsMap_with_Deny_condition_folds_to_Deny`, `…transitive_Deny…`, `TestConditionalResponseCaching/conditions-unaware_caller_does_not_cache_a_conditional_response_as_authorized`) | KILLED |
| M6 | `webhook.go:541` `if false && result.Response.UID != evaluateRequestUUID` | W 138, E 60; **integration 174** | 0; integration 0 | **SURVIVED** (T1) |
| M7 | `union.go:163` `if false && !unevaluatedSubDecision.PossibleDecisions().Has(decision)` | U 49, E 60, W 138 | U: 3 (`TestUnionEvaluateConditions/evaluate_error_propagated#01`, `…/impossible_sub-decision_fails_closed_to_sub's_FailureDecision,_not_outer_union's`) | KILLED |
| M8 | `filters/authorization.go:202` `if !conditionsAwareDecision.PossibleDecisions().Has(authorizer.DecisionAllow)` (strict inversion) | filters 237, E 60, W 138; **integration 174** | filters: 7 (`TestWithAuthorization/conditional_allow_+_classifier_true/enabled`, `…classifier_false/enabled`, `…conditional_deny-only_+_classifier_true/enabled`); E: 20 (`TestConditionsEnforcerEndToEnd/*`); integration: 105 | KILLED (also the integration canary) |

### Optional

| ID | Mutation | Packages run (RUN) | Failed tests | Result |
|---|---|---|---|---|
| M9 | `conditions.go:225-227` `FailureDecision` always NoOpinion | A 333, U 49, E 60, W 138 | A: 90; U: 2; E: 5 (`…eval_denies_=>_admission_rejects/disabled`, …); W: 13 (`TestAuthorize_FoldDown/*`, `TestEvaluateConditions/*`) | KILLED |
| M10 | `encoding.go:150` unknown type → `ConditionsAwareDecisionNoOpinion("", nil)` instead of `failClosed` | apis/v1 26, E 60, W 138, k/k registry/sar 32, k/k apis/v1beta1 11 | apis/v1: 2 (`TestToAuthorizerConditionsAwareDecision/unknown_Type_falls_back_to_failClosed`); v1beta1: 2 (`…/unrecognized_type_fails_closed_to_denied`); W, E, registry: 0 | KILLED |

### Variants and Stage 2 hypotheses (confirm/refute)

| ID | Mutation | Packages run (RUN) | Failed tests | Result | Stage 2 claim |
|---|---|---|---|---|---|
| M2b | `conditionsmap.go:169` only the noOpinion list gets a fresh ID set | A 333, apis/v1 26, E 60, W 138 | 0 | **SURVIVED** | pr-137513 "cross-list uniqueness only deny↔allow": CONFIRMED |
| M5b | `webhook.go:264` insert `case r.Status.Allowed: return Allow` before the conditional case | W 138, E 60; **integration 174** | 0; 0 | **SURVIVED** (fail-open) | pr-137633 "legacy allowed=true + conditionalDecision untested": CONFIRMED |
| M8b | `filters/authorization.go:202` `if IsConditionsMap() \|\| IsUnion()` (deny-only maps pass the filter) | filters 237, E 60, W 138; **integration 174** | filters: 3 (`TestWithAuthorization/conditional_deny-only_+_classifier_true/enabled`); integration 0 | KILLED by one unit subtest only | new |
| H1 | `metrics.go:112` `"conditional"` → `"allowed"`; `:124-128` swap `allowed`/`denied` in `EvaluateConditions` | metrics 1, filters 237 | 0 | **SURVIVED** | pr-137204 "metrics tests never call new code": CONFIRMED |
| H3 | `union.go:59,63` disable empty and duplicate name checks in `union.New` | U 49, authorizerfactory 3 | 0 | **SURVIVED** | pr-137513: CONFIRMED |
| H4 | `admission/conversion.go:65` `GetOldObject` returns `v.GetObject()` | admission 31, E 60, W 138; **integration 174** | admission: 1 (`TestObjectAccessors`); E: 3 (`…versioned_object_inspection…/enabled`); integration: 0 | KILLED (unit); integration-blind | pr-142493 "no e2e row where old object decides": CONFIRMED |
| H5 | `conditionsmap.go:154` cap compares `conditionsAmount-len(noOpinionConditions)` | A 333 | 0 | **SURVIVED** | pr-137513 "NoOpinion count toward 128 untested": CONFIRMED |
| H7 | `pkg/controlplane/apiserver/config.go:294` add `"get"` to `admissionVerbs` | k/k controlplane/apiserver 32; **integration 174** | unit: 2 (`TestConditionalRequestClassifier/GET_/api/v1/namespaces/default/pods/foo`); integration: 0 | KILLED (unit); integration-blind (fail-open GET) | pr-141959 "GET fold-down grants RBAC get": CONFIRMED |

### Findings from Part 3

- **T1 [Important] [test]** ACR UID echo check is not tested by anything. `webhook.go:541-543`; fake
  `webhook_conditional_test.go:82-84` overwrites `Response.UID`, e2e server echoes it (`:1121`), integration mock
  copies it. M6 survived 138 unit + 174 integration subtests. Fix: fake option to return empty/stale UID; expect
  `FailureDecision` + `response.uid` field error.
- **T2 [Important] [test]** Legacy `Authorize` with `allowed=true` + unrequested `conditionalDecision` is unpinned;
  reordering the switch at `webhook.go:258-271` fails open (M5b survived unit + integration). `sendSARWebhook`
  (`webhook.go:356-420`) does not validate the status on the legacy path, so the switch order is the only guard.
- **T3 [Important] [test]** Authorizer-level metrics for the conditions-aware methods are untested
  (`metrics.go:97-131`, H1 survived; `metrics_test.go:137` TODO).
- **T4 [Important] [test]** Integration cannot tell a conditional Deny from NoOpinion: every deny row's user lacks an
  RBAC grant (`conditionalauthorization_test.go:950-969`), so M1 (true Deny → NoOpinion) passes all 174 subtests.
  Fix: grant RBAC `create configmaps` to the deny-row users so NoOpinion would allow and only a real Deny forbids.
- **T5 [Important] [test]** Integration does not cover the old-object property: H4 (oldObject := object) passes all
  174 integration subtests (`hpa_conversion_test.go:173-206,243-287`, `crd_conversion_test.go:344-471`).
- **T6 [Important] [test]** Fail-open classifier change (adding `get`) is invisible end-to-end (H7): the GET
  fold-down user has RBAC `get` (`conditionalauthorization_test.go:1358-1368`). Only
  `config_test.go:TestConditionalRequestClassifier` guards it.
- **T7 [Nit] [test]** `conditionsunion_test.go:120-131` "Deny leaf short-circuits" is vacuous, demonstrated by M3.
- **T8 [Nit] [test]** `union.New` name validation untested (H3); `conditionsmap.go:154` cap ignores NoOpinion
  undetected (H5); cross-list uniqueness for the NoOpinion list undetected (M2b, `conditionsmap.go:169`).
- **T9 [Nit] [test]** Filter deny-only rejection (`filters/authorization.go:202`) is guarded by exactly one unit
  subtest (M8b); the enforcer guard (`conditionsenforcer.go:148`) by exactly one (M4). Acceptable, but each security
  guard rests on a single case.

---

## PART 4: Integration

- etcd: `hack/install-etcd.sh` in the worktree downloaded etcd v3.7.1 into `third_party/etcd` (network was available;
  `etcd --version` = 3.7.1). Removed with the worktree.
- Run (worktree root, unmutated): `go test -count=1 -v -timeout 20m ./test/integration/apiserver/conditionalauthorization/
  -run TestConditionalAuthorizationEnabled` → **174 `=== RUN`, 174 PASS, 0 FAIL, 0 SKIP**, `ok … 9.043s`,
  40 s wall including compile. Breakdown: 1 top-level, 41 second-level (34 table rows + VAP + 4 SAR-behaviour groups +
  GET fold-down + SAR-create fold-down), 108 third-level, 24 fourth-level.
- Additionally ran this test against 7 mutants (M1, M5b, M6, M8, M8b, H4, H7; 174 RUN each): only M8 failed (105).
- Not run (task limited the integration run to the Enabled test): `TestConditionalAuthorizationDisabled`,
  `TestConditionalAuthorizationEnforcerDisabled`. Stage 2 claims that therefore stay unverified by execution:
  gate-off equality with 1.37 beyond outcome + ACR count (pr-141959); "enforcer disabled ⇒ conditional-allow rows
  become forbidden" (pr-141959 Tests); gate-off builder not built (pr-143024).

Stage 2 integration claims verified by execution: the 34-row × 3-variant table, VAP ordering, SAR matrix and the two
fold-down groups all pass on HEAD with #143024; the in-process-only variants pass (so the `acrCountForUser == 0` checks
hold); M8 confirms the conditional-allow rows depend on the filter's PD check.

---

## PART 5: Verdict

The unit harness is **non-vacuous for the core decision algebra** (precedence, FailureDecision, union folding, PD
guards in union and enforcer, filter PD check, decode fail-closed): every mandatory mutation on those paths was killed,
mostly by many tests. It is **not strong enough to guarantee the shipped.md §3 properties end to end**:

- Fact 1 (fail closed for conditions-unaware consumers): guaranteed only for `allowed=false` responses; the
  `allowed=true` + conditional ordering is unguarded (T2).
- Fact 2/3 (only filter + enforcer carry conditional decisions; classifier is the switch): the fail-open classifier
  change and a deny-only map passing the filter are each caught by one unit case and by no integration row (T6, T9).
- Fact 6 (partial-evaluation precedence): well tested at unit level, but integration is blind to Deny vs NoOpinion (T4).
- Fact 8 (versioned oldObject): unit-only; integration blind (T5).
- ACR integrity (UID echo): untested (T1). Metrics: untested (T3).
- §3.9 gaps (DELETE, PATCH, apply, subresources, `failurePolicy: Deny`, top-level Union, update-to-create) remain.

Top 10 missing tests, priority order:

1. **Webhook ACR UID mismatch** (`webhook_conditional_test.go`): fake returns empty and stale `response.uid` → expect
   `FailureDecision`, reason "failed closed", `response.uid` error. Kills M6.
2. **Legacy `Authorize` with `allowed=true` + `conditionalDecision`** (allow-only map and deny map, both failurePolicies)
   → expect `FailureDecision` + error, never Allow. Kills M5b.
3. **Integration: unenforced verb fail-open guard**: allow-only conditional on GET (and on a subresource/connect path) for a
   user **without** RBAC → expect 403. Kills H7 end to end.
4. **Integration: old object decides**: unconditional user creates a violating HPA/CRD object; conditional user's
   compliant update → 403, all three variants. Kills H4 end to end.
5. **Integration: Deny vs NoOpinion distinguishable**: give deny-row users an RBAC create grant; conditional Deny must
   still 403 while a false Deny + NoOpinion falls through to allow. Kills M1 end to end.
6. **Metrics for `ConditionsAwareAuthorize`/`EvaluateConditions`**: ConditionsMap, Union, Allow, Deny, NoOpinion and an
   out-of-range decision → assert `conditional`/`allowed`/`denied`/`unknown`/no sample. Kills H1.
7. **PossibleDecisions soundness property test**: brute-force small trees (≤3 maps × ≤2 conditions/effect × {T,F,E,U},
   ≤2 nesting levels) asserting evaluated ∈ PD, partial(d) PD ⊆ PD(d), folded == unfolded.
8. **Webhook refined-decision guard with builtins**: deny condition evaluates false in-process, ACR returns Deny →
   expect NoOpinion "failed closed" (`webhook.go:545-560`).
9. **Integration: DELETE, PATCH, server-side apply and `failurePolicy: Deny`** rows (at least one allow and one deny each),
   plus re-enable the update-to-create rows (`conditionalauthorization_test.go:653-835`).
10. **`union.New` and union `EvaluateConditions` error paths**: empty/duplicate names (kills H3); non-Union input,
    unknown authorizer name, unrecognized sub-decision; assert `evaluateCondCalls` laziness. Also add the NoOpinion
    cases to the 128 cap and cross-list uniqueness tables (kills H5, M2b).

## Could not check

- `TestConditionalAuthorizationDisabled` / `…EnforcerDisabled` not executed (scope limit set by the task).
- Mutations not attempted: union `EvaluateConditions` laziness (no single-line mutation keeps the result identical),
  refined-vs-original guard in webhook (requires restructuring, not a one-line edit), `reload.go:188` gate check,
  SelfSAR/LocalSAR gate-off clearing.
- DV and `test/declarative_validation/authorization/*` were not run (not in the package list).
