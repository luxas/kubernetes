# Stage 1 / Part D: test inventory, feature-gate census, API surface (HEAD `08974670a59`)

All paths are relative to `/local/home/luxask/code/kubernetes`, all line numbers are on the HEAD working tree.
Read-only; nothing was built or run (Go toolchain not on PATH).

Search used for Part 1 (vendor excluded):
`grep -rlE 'ConditionsAware|ConditionAware|ConditionsMap|ConditionalAuthorization|AuthorizationConditionsReview|conditionalDecision|authorizationOptions|conditionsenforcer|EvaluateConditions' --include='*_test.go' pkg staging plugin test`
→ **43 files, 135 top-level `Test*` functions** (plus 3 `Benchmark*`). Of these, 8 files / 46 functions are
*incidental*: they only gained stub `ConditionsAwareAuthorize`/`EvaluateConditions` methods on a fake authorizer
(PR #137204 interface change) and test nothing about the feature. That leaves **35 substantive files / 89 functions**.
Three related files the keyword filter misses are added in §1.9 (+5 functions, 1 of them unrelated).

---

# 1. Test inventory

## 1.1 Integration tests: `test/integration/apiserver/conditionalauthorization/` (the end-to-end guarantees)

Files: `conditionalauthorization_test.go` (2045 lines), `crd_conversion_test.go`, `hpa_conversion_test.go`,
`vap_ordering_test.go`, `main_test.go`. Only `conditionalauthorization_test.go` and `main_test.go` define top-level
`Test*` functions; the other three files contribute table rows / a helper invoked from `runConditionalAuthorizationTests`.
All need etcd (`main_test.go:25` `framework.EtcdMain`).

### Top-level tests and gate requirements

| Test | Line | `--feature-gates=ConditionalAuthorization=` | AuthorizationConditionsEnforcer | "active" (`featureEnabled && enforcerEnabled`) |
|---|---|---|---|---|
| `TestConditionalAuthorizationEnabled` | `conditionalauthorization_test.go:69` | true | enabled (default-on plugin) | yes |
| `TestConditionalAuthorizationDisabled` | `:76` | false | enabled (plugin present but `Handles()` false) | no |
| `TestConditionalAuthorizationEnforcerDisabled` | `:85` | true | `--disable-admission-plugins=AuthorizationConditionsEnforcer` (`:205`) | no |
| `TestMain` | `main_test.go:25` | n/a | n/a | etcd harness only |

All three share `runConditionalAuthorizationTests(t, featureEnabled, conditionsEnforcerEnabled)` (`:119`), which
starts a fresh kube-apiserver per top-level test via `kubeapiservertesting.StartTestServerOrDie` (`:207`) with
`--feature-gates=ConditionalAuthorization=<bool>` and `--authorization-config=<file>` (`:200-202`).

### How the authorizer / webhook is set up

- **Authorization chain** (`:171-191`): `AuthorizationConfiguration` v1 with `Webhook` named `conditional-webhook`
  (timeout 10s, `subjectAccessReviewVersion: v1`, `matchConditionSubjectAccessReviewVersion: v1`,
  `failurePolicy: NoOpinion`, `authorizedTTL: 1ms`, `unauthorizedTTL: 1ms`, `connectionInfo.type: KubeConfigFile`),
  followed by `RBAC` named `rbac`. The SAR-endpoint expectations (`:1076-1101`) show the server prepends
  `system-privileged-group.authorizer.kubernetes.io`.
- **`conditionsReview`** is written into the webhook config **only when the gate is on** (`:163-169`:
  `kubeConfigContextName: conditions`, `version: v1alpha1`). With the gate off it is omitted because validation
  forbids it (`staging/src/k8s.io/apiserver/pkg/apis/apiserver/validation/validation.go:759`). Consequence: the
  gate-off run never exercises "conditionsReview configured but gate off" at runtime (unreachable by design).
- **Webhook kubeconfig** (`:128-158`): two clusters/contexts pointing at the same `httptest.NewTLSServer`
  (`newWebhookServer`, `:1705`): context `default` → `/authorize` (SAR), context `conditions` →
  `/conditionsreview` (ACR). `insecure-skip-tls-verify: true`, empty user.
- **Mock webhook** (`webhookServerHandler`, `:1620-1700`): holds one swappable `authorizer.Authorizer`
  (`setAuthorizer`, `:1643`, stacks via `t.Cleanup`; nil → `forgotAuthorizer` that Denies with an error, `:1675-1695`).
  - `handleSAR` (`:1752`): converts the SAR spec through the real internal conversion + `AuthorizationAttributesFrom`
    (`sarSpecToAttributes`, `:1858`); calls `ConditionsAwareAuthorize` **only if**
    `authorizationv1.SupportsConditionalAuthorization(sar.Spec.AuthorizationOptions)` (`:1774`), else
    `ConditionsAwareDecisionFromParts(Authorize(...))`; writes status via `applyDecisionToSAR` (`:1869`,
    ConditionsMap/Union → `status.conditionalDecision` via `FromAuthorizerConditionsAwareDecision`).
  - `handleACR` (`:1788`): counts ACRs globally (`acrCount`) and per `admissionRequest.userInfo.username`;
    decodes `request.decision` with `ToAuthorizerConditionsAwareDecision` (decode failure → Deny "failed closed");
    rebuilds `admission.Attributes` from the embedded `AdmissionRequest` (object/oldObject as Unstructured,
    `:1933`); flags an error if the installed authorizer is `inProcessOnlyAuthorizer`; calls
    `EvaluateConditions`; responds with `uid` copied from `admissionRequest.uid` and an unconditional decision.
  - `testAuthorizer` (`:1899-1931`): `Authorize` folds conditional decisions to `FailureDecision()` with reason
    "failed closed"; `EvaluateConditions` runs `ConditionsMap.Evaluate` with a tiny CEL env exposing only
    `object`, `oldObject`, `request.operation` (`:1979-2045`). Non-ConditionsMap input → `FailureDecision` + error.
- **Variants per conditional row** (`celConditionalAuthorizerVariants`, `:1547-1567`):
  - `using-webhook-only`: condition type `example.com/opaque-cel-condition-type` → apiserver cannot evaluate in-process,
    must send ACR.
  - `in-process-eval-only`: type `authorizer.kubernetes.io/cel` (`ConditionTypeAuthorizationCEL`) wrapped in
    `inProcessOnlyAuthorizer` → any ACR is a test failure; expected ACR count forced to 0 (`:986-988`).
  - `if-in-process-fails-call-webhook`: CEL type but every expression prefixed `unsupported_in_tree && ` so in-tree
    compile fails; `webhookFallbackAuthorizer.EvaluateConditions` strips the prefix (`:1584`) → ACR expected.
  The in-process variants exist only because of PR #143024 (`git show --stat f410163f598` touches all three
  integration files).
- **Per-row assertions** (`:928-995`): impersonated user `<user>-<variant>`; expected allowed vs `IsForbidden`;
  `expectAllowedWhenDisabled` overrides when not active; per-user ACR count must equal `webhookEvaluations`
  when active (0 for in-process-only and when inactive). After the table (`:999-1005`): active ⇒ global ACR count > 0;
  inactive ⇒ exactly 0.
- RBAC grants via `authutil.GrantUserAuthorization` only for `conditional-noop-rbac-user`, `webhook-noop-rbac-user`
  (create configmaps) and `compound-authz-allow-user` (`use` on `example.com/protectedlabels/protected-label`)
  (`:950-969`).

### Scenarios (table rows; all are `create` in namespace `test-ns` unless noted)

Unconditional webhook decisions (single variant `""`):
1. **unconditional allow from webhook** (`:228`): webhook Allows → create configmap succeeds in all three modes;
   0 ACRs. Shows unconditional decisions are untouched by the feature.
2. **unconditional deny from webhook** (`:244`): webhook Denies → 403 in all modes; 0 ACRs.
3. **webhook no-opinion falls through to RBAC allow** (`:260`): NoOpinion → RBAC grant allows; all modes.

Conditional decisions, 3 variants each:
4. **conditional allow – condition evaluates to allow** (`:287`): allow-only map `true` → allowed when active with
   1 ACR (webhook variants); when inactive folds to NoOpinion → RBAC has no grant → 403.
5. **conditional deny – condition evaluates to deny** (`:315`): deny `true` + allow `true` → 403 when active
   (deny wins, 1 ACR); inactive: map with Deny folds to Deny → 403.
6. **conditional no-opinion falls through to RBAC allow** (`:348`): noOpinion-only map; the constructor folds it to
   NoOpinion immediately (`webhookEvaluations: 0`) → RBAC allows in every mode.

CEL-on-object conditions, 3 variants each:
7. **cel allow by name pattern** (`:387`): `object.metadata.name.startsWith("safe-")`, name `safe-…` → allowed when
   active; 403 when inactive.
8. **cel deny by name pattern mismatch** (`:413`): same condition, name `unsafe-…` → condition false → NoOpinion →
   no RBAC → 403 (all modes); 1 ACR when active.
9. **cel deny by label overrides allow** (`:438`): deny if label `restricted=true`, allow `true` → 403.
10. **cel allow by data content** (`:476`): allow if `object.data.approved=="yes"` → allowed when active.
11. **cel deny by data content missing** (`:505`): `approved: "no"` → 403.
12. **cel operation-aware deny update** (`:533`): deny `request.operation=="UPDATE"`, allow `=="CREATE"`; create then
    update → create allowed, update 403 (2 ACRs). Inactive: the create itself is 403 (no RBAC), so the expected
    Forbidden comes from the first call; the row does not distinguish which call failed.
13. **cel deny overrides allow and noopinion** (`:575`): all three effects `true` → 403.
14. **cel noopinion overrides allow** (`:615`): noOpinion if label `review=pending`, allow `true` → 403 (no RBAC).

Commented out (`:653-835`, `TODO(luxas): Reactivate this when we add support for update/patch -> create conditions`):
three "update-to-create" rows (PUT/apply of a non-existent Lease). They use the pre-#141959 `webhookBehaviors`
/ `celConditionalTestCases` shape and would not compile if uncommented. **Not covered on HEAD.**

In-process-only (`in-process-eval-only` single variant; need PR #143024):
15. **cel authorizer compound authorization – allow** (`:838`): condition requires
    `authorizer.group('example.com').resource('protectedlabels').name('protected-label').check('use').allowed()` when the
    object has `protected-label`; user has the RBAC grant → allowed when active, 403 inactive; webhook must see 0 ACRs.
16. **cel authorizer compound authorization – deny** (`:856`): same, user lacks grant → 403.
17. **cel namespaceObject – positive match** (`:876`): `namespaceObject.metadata.labels['env']=='production'`
    (namespace `test-ns` has `env: production`) → allowed when active.
18. **cel namespaceObject – negative match** (`:900`): requires `staging` → 403.

Multi-version CRD `scalablewidgets.example.com` (`crd_conversion_test.go`; v1 storage with `spec.replicas:int`, v2
with `spec.replicas.max:int`, webhook conversion via `crdconversiontesting` at `conditionalauthorization_test.go:193`;
3 variants each; decision built by `crdReplicasDecision` `crd_conversion_test.go:484`, version-specific CEL,
update requires both `object` and `oldObject` ≤ 10):
19–22. **crd v1/v2 create allowed/denied** (`:190`, `:221`, `:251`, `:284`): replicas 5 vs 15; the v2 rows prove the
   condition sees the object in the **request** version (v2 shape), not storage v1.
23–26. **crd v1/v2 update allowed/denied** (`:316`, `:354`, `:391`, `:435`): create 5 then update to 8 (allowed) or
   15 (denied); 2 ACRs. The v2 update rows are the only end-to-end check that `oldObject` is converted to the
   request version (storage is v1) — exercises PR #142493 `GetOldObject` on `VersionedAttributes`.

HPA built-in multi-version (`hpa_conversion_test.go`; `hpaCPUUtilizationDecision` `:299`, limit 80%; 3 variants):
27–30. **hpa v1/v2 cpu utilization allow/deny** (`:39`, `:62`, `:84`, `:118`): v1 `targetCPUUtilizationPercentage`
   80 vs 90; v2 `metrics[].resource.target.averageUtilization` 80 vs 90.
31–34. **hpa v1/v2 update allowed/denied** (`:151`, `:181`, `:210`, `:251`): 70→80 allowed, 70→90 denied; both
   object and oldObject checked in the request's version (in-tree conversion path).

Additional subtests after the table:
- **ValidatingAdmissionPolicy runs before the AuthorizationConditionsEnforcer** (`:1009`, active mode only;
  body `vap_ordering_test.go:47`): VAP rejecting names `vap-denied-*` + conditional allow with the same predicate.
  `policy rejects before conditions are evaluated` (`:123`): error carries the VAP message and 0 new ACRs.
  `conditions are evaluated after the policy admits` (`:137`): allowed name succeeds and ≥1 ACR. Guarantees the
  plugin order VAP → enforcer (`pkg/kubeapiserver/options/plugins.go:113-114`).
- **SAR / SelfSAR / LocalSAR endpoint matrix** (`:1014-1311`, gate on, both enforcer modes): 4 webhook behaviours
  (`conditional allow`, `unconditional allow`, `unconditional deny`, `conditional deny`) × 3 endpoints × 2 clients
  (`conditional-client` with `handledDecisionTypes` = all five; `unconditional-client` with nil options).
  Conditions-aware client gets `status.conditionalDecision` = a `Union` of
  `[system-privileged-group NoOpinion, conditional-webhook <decision>, rbac NoOpinion]`; unconditional decisions
  appear in `allowed/denied` with reason prefixed `conditional-webhook: {…}`. Unaware client gets folded results:
  conditional allow → `{Reason: "conditional-webhook: failed closed"}` (no-opinion), conditional deny →
  `{Denied: true, Reason: "failed closed"}`. (The two folded reasons differ in prefix; whether intentional is unclear.)
  Not run with the gate off, so "gate off ⇒ authorizationOptions ignored / conditionalDecision never returned" is
  covered only by unit tests (§1.4).
- **fold down for non-admission verb (GET configmap)** (`:1321`, gate on): conditional map with Deny on GET → 403
  (`:1335`); allow-only map on GET → NoOpinion → RBAC allows (`:1358`). Proves non-admission verbs use `Authorize`.
- **fold down for SubjectAccessReview create (excluded from admission)** (`:1395`, gate on): the webhook returns a
  conditional decision for `create subjectaccessreviews`; all four (Deny/NoOpinion fold) × (RBAC/no RBAC)
  combinations (`:1445`, `:1457`, `:1479`, `:1491`): only fold-to-NoOpinion + RBAC allows succeeds.

Coverage notes (test kind, for Stage 3b): no integration row uses DELETE, PATCH, apply, a subresource, `connect`,
an aggregated API, a webhook returning a top-level `Union`, or `failurePolicy: Deny`; update-to-create is disabled;
the integration webhook CEL env has no `request.*` beyond `operation`. Stale comment at
`conditionalauthorization_test.go:99` ("today only `using-webhook-only` is active") contradicts the three variants
at `:1547-1567`.

## 1.2 Core authorizer types — `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/`

`conditions_test.go`
- `TestConditionsAwareDecision` (`:54`, 67 cases): constructors and zero value (zero = Deny); `FromParts` with
  unsupported mode; ConditionsMap construction rules: >128 conditions, duplicate IDs, ID/type must be domain-prefixed
  keys, condition body ≤10240 B and description ≤1024 B at/over the limit, invalid input fails closed to Deny if any
  Deny condition else NoOpinion, empty map, noopinion-only short-circuit; Union simplification (empty, single leaf,
  all-NoOpinion merge, nested NoOpinion reason/error aggregation, first Allow/Deny wins, nested 2–3 level folds);
  `PossibleDecisions` per shape.
- `TestConditionsAwareDecisionConditionsMap_ClonesInputSlices` (`:1204`): mutating caller slices after construction
  does not change the decision.
- `TestSampleAuthorizer` (`:1239`): a sample conditions-aware authorizer (users alice…dave) driven through
  authorize + evaluate for list/create/update/delete, including object-vs-oldObject conditions (owner label,
  `supersecret`), unsupported verbs → NoOpinion.
- `TestConditionsAwareDecisionUnionedDecisions` (`:1584`): `UnionedDecisions` iterator empty for non-union, ordered,
  supports early break.
- `TestConditionsAwareDecisionUnconditionalParts` (`:1660`): `UnconditionalPartsOrError` / `OrFailClosed` for each
  shape (allow-only map → NoOpinion, map with deny → Deny, union of allow-only maps, zero value = Deny).

`conditionsunion_test.go`
- `TestConditionsAwareDecisionUnionAdd` (`:29`): builder rejects duplicate / empty / non-DNS-1123-subdomain authorizer
  names (fail closed), stops appending after first unconditional Allow/Deny, ConditionsMap leaves do not short-circuit.
- `TestConditionsAwareDecisionUnion_AddAfterToDecisionDoesNotMutate` (`:159`): decision returned by `ToDecision` is
  immune to later `Add` calls.

`evaluate_internal_test.go`
- `TestConditionsMapPartiallyEvaluate` (`:25`, 76 cases): full precedence table for one ConditionsMap: true Deny wins
  over everything (errors/unevaluatable ignored); Deny error → fail closed Deny; NoOpinion true/error beats Allow;
  Allow error → NoOpinion; all false → NoOpinion; unevaluatable conditions yield a refined residual map;
  `evaluateFunc` fallback is used only for conditions that cannot self-evaluate (panicking func proves "not called").

`evaluate_test.go`
- `TestPartiallyEvaluateConditionsAwareDecision` (`:28`, 12 cases): `PartiallyEvaluateConditionsAwareDecision` over a
  ConditionsMap and over Unions: full builtin evaluation to Deny/NoOpinion/Allow, partial refinement, union
  short-circuits after first concrete leaf, nil evaluate func still allows concrete results/refinement.

## 1.3 Union authorizer, metrics, CEL compile

`staging/src/k8s.io/apiserver/pkg/authorization/union/union_test.go`
- `TestAuthorizationSecondPasses` (`:65`), `TestAuthorizationFirstPasses` (`:76`), `TestAuthorizationNonePasses`
  (`:87`), `TestAuthorizationError` (`:98`), `TestAuthorizationResourceRules` (`:122`),
  `TestAuthorizationNonResourceRules` (`:186`), `TestAuthorizationUnequivocalDeny` (`:249`): legacy union
  semantics (first non-NoOpinion wins, error aggregation, rule resolver merging), now through conditions-aware fakes.
- `TestUnionEvaluateConditions` (`:358`, 29 cases): authorize + evaluate through a DAG of nested unions
  (union0=[union1,union3,authz5], union1=[union2,authz3], union2=[authz1,authz2], union3=[authz4]); short-circuits,
  each leaf's conditional result, eager simplification, error propagation, impossible sub-decision fails closed to
  the sub-authorizer's `FailureDecision`.
- `TestUnionConditionsAwareAuthorizeShortCircuit` (`:937`): later authorizers are not called after unconditional
  Allow/Deny.
- `TestUnionConditionsAwareAuthorizeEmptyChain` (`:988`): empty chain → NoOpinion.
- `TestUnionEvaluateConditionsRoutesByAuthorizerName` (`:1001`): `EvaluateConditions` dispatches by the authorizer
  name in the Union entry.
- `TestUnionEvaluateConditionsUnconditionalShortCircuit` (`:1032`): unconditional input returned immediately.

`staging/src/k8s.io/apiserver/pkg/authorization/metrics/metrics_test.go`
- `TestRecordAuthorizationDecisionsTotal` (`:29`): `apiserver_authorization_decisions_total` for a legacy and a
  conditions-aware instrumented authorizer, unconditional decisions only. `TODO(luxas)` at `:137`: no conditional
  decision / evaluation case.

`staging/src/k8s.io/apiserver/pkg/authorization/cel/compile_test.go`
- `TestCompileCELExpression` (`:33`): matchCondition compilation; includes `request.authorizationOptions.handledDecisionTypes`
  usable with gate on and "undefined field 'authorizationOptions'" with gate off (`:81-88`, gate set `:94`).
- `TestBuildRequestType` (`:111`, gate on): CEL decl type for `SubjectAccessReviewSpec` matches the Go type,
  including `AuthorizationOptions` and `[]ConditionsAwareDecisionType` (`:221-227`).

## 1.4 API types, encoding, validation

`staging/src/k8s.io/api/authorization/v1/util_test.go`
- `TestSupports` (`:26`): `SupportsConditionalAuthorization`/`SupportsUnconditionalAuthorization` for nil options,
  empty list (supports neither), unconditional set, all five, missing Union, missing NoOpinion.
- `TestGetHandledDecisionTypes` (`:110`): nil → unconditional set; empty → empty; exact set; duplicates collapse.
- `TestDecisionTypeAccessorsReturnFreshCopies` (`:168`) / `TestDecisionTypeListAccessorsReturnFreshCopies` (`:212`):
  exported set/list accessors return copies.

`staging/src/k8s.io/apiserver/pkg/apis/authorization/v1/encoding_test.go`
- `TestFromAuthorizerConditionsAwareDecision` (`:29`): internal → wire for Allow/Deny/NoOpinion (reason+error),
  ConditionsMap (three buckets), Union (recursive, ordered).
- `TestUnconditionalReason` (`:145`), `TestUnconditionalEvaluationError` (`:164`): nil/empty/non-empty helpers.
- `TestToAuthorizerConditionsAwareDecision` (`:189`): wire → internal; nil sub-object tolerated; nil ConditionsMap →
  empty; unknown type → `failClosed` callback.
- `TestSerializeDeserializeRoundTrip` (`:353`): round trip of unconditional decisions only (no ConditionsMap/Union
  round-trip case).

`staging/src/k8s.io/apiserver/pkg/apis/authorization/validation/validation_test.go`
- `TestValidateSARSpec` (`:47`): union of resource/non-resource attrs, subject required, selector rules;
  `authorizationOptions` must be ⊇ {Allow,Deny,NoOpinion}; at the 32-entry limit the superset check still runs.
- `TestValidateSelfSAR` (`:451`), `TestValidateLocalSAR` (`:567`): same rules for SelfSAR/LocalSAR + metadata/namespace
  rules and status validation.
- `TestValidateAuthorizationConditionsReview` (`:666`, gate on): through `CombinedValidate…`: response must be
  unconditional; request must be ConditionsMap/Union; metadata empty except managedFields; malformed conditions
  reported by DV; nil request and response accepted.
- `TestValidateSARStatus` (`:864`, gate on): `conditionalDecision` only when the spec opted in (nil/unconditional
  options rejected); type must not be Allow/Deny/NoOpinion; with ConditionsMap/Union `allowed`, `denied`, `reason`,
  `evaluationError` must be zero; unknown type / malformed contents rejected by DV.
- `TestCombinedValidateSubjectAccessReviewCreate` (`:1124`) / `TestCombinedValidateAuthorizationConditionsReviewCreate`
  (`:1184`): wrapper recovers panics and aggregates handwritten + declarative errors.

`staging/src/k8s.io/apiserver/pkg/apis/apiserver/validation/validation_test.go` (only the relevant functions;
the other 9 functions in the file — authn config, issuer URL, audiences, CA, claim rules/mappings, user rules —
are unrelated and match only because they share the file)
- `TestValidateAuthorizationConfiguration` (`:1706`): last 7 cases cover `conditionsReview` (valid KubeConfigFile; valid InClusterConfig without context name;
  forbidden with gate off `:2717`; context name forbidden with InClusterConfig; errors aggregate; only with SAR v1;
  absent+gate off valid).
- `TestValidateConditionsReviewConfiguration` (`:2746`): direct calls: version required / only `v1alpha1`;
  `kubeConfigContextName` only with KubeConfigFile (also rejected for empty connection type); gate off forbidden;
  all errors fire together.
- `TestNewWebhookMatcher` (`:2854`): pre-existing matchConditions compiler (moved by #140714).

`pkg/apis/authorization/v1beta1/conversion_test.go`
- `TestConvert_authorization_SubjectAccessReviewStatus_To_v1beta1_SubjectAccessReviewStatus` (`:41`): folding a
  conditional status to v1beta1 by `FailureDecision()`: map/union with any Deny → denied; else no opinion; nil map
  → no opinion; unknown type → denied.
- `..._DoesNotMutateInput` (`:220`): conversion deep-copies.

`pkg/api/testing/`
- `validation_test.go`: `TestVersionedValidationByFuzzing` (`:36`) fuzzes all DV kinds and skips
  `authorizationvalidation.OmittedFieldPaths()` (v1beta1 SAR `spec.authorizationOptions`, `status.conditionalDecision`,
  `pkg/apis/authorization/validation/validation.go:37-48`); `TestOmitErrorsForPaths` (`:109`) checks the omission
  helper matches only exact paths/children (`spec.authorizationOptionsX` kept).
- `conversion_test.go`: `TestMemoryIdenticalConversion` (`:219`) exempts SAR/SelfSAR/LocalSAR (issue #142345) and
  `AuthorizationConditionsReview` (embeds `AdmissionRequest`) at `:245-253`. The 3 benchmarks are unrelated.

`test/declarative_validation/authorization/*` (each `TestDeclarativeValidate`; the 4 `zz_generated.validations.*_test.go`
files contain no Test functions, only generated expectation tables)
- `authorizationconditionsreview/declarative_validation_test.go:39`: `request.admissionRequest` and `response.uid`
  required; decision `type` required/enum/member-must-match (request and response); condition id required / unique /
  label-key format; type label-key format; condition ≤10240 B; description ≤1024 B; >128 per list; union
  authorizerName required / unique / DNS subdomain.
- `subjectaccessreview/…:42`, `selfsubjectaccessreview/…:42`, `localsubjectaccessreview/…:42` (identical 27 cases each):
  unknown `handledDecisionTypes` accepted; `authorizationOptions` and `status.conditionalDecision` forbidden with gate
  off; `handledDecisionTypes` required when empty, unique, ≤32; same conditionalDecision rules as above.

## 1.5 SAR REST handlers — `pkg/registry/authorization/`

- `subjectaccessreview/rest_test.go`: `TestCreate` (`:148`, each case run with gate off and on `:554-556`): legacy
  allow/deny/selector cases plus handledTypes variants: unconditional set + ConditionsMap → unconditional fallback;
  conditional set → ConditionsMap returned; `[Allow]` only / `[Allow,ConditionsMap]` / `[]` (validation errors when
  gate on). `TestCreateIgnoresPostedStatus` (`:614`, gate off): posted bogus status cleared before validation (1.37
  compatibility).
- `selfsubjectaccessreview/rest_test.go:67`, `localsubjectaccessreview/rest_test.go:66`:
  `TestCreateIgnoresPostedStatus` — same compatibility pin.
- `util/helpers_test.go`: `TestResourceAttributesFrom` (`:37`) and `TestAuthorizationAttributesFrom` (`:95`) are
  pre-existing; `TestConditionsAwareDecisionToSARStatus` (`:601`): unconditional → top-level fields (evaluation
  error kept), ConditionsMap → `conditionalDecision`, nested Union preserves authorizer names.

## 1.6 Handler chain / request context

`staging/src/k8s.io/apiserver/pkg/endpoints/filters/authorization_test.go`
- `TestGetAuthorizerAttributes` (`:48`), `TestAuditAnnotation` (`:255`): pre-existing.
- `TestWithAuthorization` (`:335`): legacy and conditions-aware filter: nil authorizer, allow/deny/no-opinion (±error),
  conditional allow with classifier true (passes, decision in context) / false / nil (403), deny-only map with
  classifier true (403 at filter).

`staging/src/k8s.io/apiserver/pkg/endpoints/filters/metrics_test.go`
- `TestMetrics` (`:40`): authn metrics, unrelated. `TestRecordAuthorizationMetricsMetrics` (`:170`, gate on `:274`):
  `authorization_attempts_total` / decision annotations for each variant; conditional deny counts as "denied",
  conditional allow with classifier false/nil as "no-opinion", with classifier true as "conditional".

`staging/src/k8s.io/apiserver/pkg/endpoints/request/context_test.go`
- `TestNamespaceContext` (`:29`), `TestUserContext` (`:47`): pre-existing. `TestConditionallyAuthorizedDecisionContext`
  (`:109`): empty context → not ok + zero Deny; store/retrieve; second store errors and keeps the first.

## 1.7 Admission enforcer — `staging/src/k8s.io/apiserver/pkg/admission/plugin/authorizer/conditionsenforcer/`

- `conditionsenforcer_test.go`: `TestConditionsEnforcerInitialization` (`:262`): `ValidateInitialization` errors if
  `InspectFeatureGates` not called; `Handles` false with gate off, true with gate on; `Validate` with no decision in
  context errors only when enabled. `TestConditionsEnforcerEndToEnd` (`:322`, gate on `:542`): filter + update handler
  + enforcer: unconditional outcomes at the filter; conditional allow + classifier true → evaluation Allow succeeds,
  NoOpinion/Deny (±error) rejected in admission, evaluation on the versioned object, classifier false/nil → 403 at
  filter, evaluator returning an impossible Deny → internal error.
- `context_invariant_test.go`: `TestConditionsEnforcerContextInvariant` (`:68`): over gate × enforcer × filter ×
  context-detach, with gate on the filter always registers a decision and the enforcer fails a request whose
  decision was lost (detached context).

## 1.8 Webhook authorizer — `staging/src/k8s.io/apiserver/plugin/pkg/authorizer/webhook/webhook_conditional_test.go`
(every function sets the gate on)

- `TestConditionsAwareAuthorize` (`:168`): SAR response parsing: ConditionsMap, allow/deny/no-opinion, webhook error
  with each failurePolicy, invalid combos (allowed+denied, conditional+denied/allowed), union, no reviewer: unconditional
  allow honored, unrequested conditional fails closed.
- `TestAuthorize_FoldDown` (`:371`): `Authorize` folds maps with (transitive) Deny → Deny, allow-only → NoOpinion,
  denied + allow-only stays Deny.
- `TestEvaluateConditions` (`:481`): unconditional input rejected with `FailureDecision`; no reviewer; webhook
  returns allow/deny/no-opinion; webhook error per failurePolicy; nil response; ACR request contents (conditions,
  union, apiVersion/kind required for object and oldObject, typed-nil skipped); invalid responses (unknown type,
  Allow without member, unset type) fail closed; responses impossible for the decision (Allow for deny-only map, Deny
  for allow-only map, NoOpinion for a union with an unconditional allow leaf) fail closed.
- `TestConditionsAwareAuthorize_EndToEnd` (`:1039`): real HTTP server; spec carries `authorizationOptions`, conditional
  response decoded.
- `TestEvaluateConditions_EndToEnd` (`:1102`): real HTTP server for ACR round trip.
- `TestConditionsAwareAuthorize_V1beta1Downgrade` (`:1216`): v1beta1 webhook: unconditional decisions and evaluation
  error kept; a conditional decision in a v1beta1 response is dropped.
- `TestConditionalResponseCaching` (`:1321`): conditional response cached under `authorizedTTL` only for a
  conditions-aware caller; unaware caller does not cache it as authorized; denials still `unauthorizedTTL`.
- `TestEvaluateConditions_Builtins` (`:1428`, #143024): fully in-process → webhook not called; partial → webhook gets
  refined decision; in-process error or builder failure → webhook gets original decision.
- `TestEvaluateConditions_BuiltinsWithoutContextAuthorizer` (`:1530`, #143024): builder gets a nil authorizer when the
  context has none and still resolves.

## 1.9 Related tests not matched by the keyword filter

- `staging/src/k8s.io/apiserver/pkg/admission/plugin/cel/authorization_conditions_test.go` (#143024, 4 functions):
  `TestAuthorizationConditionsEvaluator_EvaluateCondition` (`:135`): nil/wrong-type/empty condition → Unevaluatable;
  true/false over `object`, `oldObject`, `request.*`, `namespaceObject`, `authorizer` checks; invalid CEL and cost
  budget exceeded → Error; `authorizer` undeclared without one. `TestNewAuthorizationConditionsEvaluatorBuilder`
  (`:303`): nil informer factory / client → error and nil interface. `TestAuthorizationConditionsEvaluatorBuilder_EvaluatorForData`
  (`:318`): nil data, unversioned attributes, missing namespace, versioned attributes, cluster-scoped.
  `TestAuthorizationConditionsEvaluator_CachesAuthorizerChecks` (`:366`): identical authorizer checks hit the
  authorizer once.
- `pkg/controlplane/apiserver/config_test.go`: `TestConditionalRequestClassifier` (`:86`): URL-derived attributes;
  POST/PUT/PATCH/DELETE(-collection) on resources (including CRDs and `*` segments) → true; GET/LIST/WATCH, admission-
  excluded resources (e.g. `localsubjectaccessreviews`), non-resource URLs → false. (`TestBuildGenericConfig` `:41` is
  unrelated.)
- `test/integration/apiserver/conditionalauthorization/main_test.go`: `TestMain` (`:25`).

## 1.10 Incidental matches (fake authorizer gained stub methods only; no feature behaviour tested)

- `pkg/registry/core/serviceaccount/storage/token_test.go` (stub `:517-521`): `TestCreate_Token_WithExpiryCap`,
  `TestTokenRequest_ServiceAccountUIDValidation`, `TestValidateWebhookAudience`, `TestValidateAttestationAPIGroup`,
  `TestTokenRESTCreateWebhookAuthenticationFlow`, `TestTokenRESTCreateWebhookExpirationCap`,
  `TestTokenRESTCreateWebhookDeletionTimestamp` — token request API.
- `plugin/pkg/admission/gc/gc_admission_test.go` (stub `:103-109`): `TestGCAdmission`, `TestBlockOwnerDeletionAdmission`.
- `staging/src/k8s.io/apiserver/pkg/admission/initializer/initializer_test.go` (stub `:185-191`):
  `TestWantsUnconditionalAuthorizer` (`:36`) and `TestWantsAuthorizer` (`:47`) are series-related (rename #138801 /
  re-added `WantsAuthorizer` #140916: the authorizer is injected through each interface); `TestWantsExternalKubeClientSet`,
  `TestWantsExternalKubeInformerFactory`, `TestWantsShutdownNotification`, `TestRESTMapperAdmissionPlugin` unrelated.
- `staging/src/k8s.io/apiserver/pkg/server/genericapiserver_test.go` (stub `:583-589`): 10 functions
  (`TestNew` … `TestWarningWithRequestTimeout`), unrelated.
- `test/integration/apiserver/flowcontrol/concurrency_util_test.go` (stub `:135-141`): `TestConcurrencyIsolation`.
- `test/integration/auth/accessreview_test.go` (stub `:50-56`): `TestSubjectAccessReview`, `TestSelfSubjectAccessReview`,
  `TestLocalSubjectAccessReview` — legacy SAR behaviour with a conditions-unaware authorizer (useful as gate-default
  regression, not as feature tests).
- `test/integration/auth/auth_test.go` (stubs `:817-823`, `:1852-1858`): 16 functions (`TestAuthModeAlwaysAllow` …
  `TestSloppySANCertificates`), unrelated.
- `pkg/api/testing/conversion_test.go` is listed in §1.4 (one exemption list); its benchmarks are unrelated.

---

# 2. Feature-gate census (`ConditionalAuthorization`)

Search: `grep -rnE '\.ConditionalAuthorization([^A-Za-z]|$)|"ConditionalAuthorization"' --include='*.go' pkg staging plugin cmd test`
(vendor excluded) plus `+featureGate=` / `+k8s:if*` tags. `cmd/` has **no** reference.

## 2.1 Hand-written code sites (20)

| # | path:line | What it does | Class |
|---|---|---|---|
| 1 | `staging/src/k8s.io/apiserver/pkg/features/kube_features.go:100` | `ConditionalAuthorization featuregate.Feature` constant | registration (gate) |
| 2 | `staging/src/k8s.io/apiserver/pkg/features/kube_features.go:404` | versioned spec `{1.38, Default false, Alpha}` for generic apiservers | registration (gate) |
| 3 | `pkg/features/kube_features.go:2156` | same spec in kube's `defaultVersionedKubernetesFeatureGates` | registration (gate) |
| 4 | `pkg/features/kube_features.go:2720` | entry in `defaultKubernetesFeatureGateDependencies` (`:2346`): no dependencies | registration (gate) |
| 5 | `pkg/controlplane/apiserver/config.go:248` | sets `genericConfig.Authorization.ConditionalAuthorizationRequestClassifier = conditionalRequestClassifier` | enables new code path |
| 6 | `staging/src/k8s.io/apiserver/pkg/server/config.go:1077` | `DefaultBuildHandlerChain` uses `WithConditionsAwareAuthorization` only if gate on ∧ classifier ≠ nil ∧ `ConditionsEnforcerPluginEnabled`; else legacy `WithAuthorization` | enables new code path |
| 7 | `staging/src/k8s.io/apiserver/pkg/server/config.go:1089` | warns when gate on but enforcer plugin disabled | enables new code path (diagnostic) |
| 8 | `staging/src/k8s.io/apiserver/pkg/endpoints/filters/authorization.go:101` | legacy filter registers the Allow decision in the request context (so the enforcer's "decision must be present" check holds) | enables new code path |
| 9 | `staging/src/k8s.io/apiserver/pkg/endpoints/filters/authorization.go:136` | `WithConditionsAwareAuthorization` errors unless gate on and classifier non-nil | enables new code path (precondition) |
| 10 | `staging/src/k8s.io/apiserver/pkg/admission/plugin/authorizer/conditionsenforcer/conditionsenforcer.go:64` | `InspectFeatureGates` stores the gate; `Handles` (`:75`) and `Validate` (`:80`) are no-ops when off | enables new code path |
| 11 | `pkg/kubeapiserver/authorizer/reload.go:189` | loads the `conditionsReview` kubeconfig context and (#143024, `:204`) builds the in-process CEL evaluator only when on | enables new code path |
| 12 | `staging/src/k8s.io/apiserver/plugin/pkg/authorizer/webhook/webhook.go:155` | keeps the ACR reviewer only when on; `handlesConditional := reviewer != nil` (`:287`) decides whether SARs carry `authorizationOptions` | enables new code path |
| 13 | `staging/src/k8s.io/apiserver/pkg/authorization/cel/compile.go:218` | adds `authorizationOptions` to the matchConditions CEL `request` type | enables new code path (CEL surface) |
| 14 | `staging/src/k8s.io/apiserver/pkg/authorization/cel/compile.go:344` | populates `request.authorizationOptions` value | enables new code path (CEL surface) |
| 15 | `pkg/registry/authorization/subjectaccessreview/rest.go:78` | gate off ⇒ `Spec.AuthorizationOptions = nil` before validation | clears API fields when off |
| 16 | `pkg/registry/authorization/selfsubjectaccessreview/rest.go:79` | same for SelfSAR | clears API fields when off |
| 17 | `pkg/registry/authorization/localsubjectaccessreview/rest.go:80` | same for LocalSAR | clears API fields when off |
| 18 | `pkg/registry/authorization/util/helpers.go:252` | `ResolveAuthorizationOptions` returns "unconditional only" when off (redundant with 15–17) | enables new code path |
| 19 | `staging/src/k8s.io/apiserver/pkg/apis/apiserver/validation/validation.go:759` | `conditionsReview` in AuthorizationConfiguration Forbidden when off | validation |
| 20 | `staging/src/k8s.io/apiserver/pkg/apis/authorization/validation/validation.go:313` | `DeclarativeValidationConfig()` passes the gate as DV option `"ConditionalAuthorization"` | validation |

No gate reference exists in `cmd/`, `plugin/pkg/`, or `pkg/kubeapiserver/options/`.

Note: SAR status is not cleared when the gate is off; it is generated by the server, which with the gate off only
takes the unconditional path (15–18), and DV forbids `status.conditionalDecision` with the gate off (§2.2). The
gate-off webhook response path relies on site 12 (no `authorizationOptions` sent) plus the webhook's own
"unrequested conditional decision fails closed" handling (tested `webhook_conditional_test.go:168`, with the gate on).

## 2.2 API tags and generated validation (validation)

- Tags on `staging/src/k8s.io/api/authorization/v1/types.go`: `+featureGate=ConditionalAuthorization` +
  `+k8s:ifEnabled(...)=+k8s:optional` + `+k8s:ifDisabled(...)=+k8s:forbidden` on
  `SubjectAccessReviewSpec.AuthorizationOptions` (`:236-238`), `SelfSubjectAccessReviewSpec.AuthorizationOptions`
  (`:269-271`), `SubjectAccessReviewStatus.ConditionalDecision` (`:304-306`).
- Internal `pkg/apis/authorization/types.go:185, :205, :235`: `+featureGate=ConditionalAuthorization` only (doc/openapi).
- Generated `validate.IfOption(..., "ConditionalAuthorization", ...)`: `staging/src/k8s.io/api/authorization/v1/zz_generated.validations.go:876-886, :1060-1070, :1114-1124`
  and `pkg/apis/authorization/v1/zz_generated.validations.go:932-942, :1116-1126, :1170-1180` (9 calls each).
  Options come from site 20. `v1beta1` has no such fields; v1beta1 conversion folds instead
  (`pkg/apis/authorization/v1beta1`, tested §1.4).
- `AuthorizationConditionsReview` (v1alpha1) has **no** gate tags; it is not served (§2.4), so gating applies only
  through its configuration (site 19) and the webhook (site 12).

## 2.3 Test setup sites (30)

`SetFeatureGateDuringTest(..., ConditionalAuthorization, ...)` — 29 calls:
`webhook_conditional_test.go` ×9 (`:169, :372, :482, :1040, :1103, :1217, :1322, :1429, :1531`, all true);
`apis/authorization/validation/validation_test.go` ×4 (`:667, :865, :1125, :1185`, true);
`apis/apiserver/validation/validation_test.go` ×2 (`:2717, :2845`, table-driven);
`authorization/cel/compile_test.go` ×2 (`:94` table, `:112` true);
`conditionsenforcer_test.go` ×2 (`:295` table, `:542` true); `context_invariant_test.go:111` (loop false/true);
`endpoints/filters/authorization_test.go:481` (true); `endpoints/filters/metrics_test.go:274` (true);
`pkg/registry/authorization/subjectaccessreview/rest_test.go` ×2 (`:556` loop, `:615` false);
`selfsubjectaccessreview/rest_test.go:68` (false); `localsubjectaccessreview/rest_test.go:67` (false);
`test/declarative_validation/authorization/{subject,selfsubject,localsubject}accessreview/declarative_validation_test.go:392/:391/:392`
(per case). Plus the integration flag `test/integration/apiserver/conditionalauthorization/conditionalauthorization_test.go:201`.

Gate-off coverage gaps (test): no unit test runs `webhook.newWithBackoff` with the gate off (site 12 only via the
integration Disabled run, where no `conditionsReview` is configured anyway); no test runs
`pkg/controlplane/apiserver/config.go:248` with the gate off other than the integration Disabled run;
`authorizer/reload.go:189` gate-off branch is unreachable with a valid config (site 19).

## 2.4 API-group registration of `authorization.k8s.io/v1alpha1`

- Types: `staging/src/k8s.io/api/authorization/v1alpha1/register.go:44-50` registers only `AuthorizationConditionsReview`;
  `+k8s:prerelease-lifecycle-gen:introduced=1.38` (`types.go:30`); `+genclient` / `+genclient:onlyVerbs=create`
  (`types.go:26-28`), so a typed client is generated even though nothing serves it.
- Internal scheme: `pkg/apis/authorization/install/install.go:38` `v1alpha1.AddToScheme(scheme)` into `legacyscheme`;
  version priority v1 > v1beta1 > v1alpha1 (`:41`). Internal kind exists (`pkg/apis/authorization/validation/validation.go`
  `ValidateAuthorizationConditionsReviewCreate`).
- **Not served**: `pkg/registry/authorization/rest/storage_authorization.go:44-46` only installs `v1` storage
  (SAR, SelfSAR, LocalSAR, SelfSubjectRulesReview); no `v1alpha1` resource, no entry in
  `pkg/controlplane/apiserver/aggregator.go` priorities (`:326` lists only `authorization.k8s.io/v1`), no resource-config
  default. `AuthorizationConditionsReview` is a webhook wire type (like `AdmissionReview`), not an API resource.
- How it is "enabled": per webhook authorizer, by `AuthorizationConfiguration.authorizers[].webhook.conditionsReview`
  (`version: v1alpha1`), only valid with the gate on (site 19) and with `subjectAccessReviewVersion: v1`
  (`validation.go:740-741`), loaded at `reload.go:189`, kept at `webhook.go:155`.

## 2.5 AuthorizationConditionsEnforcer admission plugin

- Registration: generic `staging/src/k8s.io/apiserver/pkg/server/plugins.go:35` (`conditionsenforcer.Register`), called by
  `genericoptions.NewAdmissionOptions` (`staging/src/k8s.io/apiserver/pkg/server/options/admission.go:100`), which kube's
  `NewAdmissionOptions` wraps (`pkg/kubeapiserver/options/admission.go:57`). `pkg/kubeapiserver/options/plugins.go`
  `RegisterAllAdmissionPlugins` (`:128-163`) does not register it itself.
- **Default on** for kube-apiserver: listed in `defaultOnPlugins` (`pkg/kubeapiserver/options/plugins.go:193`, comment
  "only active when feature gate ConditionalAuthorization is enabled"); generic apiserver `DefaultOffPlugins` is empty
  (`admission.go:98`); sample generic controlplane also default-on (`pkg/controlplane/apiserver/samples/generic/server/admission.go:52`).
  With the gate off it is in the chain but `Handles()` returns false (site 10).
- Order in `AllOrderedPlugins` (`pkg/kubeapiserver/options/plugins.go:73-118`): position 37 of 40, after
  `MutatingAdmissionPolicy` (`:111`), `MutatingAdmissionWebhook` (`:112`), `ValidatingAdmissionPolicy` (`:113`);
  then `AuthorizationConditionsEnforcer` (`:114`, comment "after VAP to avoid having to send webhooks unless needed"),
  then `ValidatingAdmissionWebhook` (`:115`), `ResourceQuota` (`:116`), `AlwaysDeny` (`:117`). Generic order:
  `admission.go:97` (…, VAP, enforcer, ValidatingAdmissionWebhook). As a validating plugin it runs after all mutating
  plugins regardless of list position (comment `admission.go:93-96`).
- Enforcement wiring: `admission.go:183` sets `c.Authorization.ConditionsEnforcerPluginEnabled` from the enabled plugin
  list; `config.go:1077` requires it for the conditions-aware filter (so disabling the plugin disables conditional
  authorization, as `TestConditionalAuthorizationEnforcerDisabled` asserts).

---

# 3. API surface

## 3.1 `staging/src/k8s.io/api/authorization/v1/types.go` (new or changed for this feature)

`SubjectAccessReviewSpec` (`:204`), new field (`:231-239`):

```go
	// authorizationOptions contains options for specifying the client's authorization abilities.
	// If unset, only unconditional authorization is supported, for backwards-compatibility.
	// Requires the ConditionalAuthorization feature to be enabled.
	// +optional
	// +featureGate=ConditionalAuthorization
	// +k8s:ifEnabled("ConditionalAuthorization")=+k8s:optional
	// +k8s:ifDisabled("ConditionalAuthorization")=+k8s:forbidden
	AuthorizationOptions *AuthorizationOptions `json:"authorizationOptions,omitempty" protobuf:"bytes,7,opt,name=authorizationOptions"`
```

`SelfSubjectAccessReviewSpec` (`:253`), new field (`:264-272`):

```go
	// authorizationOptions contains options for specifying the client's authorization abilities.
	// If unset, only unconditional authorization is supported, for backwards-compatibility.
	// Requires the ConditionalAuthorization feature to be enabled.
	// +optional
	// +featureGate=ConditionalAuthorization
	// +k8s:ifEnabled("ConditionalAuthorization")=+k8s:optional
	// +k8s:ifDisabled("ConditionalAuthorization")=+k8s:forbidden
	AuthorizationOptions *AuthorizationOptions `json:"authorizationOptions,omitempty" protobuf:"bytes,3,opt,name=authorizationOptions"`
```

(`LocalSubjectAccessReview` reuses `SubjectAccessReviewSpec`.)

`SubjectAccessReviewStatus` (`:275-308`, doc comments of `allowed`/`denied` updated, new `conditionalDecision`):

```go
// SubjectAccessReviewStatus
type SubjectAccessReviewStatus struct {
	// allowed is true if the action would be allowed, false otherwise.
	// allowed=true is mutually exclusive with denied=true and conditionalDecision != nil.
	// +optional
	Allowed bool `json:"allowed" protobuf:"varint,1,opt,name=allowed"`
	// denied is optional. True if the action would be denied, otherwise false
	// If allowed is false, denied is false, and conditionalDecision is unset,
	// then the authorizer has no opinion on whether to authorize the action.
	// denied=true is mutually exclusive with allowed=true and conditionalDecision != nil.
	// +optional
	Denied bool `json:"denied,omitempty" protobuf:"varint,4,opt,name=denied"`
	// reason is optional.  It indicates why a request was allowed or denied.
	// +optional
	Reason string `json:"reason,omitempty" protobuf:"bytes,2,opt,name=reason"`
	// evaluationError is an indication that some error occurred during the authorization check.
	// It is entirely possible to get an error and be able to continue determine authorization status in spite of it.
	// For instance, RBAC can be missing a role, but enough roles are still present and bound to reason about the request.
	// +optional
	EvaluationError string `json:"evaluationError,omitempty" protobuf:"bytes,3,opt,name=evaluationError"`

	// conditionalDecision represents a conditional decision returned by the authorizer.
	// When conditionalDecision is set, allowed, denied, reason and evaluationError must have their zero values.
	// The top-level decision type should be ConditionsAwareDecisionTypeConditionsMap or
	// ConditionsAwareDecisionTypeUnion, as Allow/Deny/NoOpinion decisions can be represented
	// with SubjectAccessReviewStatus.Allowed and SubjectAccessReviewStatus.Denied alone.
	// May only be set if spec.authorizationOptions.handledDecisionTypes includes `ConditionsMap` and `Union`.
	// Requires the ConditionalAuthorization feature to be enabled.
	// +optional
	// +featureGate=ConditionalAuthorization
	// +k8s:ifEnabled("ConditionalAuthorization")=+k8s:optional
	// +k8s:ifDisabled("ConditionalAuthorization")=+k8s:forbidden
	ConditionalDecision *ConditionsAwareDecision `json:"conditionalDecision,omitempty" protobuf:"bytes,5,opt,name=conditionalDecision"`
}
```

New types (`:411-625`):

```go
// AuthorizationOptions contains options for specifying the client's authorization abilities.
type AuthorizationOptions struct {
	// handledDecisionTypes specifies what decision types the client can handle in the context it is in.
	// Currently valid values are:
	// - [Allow, Deny, NoOpinion] (for conditions-unaware clients) or
	// - [Allow, Deny, NoOpinion, ConditionsMap, Union, ...] (for conditions-aware clients)
	// If the authorizer would like to return conditions, but the client does not opt in to handle those here,
	//   the authorizer must fail closed to a safe unconditional decision
	//   (Deny if any Deny conditions were present, otherwise NoOpinion).
	// Order does not matter in this slice; set semantics should be used.
	// The server does not reject unrecognized decision types, but focuses on whether the client
	// supports a mode that the server does. All clients must support "classic", conditions-unaware authorization.
	// +listType=set
	// +k8s:listType=set
	// +k8s:required
	// +required
	// +k8s:eachVal=+k8s:opaqueType
	// +k8s:maxItems=32
	HandledDecisionTypes []ConditionsAwareDecisionType `json:"handledDecisionTypes" protobuf:"bytes,1,rep,name=handledDecisionTypes"`
}

// Condition represents a single authorization condition to be evaluated against
// data available later in the request chain, e.g. objects available in admission.
type Condition struct {
	// id uniquely identifies this condition within the scope of the authorizer
	// that authored it and ConditionsMap it is part of. Validated as a Kubernetes label key.
	// Any domain of form *.k8s.io or *.kubernetes.io is reserved for Kubernetes use.
	// +k8s:required
	// +k8s:format=k8s-prefixed-label-key
	// +required
	ID string `json:"id" protobuf:"bytes,1,opt,name=id"`

	// condition returns a string encoding of the condition to be evaluated.
	// It is a pure, deterministic function from ConditionsData to a boolean (or error).
	// Might or might not be human-readable.
	// Optional, if the ID alone is enough for the authorizer to know how to evaluate the condition.
	// +k8s:maxBytes=10240
	// +k8s:optional
	// +optional
	Condition string `json:"condition,omitempty" protobuf:"bytes,2,opt,name=condition"`

	// type describes the type of the condition, if there are multiple possibilities.
	// Should be formatted as a Kubernetes label key.
	// Any domain of form *.k8s.io or *.kubernetes.io is reserved for Kubernetes use.
	// authorizer.kubernetes.io/cel is a conditions type for CEL, handled by kube-apiserver.
	// Optional. Can be omitted if the authorizer already knows how to evaluate the condition.
	// +k8s:format=k8s-prefixed-label-key
	// +k8s:optional
	// +optional
	Type string `json:"type,omitempty" protobuf:"bytes,3,opt,name=type"`

	// description is an optional human-friendly description that can be shown
	// as an error message or for debugging. Optional.
	// +k8s:maxBytes=1024
	// +k8s:optional
	// +optional
	Description string `json:"description,omitempty" protobuf:"bytes,4,opt,name=description"`
}

// ConditionsMap represents a map of conditions, keyed by ID across all conditions, across
// all effects. The ConditionsMap must have at least one Allow condition or at least one
// Deny condition. It cannot contain more than 128 conditions in total. The conditions are evaluated
// against data available later, to determine whether the authorizer that authored the conditions
// allows or denies the request.
// If all conditions in the map evaluate to false, the final decision must be NoOpinion.
type ConditionsMap struct {
	// denyConditions contains the conditions with Deny effect. If any such condition evaluates to
	// true or error, the ConditionsMap as a whole must evaluate to Deny.
	// +listType=map
	// +listMapKey=id
	// +k8s:listType=map
	// +k8s:listMapKey=id
	// +k8s:maxItems=128
	// +k8s:optional
	// +optional
	DenyConditions []Condition `json:"denyConditions,omitempty" protobuf:"bytes,1,rep,name=denyConditions"`

	// noOpinionConditions contains the conditions with NoOpinion effect. If any such condition evaluates to
	// true or error, the ConditionsMap as a whole must evaluate to NoOpinion.
	// +listType=map
	// +listMapKey=id
	// +k8s:listType=map
	// +k8s:listMapKey=id
	// +k8s:maxItems=128
	// +k8s:optional
	// +optional
	NoOpinionConditions []Condition `json:"noOpinionConditions,omitempty" protobuf:"bytes,2,rep,name=noOpinionConditions"`

	// allowConditions contains the conditions with Allow effect. If any such condition evaluates to
	// true, the ConditionsMap as a whole must evaluate to Allow.
	// +listType=map
	// +listMapKey=id
	// +k8s:listType=map
	// +k8s:listMapKey=id
	// +k8s:maxItems=128
	// +k8s:optional
	// +optional
	AllowConditions []Condition `json:"allowConditions,omitempty" protobuf:"bytes,3,rep,name=allowConditions"`
}

// ConditionsAwareDecisionType is an enum representing what kind of authorization decision
// the ConditionsAwareDecision represents.
// +k8s:enum
type ConditionsAwareDecisionType string

const (
	// ConditionsAwareDecisionTypeDeny represents an unconditional Deny authorizer decision.
	ConditionsAwareDecisionTypeDeny ConditionsAwareDecisionType = "Deny"

	// ConditionsAwareDecisionTypeAllow represents an unconditional Allow authorizer decision.
	ConditionsAwareDecisionTypeAllow ConditionsAwareDecisionType = "Allow"

	// ConditionsAwareDecisionTypeNoOpinion represents an unconditional NoOpinion authorizer decision,
	// which means that the authorizer does not have a specific opinion on whether the request
	// should be allowed or denied, and thus can other authorizers later in the union have their say.
	ConditionsAwareDecisionTypeNoOpinion ConditionsAwareDecisionType = "NoOpinion"

	// ConditionsAwareDecisionTypeConditionsMap represents an authorizer decision that is dependent
	// on request data available later in the request chain, and thus at this stage conditional.
	ConditionsAwareDecisionTypeConditionsMap ConditionsAwareDecisionType = "ConditionsMap"

	// ConditionsAwareDecisionTypeUnion is a decision type whose final decision is computed by
	// an ordered list of sub-authorizers, with their individual decisions. A decision can thus
	// be represented as a tree, with Union decisions being internal nodes, and
	// Deny/Allow/NoOpinion/ConditionsMap decisions being leaf nodes, which are visited in depth-first order.
	ConditionsAwareDecisionTypeUnion ConditionsAwareDecisionType = "Union"
)

// ConditionsAwareDecision represents one authorizer's decision. It is an enum type,
// with variants described in ConditionsAwareDecisionType, plus a reason and error.
type ConditionsAwareDecision struct {
	// type describes the type of the decision, and acts as an enum discriminator.
	// +k8s:unionDiscriminator
	// +k8s:required
	// +required
	Type ConditionsAwareDecisionType `json:"type" protobuf:"bytes,1,opt,name=type,casttype=ConditionsAwareDecisionType"`

	// deny represents an unconditional Deny decision.
	// Must be non-null when type == "Deny", otherwise this field must be unset.
	// +k8s:unionMember
	// +k8s:optional
	// +optional
	Deny *UnconditionalDecision `json:"deny,omitempty" protobuf:"bytes,2,opt,name=deny"`

	// noOpinion represents an unconditional NoOpinion decision.
	// Must be non-null when type == "NoOpinion", otherwise this field must be unset.
	// +k8s:unionMember
	// +k8s:optional
	// +optional
	NoOpinion *UnconditionalDecision `json:"noOpinion,omitempty" protobuf:"bytes,3,opt,name=noOpinion"`

	// allow represents an unconditional Allow decision.
	// Must be non-null when type == "Allow", otherwise this field must be unset.
	// +k8s:unionMember
	// +k8s:optional
	// +optional
	Allow *UnconditionalDecision `json:"allow,omitempty" protobuf:"bytes,4,opt,name=allow"`

	// conditionsMap represents a conditional decision, modelled as a map of conditions.
	// Must be non-null when type == "ConditionsMap", otherwise this field must be unset.
	// +k8s:unionMember
	// +k8s:optional
	// +optional
	ConditionsMap *ConditionsMap `json:"conditionsMap,omitempty" protobuf:"bytes,5,opt,name=conditionsMap"`

	// union forms an ordered tree of decisions, where the union decision is represented by
	// an internal node, and all other decision types are leaf nodes. During evaluation, the
	// leaf decisions are evaluated in depth-first order, until an Allow or Deny decision is found.
	// The order of the decisions should match the order of the authorizers in the union authorizer
	// for interpretability, but the authorizerName is the map key.
	// At least one of the leaves must be of type ConditionsMap, as otherwise the union could be trivially
	// reduced to just a single Allow/Deny/NoOpinion.
	//
	// Must have at least one element when type == "Union", otherwise this field must be unset.
	//
	// +k8s:unionMember
	// +k8s:optional
	// +optional
	// +k8s:listType=map
	// +k8s:listMapKey=authorizerName
	// +listType=map
	// +listMapKey=authorizerName
	Union []NamedConditionsAwareDecision `json:"union,omitempty" protobuf:"bytes,6,rep,name=union"`
}

// NamedConditionsAwareDecision is a named ConditionsAwareDecision, returned by a unioned authorizer.
type NamedConditionsAwareDecision struct {
	// authorizerName details the name of the authorizer that authored the condition, such that
	// the right Decision can be paired with the right authorizer when evaluating the conditions,
	// even across API server replicas. The name must be stable over time.
	// This name must be unique within a given union authorizer, not necessarily globally.
	// +required
	// +k8s:required
	// +k8s:format=k8s-long-name
	AuthorizerName string `json:"authorizerName" protobuf:"bytes,1,opt,name=authorizerName"`

	// decision carries the inner decision returned from the authorizer.
	// +required
	Decision ConditionsAwareDecision `json:"decision" protobuf:"bytes,2,opt,name=decision"`
}

// UnconditionalDecision represents the data associated with an unconditional decision.
type UnconditionalDecision struct {
	// reason is optional. It indicates why a request was allowed or denied.
	// +k8s:optional
	// +optional
	Reason string `json:"reason,omitempty" protobuf:"bytes,1,opt,name=reason"`

	// evaluationError is an indication that some error occurred during the authorization check.
	// It is entirely possible to get an error and be able to continue determine authorization status in spite of it.
	// For instance, RBAC can be missing a role, but enough roles are still present and bound to reason about the request.
	// +k8s:optional
	// +optional
	EvaluationError string `json:"evaluationError,omitempty" protobuf:"bytes,2,opt,name=evaluationError"`
}
```

Exported helpers in `staging/src/k8s.io/api/authorization/v1/util.go`: `SupportsConditionalAuthorization(ao)` (`:42`,
nil → false; else handled ⊇ {Allow, Deny, NoOpinion, ConditionsMap, Union}), `SupportsUnconditionalAuthorization(ao)`
(`:57`, nil → true; else ⊇ {Allow, Deny, NoOpinion}), `GetHandledDecisionTypes` (`:67`),
`ConditionalAuthorizationDecisionTypes[List]` (`:76`, `:82`), `UnconditionalAuthorizationDecisionTypes[List]` (`:88`, `:94`).
Doc nits: `:86-87` says the unconditional set is what a client needs "to handle conditional authorization"; comments
spell `ConditionMap` (`:41`, `:55`, `:75`).

## 3.2 `staging/src/k8s.io/api/authorization/v1alpha1/types.go` (whole file is new)

```go
// +genclient
// +genclient:nonNamespaced
// +genclient:onlyVerbs=create
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:prerelease-lifecycle-gen:introduced=1.38

// AuthorizationConditionsReview describes a request to evaluate authorization conditions.
type AuthorizationConditionsReview struct {
	metav1.TypeMeta `json:",inline"`
	// metadata is the standard list metadata.
	// In AuthorizationConditionsReview, it must be an empty struct.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata
	// +optional
	// +k8s:opaqueType
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// request describes the attributes for the authorization conditions request.
	// +k8s:optional
	// +optional
	Request *AuthorizationConditionsRequest `json:"request,omitempty" protobuf:"bytes,2,opt,name=request"`
	// response describes the attributes for the authorization conditions response.
	// +k8s:optional
	// +optional
	Response *AuthorizationConditionsResponse `json:"response,omitempty" protobuf:"bytes,3,opt,name=response"`
}

// AuthorizationConditionsRequest describes the authorization conditions request.
type AuthorizationConditionsRequest struct {
	// decision contains the conditional decision the authorizer authored at authorization time.
	// The API server may refine the decision before sending it, by evaluating some of the conditions in-process,
	// e.g. removing conditions that evaluated to false.
	// +required
	Decision authorizationv1.ConditionsAwareDecision `json:"decision" protobuf:"bytes,1,opt,name=decision"`

	// admissionRequest may contain additional information for evaluating the conditions.
	// +k8s:required
	// +required
	AdmissionRequest *admissionv1.AdmissionRequest `json:"admissionRequest,omitempty" protobuf:"bytes,2,opt,name=admissionRequest"`
}

// AuthorizationConditionsResponse describes an authorization conditions response.
type AuthorizationConditionsResponse struct {
	// uid is an identifier for the individual request/response.
	// This must be copied over from request.admissionRequest.uid of the corresponding
	// AuthorizationConditionsReview.
	// It is possible that the same request content (except uid) is sent to the
	// authorizer multiple times.
	// +k8s:required
	// +required
	UID types.UID `json:"uid" protobuf:"bytes,1,opt,name=uid"`

	// decision contains the authorizer's decision after seeing the data.
	// Currently, this must return an unconditional decision, that is, one of {Allow, Deny, NoOpinion}.
	// +required
	Decision authorizationv1.ConditionsAwareDecision `json:"decision" protobuf:"bytes,2,opt,name=decision"`
}
```

(The two "may refine the decision…" lines were added by #143024, `git show f410163f598 -- staging/src/k8s.io/api/authorization/v1alpha1/types.go`.)
Observation: `admissionRequest` is `+k8s:required` but serialized `omitempty` (`types.go:63`); the field is a pointer,
so DV `RequiredPointer` (`v1alpha1/zz_generated.validations.go:77`) is the effective rule.

## 3.3 `AuthorizationConfiguration` — `staging/src/k8s.io/apiserver/pkg/apis/apiserver/types.go`

Internal `WebhookConfiguration` (`:405-411`) and new type (`:414-432`):

```go
	// ConditionsReview defines the configuration for evaluating authorization
	// conditions via AuthorizationConditionsReview. When set, enables
	// conditional authorization support for this webhook authorizer.
	// The conditions review endpoint is reached via the given context
	// within the same kubeconfig file specified in ConnectionInfo.
	// +optional
	ConditionsReview *ConditionsReviewConfiguration
}

// ConditionsReviewConfiguration configures the connection to the conditions
// review endpoint for conditional authorization.
type ConditionsReviewConfiguration struct {
	// version is the API version of AuthorizationConditionsReview to use.
	// Valid values: v1alpha1
	// Required.
	Version string

	// kubeConfigContextName is the name of the context within the webhook's
	// kubeconfig file to use for conditions review requests.
	// Can only be specified when connectionInfo.type = KubeConfigFile.
	// If unset and connectionInfo.type = KubeConfigFile, the default kubeconfig
	// context is used, which means the API server sends both SubjectAccessReview and
	// AuthorizationConditionsReview payloads to the same HTTP endpoint, and the
	// caller must distinguish between these through TypeMeta information.
	// Optional.
	KubeConfigContextName string
}
```

Versioned: only `apiserver.config.k8s.io/v1` has it (`staging/src/k8s.io/apiserver/pkg/apis/apiserver/v1/types.go:524-551`,
JSON `conditionsReview`, `version` `+required` `json:"version"`, `kubeConfigContextName` `+optional`
`json:"kubeConfigContextName,omitempty"`). `v1beta1` and `v1alpha1` lack the field; their manual conversions
deliberately drop it (`v1beta1/conversion.go:35`, `v1alpha1/conversion.go:35`).

## 3.4 Validation rules

### Declarative (generated, `staging/src/k8s.io/api/authorization/v1/zz_generated.validations.go`; mirrored for the internal
types in `pkg/apis/authorization/v1/zz_generated.validations.go`)

| Field | Rules |
|---|---|
| `spec.authorizationOptions` (SAR/SelfSAR/LocalSAR) | gate off: forbidden; gate on: optional (`:876-886`, `:1060-1070`) |
| `authorizationOptions.handledDecisionTypes` | required (`RequiredSlice`), `maxItems=32`, unique set; values are `+k8s:opaqueType` so **unknown values accepted** (`:53-65`) |
| `status.conditionalDecision` | gate off: forbidden; gate on: optional (`:1114-1124`) |
| `ConditionsAwareDecision.type` | required; enum {Allow, ConditionsMap, Deny, NoOpinion, Union} (`:458-466`); discriminated union: exactly the member matching `type` set, `union` counts as set iff `len>0` (`:214-257`) |
| `ConditionsAwareDecision.union` | list-map keyed by `authorizerName`, unique (`:413-452`) |
| `NamedConditionsAwareDecision.authorizerName` | required; `k8s-long-name` = DNS-1123 subdomain, ≤253 chars (`:683`; `apimachinery/pkg/api/validate/strfmt.go:68-76`) |
| `ConditionsMap.{deny,noOpinion,allow}Conditions` | optional; each `maxItems=128`; list-map unique by `id` **within each list** (`:492-587`) |
| `Condition.id` | required; `k8s-prefixed-label-key` = label key **with mandatory DNS-subdomain prefix** (prefix ≤253, name ≤63) (`:99-106`; `strfmt.go:111-119`) |
| `Condition.condition` | optional; `maxBytes=10240` (`:137`) |
| `Condition.type` | optional; `k8s-prefixed-label-key` |
| `Condition.description` | optional; `maxBytes=1024` (`:199`) |
| `AuthorizationConditionsReview.metadata` | `+k8s:opaqueType` (handwritten rule below) |
| `ACR.request.admissionRequest` | required pointer (`v1alpha1/zz_generated.validations.go:77`) |
| `ACR.response.uid` | required (`v1alpha1/zz_generated.validations.go:115`) |
| `ACR.request.decision` / `response.decision` | validated as `ConditionsAwareDecision` above |

### Handwritten (`staging/src/k8s.io/apiserver/pkg/apis/authorization/validation/validation.go`)

- `validateAuthorizationOptions` (`:76-87`): if `0 < len ≤ 32`, `handledDecisionTypes` must ⊇ {Allow, Deny, NoOpinion}.
- `ValidateSubjectAccessReviewStatus` (`:90-135`): `allowed && denied` invalid; `conditionalDecision` set but client not
  conditions-aware (`SupportsConditionalAuthorization(spec.authorizationOptions)` false) → Forbidden; type ∈ {Allow,
  Deny, NoOpinion} → Invalid; type ∈ {ConditionsMap, Union} ⇒ `allowed`, `denied` must be false and `reason`,
  `evaluationError` empty.
- SAR/SelfSAR/LocalSAR (`:138-184`): spec rules above + status rules + metadata must be empty except `managedFields`
  (LocalSAR: and `namespace`, which must equal `spec.resourceAttributes.namespace`).
- `ValidateAuthorizationConditionsReview` (`:244-260`): metadata empty except `managedFields`; request decision type
  must be ConditionsMap or Union (`:263-284`); response decision type must be Allow/Deny/NoOpinion (`:287-305`).
  `admissionRequest` contents not validated (`:281-282`).
- `DeclarativeValidationConfig` (`:310-316`) feeds the gate to DV; `CombinedValidate{SubjectAccessReview,AuthorizationConditionsReview}Create`
  (`:319-352`) run handwritten + DV with panic recovery; used by the webhook authorizer on webhook responses.
- kube-apiserver composition for the served SAR kinds: `pkg/apis/authorization/validation/validation.go:52-112`
  (convert internal→v1, handwritten, then `rest.DeclarativeValidation` with the same options); v1beta1 SAR
  `spec.authorizationOptions` / `status.conditionalDecision` are omitted paths (`:37-48`).

### In-process constructor (applies to every ConditionsMap, regardless of source)

`staging/src/k8s.io/apiserver/pkg/authorization/authorizer/conditionsmap.go`: `MaxConditionsPerMap = 128` **total across
the three lists** (`:116`, checked `:154`), `MaxConditionBytes = 10240` (`:119`), `MaxConditionDescriptionBytes = 1024`
(`:122`); 0 conditions → NoOpinion with error (`:150-152`); noOpinion-only → NoOpinion (`:160-162`); IDs unique
**across all three lists** (`:191-195`); ID and (non-empty) type must pass `utilvalidation.IsDomainPrefixedKey`
(`:197-210`); any violation fails closed (Deny if any Deny condition, else NoOpinion, `:141-146`).

### AuthorizationConfiguration (`staging/src/k8s.io/apiserver/pkg/apis/apiserver/validation/validation.go`)

- `:739-745`: `conditionsReview` only when `subjectAccessReviewVersion == "v1"`, then `ValidateConditionsReviewConfiguration`.
- `ValidateConditionsReviewConfiguration` (`:756-783`): gate off → Forbidden on the whole field; `kubeConfigContextName`
  only with `connectionInfo.type=KubeConfigFile` (also rejected for empty/unknown type); `version` required, only
  `v1alpha1` supported. No format check on `kubeConfigContextName` (existence checked at load time,
  `pkg/kubeapiserver/authorizer/reload.go:191-198`).

### Discrepancies between layers (for Stage 2/3; severity tentative)

1. **Question / code+KEP**: API docs say IDs and types in `*.k8s.io` / `*.kubernetes.io` are reserved
   (`v1/types.go:437`, `:451`; `authorizer/interfaces.go:265`, `:271`); no validation enforces it (not found in DV,
   `validation.go`, or `conditionsmap.go:187-218`). The built-in type `authorizer.kubernetes.io/cel` therefore can be
   emitted by any webhook (that is the intended use) but so can any other reserved type.
2. **Nit / code**: total-128 and cross-list ID uniqueness are only enforced by the in-process constructor; DV allows
   up to 3×128 conditions and the same ID in different effect lists. Webhook responses are decoded through the
   constructor (`ToAuthorizerConditionsAwareDecision`), so they fail closed rather than being rejected by validation;
   a SAR/ACR object that passes DV can still be one the server would never produce. The `validation.go:278` comment
   ("between 1 and 128 … enforced by `ConditionsAwareDecisionConditionsMap`") documents this split.
3. **Nit / KEP**: `ConditionsAwareDecision.union` doc says "At least one of the leaves must be of type ConditionsMap";
   no validation rule enforces it (DV requires only `len>0`).
4. **Nit / code**: ID format differs in wording between layers (`k8s-prefixed-label-key` in DV vs `IsDomainPrefixedKey`
   in-process); both require a prefix, equivalence not verified character-by-character.
5. **Nit / doc**: `ConditionsMap` doc says "must have at least one Allow condition or at least one Deny condition"; DV
   accepts a map with only `noOpinionConditions` (in-process it folds to NoOpinion).

---

## Could not determine

- Whether the folded-reason prefix difference in the SAR matrix (`"conditional-webhook: failed closed"` at
  `conditionalauthorization_test.go:1212` vs `"failed closed"` at `:1256`) is intentional.
- Exact runtime behaviour was not executed (no Go toolchain, no etcd); all statements are from reading HEAD.
- Character-level equivalence of `content.IsPrefixedLabelKey` vs `utilvalidation.IsDomainPrefixedKey` (not read).
