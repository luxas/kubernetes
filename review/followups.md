# KEP-5681 Conditional Authorization: consolidated follow-ups (Stage 3d)

HEAD `57a6904a21a` = `origin/master` `c5bdf2219ee` + #143024 (`f410163f598`) + review docs.

Inputs: section 2 (follow-up tables) and section 3 (findings) of the ten `review/pr-<n>.md` files, `review/shipped.md` §4 (Q1-Q9), and the
`review/pr-*-review.json` exports for the thread text. Nothing was built or run. I re-checked on HEAD every row marked Partially,
Unaddressed or Unclear, plus every Important finding cited in Part 2, and cite HEAD `path:line` throughout.

Path abbreviations:
- `AS/` = `staging/src/k8s.io/apiserver/`
- `AZ/` = `AS/pkg/authorization/authorizer/`
- `W` = `AS/plugin/pkg/authorizer/webhook/webhook.go`
- `API/` = `staging/src/k8s.io/api/authorization/`
- `IT` = `test/integration/apiserver/conditionalauthorization/conditionalauthorization_test.go`
- `ENF` = `AS/pkg/admission/plugin/authorizer/conditionsenforcer/conditionsenforcer.go`
- `CEL` = `AS/pkg/admission/plugin/cel/authorization_conditions.go`

Thread numbers are the per-PR numbering used in each Stage 2 file. For #137633 that is 1-based JSONL lines; for #137513 it is 0-based.

Summary:
- Part 1: 65 deduplicated follow-up rows (F-1 … F-65) from the ten per-PR tables. 10 are Unaddressed (Part 4).
- Part 2: 71 Important findings, merged into 20 root-cause clusters (R-1 … R-20). There are no Critical findings.

---

## PART 1: Follow-ups not Addressed (deduplicated)

Disposition key:
- **close**: no further action.
- **beta**: must-fix-before-beta.
- **should**: should-fix.
- **KEP**: update the KEP text only.
- **deferred**: deferred by the maintainers.
- **→R-n**: tracked in cluster R-n.

| id | origin PR(s) and thread path:line | what was asked | by | current status on HEAD (re-verified) | disposition |
|---|---|---|---|---|---|
| F-1 | #138801 T3 `AZ/interfaces.go` (no line) | Do not merge TODOs into public interface docs | liggitt | Superseded. #137204 removed that TODO, but the pattern is back on HEAD: `TODO(luxas)` in the public `BuiltinConditionsEvaluatorBuilder` doc (`AZ/interfaces.go:356-359`, #143024) | should: move to an issue before #143024 merges |
| F-2 | #138801 overview (luxas lint) | Rename the `self` receiver | luxas | **Unaddressed**, declined as pre-existing. `AS/pkg/admission/initializer/initializer_test.go:98-173` still uses `self` (incl. `:132`, `:149`) | close (Nit, pre-existing) |
| F-3 | #140714 T5 `pkg/apis/authorization/v1/doc.go:21` | Comment the generation route "if we go this route" | luxas | Superseded: the route was dropped; `doc.go:17-22` needs no comment | close |
| F-4 | #140714 T6 `AS/pkg/apis/authorization/validation/validation.go:1` | Could live in `k8s.io/api/authorization/v1/validation` | luxas | Unclear: an alternative was recorded but nothing was asked. The package stayed in `AS/pkg/apis/authorization/validation/` | close |
| F-5 | #140714 overview 2026-09-04 | Temporary opaque-field workaround for DV | luxas | Superseded by the generator fix #141874: `API/v1alpha1/zz_generated.validations.go:54,143` call `v1.Validate_ConditionsAwareDecision` | close |
| F-6 | #137204 T1 `pkg/auth/authorizer/abac/abac.go:235` | Constructor-style `DecisionAllow()` (KEP Decision struct) | luxas | KEP-change: `Decision` stays `int` (`AZ/interfaces.go:231-242`); the KEP still describes the struct (`kep.md:613-618,660-663`) | KEP →R-19 |
| F-7 | #137204 T3 `AZ/interfaces.go` (no line) | Join reasons with a newline, "like union" | luxas | Unclear (no anchor line exported). Three formats exist on HEAD: legacy union `name: r` joined by `"\n"` (`AS/pkg/authorization/union/union.go:89,99`); fold `name: {r}` joined by `", "` (`AZ/conditionsunion.go:162-170,192`) | should →R-6 |
| F-8 | #137204 T5, T6, T15 | Aggregate earlier errors; TODO on `ConditionsData`; why the test fake implements new methods | luxas, liggitt, deads2k | Superseded: withdrawn, implemented by #137513, re-added by #140916 respectively (`union.go:92-93`; `AZ/conditions.go:31-68`; `policy_test_context.go:642-656`) | close |
| F-9 | #137204 T11 + #143024 #23 `delegating.go:53` | (a) a builtin-evaluator registry that binary initializers populate (liggitt); (b) "nothing sets this; aggregated apiservers next release" (luxas) | liggitt, luxas | Partially / Deferred. There is no registry. The builder is injected per webhook (`W:101`, `pkg/kubeapiserver/authorizer/reload.go:204-208`), and only when `conditionsReview` is configured (`reload.go:189-190`). `DelegatingAuthorizerConfig.BuiltinConditionsEvaluatorBuilder` (`AS/pkg/authorization/authorizerfactory/delegating.go:51-53`) is never set by `AS/pkg/server/options/authorization.go:200-207` | deferred (next release) →R-8, R-13 |
| F-10 | #137204 T20 `AZ/conditions.go` | `EvaluateConditions` on an unconditional decision should be an error | liggitt | Partially. The webhook (`W:430-432`) and union (`union.go:134-136`) return errors. `AuthorizerFunc` returns `Deny`+`ErrorConditionEvaluationNotSupported` for **any** input (`AZ/interfaces.go:143-145`), as do the 9 unaware implementations | should: say in the `EvaluateConditions` doc that callers clamp to `PossibleDecisions`, or return `FailureDecision()` (#137204 Bugs Nit) |
| F-11 | #137204 T21 + #140715 T3 `AZ/conditions.go` | Do not add the unconditional-parts method until there is a call site | liggitt | Partially. Re-added by #140715 as `UnconditionalPartsOrFailClosed` (`AZ/conditions.go:181-198`). Verified: zero non-test callers (`git grep` finds only the definition) | →R-2 (decision, Part 5) |
| F-12 | #137204 T22, O1 | Defer the fail-closed computation; type-safe argument to `EvaluateConditions` | liggitt, luxas | T22 effectively done: `FailureDecision` (`AZ/conditions.go:224-229`) has callers at `union.go:135,164` and in `W`. O1 was declined by liggitt; `AZ/interfaces.go:123` unchanged | close (O1 links to F-10) |
| F-13 | #137513 A#0 `AZ/conditions.go` | Is the reserved `k8s.io` prefix enforced? | micahhausler | **Unaddressed**, declined by the author ("I don't know why we would actually need enforcement"). Doc only at `AZ/interfaces.go:265,271` and `API/v1/types.go:437,454`; `validateConditions` (`AZ/conditionsmap.go:187-219`) accepts any domain | should: enforce a reserved-type allowlist or drop the word "reserved" (#140715 S3, K2) |
| F-14 | #137513 A#5, A#6; #137633 A#2, A#3 | Effect is implicit in three lists, not a per-condition field | luxas, deads2k | KEP-change: `AZ/conditionsmap.go:138`, `API/v1/types.go:476-510`; the KEP still has `Effect` (`kep.md:761-764,1073`) | KEP →R-19 |
| F-15 | #137513 A#7, A#8, A#18, A#27, A#35, O-C15; #137633 A#1, A#7, A#9, O6 | Author self-notes without context ("add error here", "error here", "use the struct", "add a comment here", "I'll fix this", "this goes away now", "make API shape clearer?", "decide on these fields", "two questions on validation.go") | luxas, liggitt | Unclear: JSON text re-read, and none can be mapped to a HEAD line | close (untraceable) |
| F-16 | #137513 A#9, A#17, A#23, A#24; B#21, B#74 | Split evaluate funcs; temporary `unconditionalParts`; file rename; index-bounded union; comment wording | luxas, liggitt | Superseded: `MaybeEvaluateConditionFunc` (`AZ/interfaces.go:302`), the #140715 pair (`AZ/conditions.go:162,181`), and name routing (`union.go:188-194`) | close |
| F-17 | #137513 A#13 `AZ/conditions.go` | `EvaluateFn` for an instance, `EvaluateFunc` for a type | deads2k | **Unaddressed**: `GenericCondition.EvaluateFunc` (`AZ/conditionsmap.go:229`) | should (Nit; alpha API, rename is cheap now) |
| F-18 | #137513 A#22, B#32 | In-process CEL first in the webhook; `PartiallyEvaluate…` has no user yet | luxas | Deferred to #143024 (open). The only caller is `W:963` | deferred (lands with #143024) |
| F-19 | #137513 A#30 `AZ/conditionsmap.go` | Doc: "secondarily using evaluateConditionFn, if set" | luxas | Partially: the doc at `AZ/evaluate.go:99-100` says "if set", but the closure calls the function unconditionally (`:106`), so a nil function panics | should →R-17 |
| F-20 | #137513 A#39, A#45, B#53 | DNS-1123 "+ two dots"; move name validation into the config API; the superuser name must not collide with user names | luxas, liggitt | Partially. `Add` checks DNS-1123 (`AZ/conditionsunion.go:70`); there is no two-dot or domain rule. Config validation checks DNS-1123 (`AS/pkg/apis/apiserver/validation/validation.go:636-637`) but only **warns** on reserved names (`:641-647`). An exact collision with `system-privileged-group.authorizer.kubernetes.io` (`reload.go:119`) becomes a hard `union.New` duplicate error (`union.go:63-64`) | should →R-16 |
| F-21 | #137513 A#41 `AZ/conditions.go:211` | `FailureDecision` needs only `CanDeny()`; do not build the full set | liggitt | **Unaddressed** (resolved in the UI): `AZ/conditions.go:225`, `AZ/conditionsmap.go:51`, `AZ/conditionsunion.go:99` still call `PossibleDecisions().Has(Deny)` | should (Nit, perf) |
| F-22 | #137513 A#52 (authorizer/union.go) | `EvaluateConditions` result must be ∈ `PossibleDecisions` (webhook and partial evaluation) | luxas | Partially. Guards exist at `union.go:163-165`, `W:545-562` and `ENF:145-150`. `PartiallyEvaluateConditionsAwareDecision` is in bounds by construction, but this is never tested as a property | →R-7 (test) |
| F-23 | #137513 A#64 `AZ/interfaces.go` | Also fix the admission docs ("prior to default values") | liggitt | Partially: fixed in `AZ/interfaces.go:335`, still wrong in `AS/pkg/admission/interfaces.go:54` | should (Nit) |
| F-24 | #137513 A#82 `AZ/conditionsunion.go:136` | Integration tests that show the user-facing reason text | liggitt | Deferred to #137633/#141959. The SAR matrix shows the asymmetry (`IT:1212` vs `IT:1256`, Q9) | →R-6 |
| F-25 | #137513 O-C7 | Make `Condition` a struct? | luxas | Partially: the interface is kept plus `GenericCondition` (`AZ/conditionsmap.go:227-232`) | close |
| F-26 | #137513 O-R36, O-C8, O-C9 (Part A **and** Part B, which agree) | What does "union" mean (any / all / first wins)? Document it; maybe restrict who can build a Union | lmktfy, luxas | Partially. The API doc states it (`API/v1/types.go:576-579`); the Go doc at `AZ/conditions.go:49-55` says only "an ordered list of sub-decisions". The builder is exported and used outside `union` (`AS/pkg/apis/authorization/v1/encoding.go:143-147`) | should (Go doc; restricting construction is optional) |
| F-27 | #137513 O-R32 | Flatten the Union into `[]ConditionsMap` with an owner | neolit123 | **Disagreement**: Part A says KEP-change, Part B says Addressed (rejected with rationale, neolit123 agreed in C19). Merged: the code is settled (tree, `AZ/conditions.go:63-64`), but the KEP still has `ConditionSet{unconditionalDecision,set}` (`kep.md:779-790`) | KEP →R-19 |
| F-28 | #137513 O-C21 item 2 | No partial error list on a true short-circuit, pending a warnings design | luxas | Deferred, with no issue or TODO. `AZ/evaluate.go:177-180,209` drop same-effect errors on a true | deferred |
| F-29 | #137513 B#38 `union/union.go` | "If you prefer us to return an error here, I can do that" | luxas | Unclear. The probable target, non-Union input, returns an error on HEAD (`union.go:134-136`) | close |
| F-30 | #137513 B#69 `AZ/evaluate.go` | Follow-up on 500 vs 403 for errors that come with Deny/NoOpinion | liggitt | Deferred: TODO at `AZ/evaluate.go:139-141`; no issue number anywhere | deferred →R-2, R-7 (Part 5) |
| F-31 | #140715 T2 `AZ/conditionsmap.go:197` | Scrub validation for unbounded `strings.Split`; use `SplitN`, in a standalone PR | liggitt | Deferred, and no PR found. Still unbounded: `staging/src/k8s.io/apimachinery/pkg/api/validate/content/kube.go:45,112` and `…/apimachinery/pkg/util/validation/validation.go:138` | deferred (should before beta) |
| F-32 | #140715 T6 `AZ/conditions.go` | What does `expectConditional` refer to? | stlaz | Partially: removed from code, but still mentioned in `AZ/conditions_test.go:1672-1673` | should (Nit) |
| F-33 | #140715 T7 `AZ/conditions.go:192` | Users won't understand "failed closed"; reword | stlaz | Deferred (author: "separate PR"; no issue). Unchanged at `AZ/conditions.go:193`. Non-test occurrences of `"failed closed`: conditions.go 2, conditionsmap.go 2, conditionsunion.go 2, union.go 4, `W` 14. The string reaches 403 bodies and audit annotations | deferred (pick wording before beta) |
| F-34 | #137633 A#5, A#10, A#12 | Tree layer `[]NamedConditionsAwareDecision`; typed opt-in instead of a bool; ACR embeds `AdmissionRequest` | luxas, deads2k | KEP-change: `API/v1/types.go:593,597`, `:412-429`; `API/v1alpha1/types.go:63`. The KEP still has `ConditionSetChain`, `conditionalAuthorization.mode`, and "all fields in ConditionData" (`kep.md:1018,1098-1113,1168`) | KEP →R-19 |
| F-35 | #137633 A#8 = B#8 `AZ/conditions.go` | Explicit "can allow" helper | luxas | Superseded (both parts agree): `PossibleDecisions().Has(Allow)` (`AS/pkg/endpoints/filters/authorization.go:202`) | close |
| F-36 | #137633 A#18 = B#30 `AS/pkg/apis/apiserver/v1/types.go` | The doc says required but nothing validates it; decide required vs optional | liggitt | **Disagreement**: Part A says KEP-change, Part B says Addressed. Verified: now optional and documented (`AS/pkg/apis/apiserver/v1/types.go:542-551`); forbidden unless `KubeConfigFile` (`AS/pkg/apis/apiserver/validation/validation.go:761-768`). The KEP still says unset ⇒ unsupported (`kep.md:1226-1231`). Merged: code Addressed, KEP stale. Unresolved in the UI | KEP |
| F-37 | #137633 A#19 = B#31 `AS/pkg/apis/apiserver/v1/types.go:540` | "Validated only at authorizer init time; add checks to ValidateWebhookConfiguration" | liggitt | **Disagreement**: Part A says Partially (context existence is checked only at `reload.go:191-197`), Part B says Addressed (version). At merge, line 540 is in the `Version` field block. `version` is now validated at `validation.go:771-778`. Context existence needs the kubeconfig file and cannot be checked statically. Merged: Addressed | close |
| F-38 | #137633 A#25, A#28 `API/v1/types.go:450,617` | Size limits on the whole SAR (3 MB limit reader); limit reason/evaluationError | liggitt, luxas | Partially. Per-field limits only. No body limit in the webhook package: `W:812` reads `// TODO(luxas): Enforce a limited read here?`, and there is no `LimitReader`. Union has no `maxItems` (`API/v1/types.go:584-593`; the only `maxItems` are at `:428,483,494,505`) | beta →R-4 |
| F-39 | #137633 A#26 `API/v1alpha1/types.go:65` | ACR UID; parity with AuditAnnotations/Warnings | liggitt | Partially: UID exists (`API/v1alpha1/types.go:67-75`). Audit/warnings were postponed with no TODO or issue | deferred (record in KEP) |
| F-40 | #137633 A#29 `API/v1/types.go:593` | `maxItems` on union (16) | luxas | Deferred "for beta graduation" per the thread; nothing tracks it in code or KEP | beta →R-4 |
| F-41 | #137633 A#34, A#42, A#43 | `+k8s:beta` union discriminator; validation inside v1beta1 conversion | liggitt, deads2k | Superseded: the lint was dropped; the conversion folds and never errors (`pkg/apis/authorization/v1beta1/conversion.go:59-86`) | close |
| F-42 | #137633 A#36, A#48 `pkg/apis/authorization/fuzzer/fuzzer.go:35-38` | Fuzz the new fields v1↔internal and per external version | deads2k, liggitt | Deferred (issue 142346): `fuzzer.go:36-47` sets both fields to nil everywhere | deferred |
| F-43 | #137633 A#47, A-O5; #141959 #22 | conversion-gen memory-identical support; avoid double conversion once #142345 lands | liggitt, luxas | Deferred (issue 142345). TODO at `pkg/api/testing/conversion_test.go:248` exempts SAR/SSAR/LSAR (`:249-251`); `pkg/registry/authorization/util/helpers.go:276-278` still converts v1→internal | deferred |
| F-44 | #137633 A#54 = B#82 `AS/pkg/apis/apiserver/validation/validation.go:756` | Early return when `crc` is nil | liggitt | Partially (both parts agree). The caller guards (`:739`), but exported `ValidateConditionsReviewConfiguration` dereferences `crc` unguarded (`:763`, `:771`) | should →R-17 |
| F-45 | #137633 A#55 = B#83 `validation.go:748` | What does the matchConditions TODO prevent? | liggitt | Deferred (both parts agree): TODO still at `validation.go:747-748` | deferred (or delete the TODO) |
| F-46 | #137633 A#57 `API/v1/util.go:1` | Pass a set in rather than return clones | liggitt | Partially: `GetHandledDecisionTypes` allocates per call (`API/v1/util.go:67-72`). The reviewer said "not a big deal" | close |
| F-47 | #137633 A#59 (= JSONL #87) `AS/pkg/apis/authorization/validation/validation.go` | Does anything check that at least one condition list is non-empty? | liggitt | **Unaddressed** (unresolved). The author proposed relying on the constructor. Verified: the comment at `validation.go:278` defers to `ConditionsAwareDecisionConditionsMap`, and DV accepts `conditionsMap: {}`. The constructor then returns NoOpinion+error (`AZ/conditionsmap.go:150-153`), which skips `failurePolicy` | beta →R-3, R-4 |
| F-48 | #137633 A-O2 = B-O3 (deads2k CHANGES_REQUESTED 2026-07-22) | Too many ungated changes | deads2k | Partially (both parts agree). Still ungated: status cleared before `createValidation` (`pkg/registry/authorization/subjectaccessreview/rest.go:73`, SSAR `:74`, LSAR `:75`); status checks in exported validators (`AS/pkg/apis/authorization/validation/validation.go:140`); legacy-webhook decoding of `conditionalDecision` (`W:264-267`); union reason prefix (`union.go:89`) | →R-6, R-2 (release note) |
| F-49 | #137633 A-O3 | Simplify/narrow the v1beta1 DV-equivalence exclusion mechanism | liggitt | Deferred: TODO `pkg/api/testing/validation_test.go:88` | deferred |
| F-50 | #137633 A-O4 = B-O2 | Unify `AdmissionRequest` construction with `CreateV1AdmissionReview` | luxas | Deferred, no issue: still hand-built at `W:494-520` | deferred |
| F-51 | #137633 B#23 `pkg/controlplane/apiserver/config.go` | Do all write-verb subresources (`pods/proxy`, …) go through admission? | liggitt | Partially (unresolved). The classifier uses `exclusion.Excluded()` (`config.go:296,307-309`). POST `pods/exec\|attach\|portforward` and `*/proxy` are classified true; this is neither checked exhaustively nor tested. GET connect is excluded (TODO `config.go:314-317`). The author promised an "exhaustive re-check" | beta →R-1 |
| F-52 | #137633 B#24 `pkg/controlplane/apiserver/config.go` | "This would classify aggregated APIs as conditions-aware, right?" | liggitt | **Unaddressed** (unresolved). Verified: no aggregated-group check in `config.go:298-318`, and the aggregator copies the config (`pkg/controlplane/apiserver/aggregator.go:63`). The author's stated plan for 1.38 is the opposite of the fix: *always* classify aggregated groups as conditional (TODO `config.go:314-316`) | beta →R-1 |
| F-53 | #137633 B#81 `AS/pkg/server/options/authorization.go:206` | Populate the ACR client only when the gate is on, and check internally too | liggitt | Partially. The internal check exists (`W:153-157`); the options still pass `client.AuthorizationV1alpha1()` unconditionally (`authorization.go:206`) | beta →R-13 |
| F-54 | #141959 #9 `ENF` | "default: nil" | luxas | Unclear. The probable intent (pairs with #10): `featureEnabled *bool`, nil-safe at `ENF:59,80` | close |
| F-55 | #141959 #16 | Rebase on the merged `GetOldObject` fix | luxas | Superseded: `admission.NewVersionedAttributes` (`ENF:106`) | close |
| F-56 | #141959 #18 `pkg/controlplane/apiserver/config.go` | Should SAR/TokenReview (admission-excluded) be classifiable? If so, add coverage | luxas | **Unaddressed** (open design question). The exclusion is kept (`config.go:296,307-309`), which is fail-closed (fold-down, `IT:1395`) | should: decide; keep the exclusion for alpha and record it in the KEP |
| F-57 | #141959 #26 `AS/pkg/endpoints/filters/authorization.go:147` | Delete the nil-authorizer branches (separate PR) | liggitt | Deferred (#143440). Still at `authorization.go:66-69,144-147`. With the gate on and a nil authorizer, every admission request returns 500 (`ENF:84-88`) | deferred |
| F-58 | #141959 #28 `pkg/controlplane/apiserver/config.go` | Drop the special-casing of `*`; pass through to authz | liggitt | KEP-change: no `*` check in `config.go:298-318`, and `config_test.go:114-115` asserts `*` → true. The KEP says no wildcards (`kep.md:899-900`) | KEP |
| F-59 | #143024 #2-7, #9, #16, #17, #19 (10 threads) | Global builtin registry design notes | luxas | Superseded: the registry was removed, and the builder is injected per webhook (`W:101`, `reload.go:204`) | close |
| F-60 | #143024 #8 `CEL` | Add godoc | luxas | Partially: only the constructor is documented (`CEL:49-52`). Undocumented: `:73`, `:79`, `:142`, `:148`, `:180` | should (before merge, Nit) |
| F-61 | #143024 #11 `CEL:118` | De-duplicate `getNamespace` with VAP | luxas | **Unaddressed** (optional): copy at `CEL:118-140` ("exactly mirrors") | should (Nit) |
| F-62 | #143024 #12 `CEL` | Nil condition / nil data should be errors | luxas | Partially: nil data → error (`CEL:80-82`); nil condition → Unevaluatable (`CEL:150-151`) | should (before merge, Nit) |
| F-63 | #143024 #13 `authorization_conditions_test.go:17` | Add benchmarks | luxas | **Unaddressed**: 0 `func Benchmark` in `AS/pkg/admission/plugin/cel/authorization_conditions_test.go` | beta →R-8 |
| F-64 | #143024 #14 `CEL` | Setup/compile phase before evaluation | luxas | Partially: there is a setup phase (`EvaluatorForData`, `CEL:79`), but every call still compiles (`CEL:163`) | beta (before merge) →R-8 |
| F-65 | #143024 #20 `IT:1574` | A case that compiles but errors at runtime because of version skew | luxas | **Unaddressed**: only the compile-error prefix `unsupportedInTreePrefix` (`IT:1574`) | beta →R-8 |

Rows marked Addressed in both reviews are omitted. The two Part A/B pairs that cover the same thread agree on every merged row except F-27, F-36 and F-37, where the disagreement is noted in the row.

Unaddressed rows: F-2, F-13, F-17, F-21, F-47, F-52, F-56, F-61, F-63, F-65.

Dispositions of the 65 rows (by the first keyword in the disposition column):

| Disposition | Rows |
|---|---|
| close | 17 |
| should | 16 |
| deferred | 13 |
| beta | 9 |
| KEP | 6 |
| tracked only by cluster (→R-n) | 4 |

---

## PART 2: Important findings by root cause

There is no Critical finding in any of the ten reviews. Every cluster below is Important, which is the maximum severity of its members. Questions are listed under a cluster as "related" when they share the root cause; they do not raise its severity.

### R-1 Classifier contract holes: requests classified conditional that never reach the enforcer

The classifier promises that a `true` request "MUST" be enforced (`AS/pkg/endpoints/filters/authorization.go:53-54`), but it only checks resource request + verb + admission exclusion (`pkg/controlplane/apiserver/config.go:298-318`). Two request paths skip `AuthorizationConditionsEnforcer` after a conditional Allow passed the filter (`authorization.go:202-208`):
- (a) Aggregated APIs. The aggregator copies the classifier (`aggregator.go:63`) and proxies with no local admission. Safety then depends on the aggregated server re-authorizing. A conforming webhook answers that delegated SAR unconditionally, so the result fails closed. An aggregated server that trusts the front proxy executes the request unenforced.
- (b) Unsafe corrupt-object delete (`AS/pkg/endpoints/handlers/delete.go:141-162`). It checks only `unsafe-delete-ignore-read-errors` and replaces the deleter, so `deleteValidation` never runs (`AllowUnsafeMalformedObjectDeletion` is Beta, default on).

Connect subresources are classified true but evaluate conditions against `*Options` objects, which is neither documented nor tested.

| Contributing finding | PR | path:line |
|---|---|---|
| [Important][code] Aggregated APIs classified, never enforced | #141959 Sec | `config.go:298-318`, `aggregator.go:63`, `staging/src/k8s.io/kube-aggregator/pkg/apiserver/handler_proxy.go:107` |
| [Important][code] Same (thread #24 unresolved) | #137633 B S2 | `config.go:314-318` |
| [Important][KEP/code] KEP: "served by the same API server"; aggregated servers "MUST use kube-apiserver as first authorizer" | #141959 KEP | `kep.md:899,906-913` vs `config.go:298-318` |
| [Important][code] Unsafe delete skips admission | #141959 Sec | `delete.go:141-162`, `AS/pkg/registry/generic/registry/corrupt_obj_deleter.go:111,134` |
| [Important][test] No test that a classified request never completes without the enforcer | #141959 Tests | `IT:1358-1368` grants RBAC `get`, so it cannot catch it |
| related [Question] CONNECT evaluates against `*Options` | #141959 Bugs | `AS/pkg/endpoints/handlers/rest.go:199-211` |
| related threads | F-51, F-52 | |

- **Fix carried by:** a #141959 follow-up (`pkg/controlplane/apiserver/config.go`, `AS/pkg/endpoints/handlers/delete.go`), possibly the kube-aggregator proxy.
- **Disposition:** must-fix before beta. Classify false for non-local GroupVersions, or have the proxy reject any ctx decision that is not `IsAllow()`. In `DeleteResource`, reject the unsafe option unless `IsAllow()`. Add a negative integration row. Scope is a user decision (Part 5, D-1).

### R-2 Fold-down for conditions-unaware callers: 500 vs 403, the unused `UnconditionalPartsOrFailClosed`, and the undocumented `Authorize` contract

The safety of all 29 `UnconditionalAuthorizer` sites rests on a rule that is written nowhere: `Authorize` must never return Allow for a would-be-conditional result (`AZ/interfaces.go:84-88`; `Authorize` has no doc comment). `UnconditionalPartsOrFailClosed` was built to implement the 403 fold (`AZ/conditions.go:175-198`) and has zero production callers. Two things happen instead:
- The webhook folds inline with `FailureDecision()` **plus an error** (`W:264-267`), which callers turn into a 500 (`authorization.go:115-118`, `AS/pkg/endpoints/handlers/update.go:275`, `pkg/registry/core/pod/rest/authorize.go:55`).
- The conditions-aware filter answers a Deny/NoOpinion-only conditional decision with a 403 that has an empty reason.

The KEP describes a plain 403 fold (`kep.md:672-675,1913-1918`). shipped.md Q1.

| Contributing finding | PR | path:line |
|---|---|---|
| [Important][code] Narrowed sites rely on an undocumented `Authorize` contract | #138801 Sec | `AZ/interfaces.go:84-88` |
| [Important][KEP] KEP fold is a plain answer; code is error → 500 | #138801 KEP | `kep.md:672-675` vs `W:264-267` |
| [Important][KEP] Same, and `OrFailClosed` has no caller | #137204 KEP | `kep.md:676-680,1913-1918` |
| [Important][code] `OrFailClosed` has zero production callers; the filter returns a reasonless 403 | #140715 S1 | `AZ/conditions.go:181-198`, `authorization.go:208-221` |
| [Important][test] `OrFailClosed` exercised only inside test fakes | #140715 T-c | `AS/pkg/endpoints/filters/authorization_test.go:324`, `ENF_test.go:92` |
| related [Question] legacy 500 is defensible | #137633 B Bugs | `W:264-267` |
| related [Question]/[Nit] the `OrFailClosed` reason discloses possible outcomes | #137513 A, #140715 S2 | `AZ/conditions.go:191-195` |
| related threads | F-11, F-30, F-48 | |

- **Fix carried by:** follow-up on the #137633 webhook code and the #141959 filter; KEP.
- **Disposition:** user decision (Part 5, D-2). Either way, document the contract on `UnconditionalAuthorizer.Authorize`, and give `OrFailClosed` a caller or delete it.

### R-3 `failurePolicy` bypass and legacy vs conditions-aware webhook asymmetry

For one webhook response, the conditions-aware path (`W:275-345`) and legacy `Authorize` (`W:255-272`) disagree, and `failurePolicy: NoOpinion` turns several Deny-carrying answers into NoOpinion so a later authorizer (RBAC) decides:
1. `denied=true` + `conditionalDecision`.
2. An unrequested deny map.
3. A deny map that fails DV.
4. A server-built spec that fails *client-input* validation: `?fieldSelector==x` gives an empty-key requirement, so `key: Required` and the webhook's Deny is discarded (`W:327`).

In the other direction, a DV-valid but constructor-rejected `ConditionsMap` never reaches `failClosed`. These are: empty `{}`; more than 128 conditions in total; IDs duplicated across lists. The constructor's own rule (Deny iff deny conditions, else NoOpinion) is applied instead (`encoding.go:134-142`, `AZ/conditionsmap.go:139-174`), so `failurePolicy: Deny` is downgraded.

Also, with no ACR configured, `ConditionsAwareAuthorize` is not `FromParts(Authorize)`. It turns `status.evaluationError` into an error, which gives a 500 that echoes webhook text to the client (`W:331-345`, `AS/pkg/endpoints/handlers/responsewriters/errors.go:84`).

`EvaluateConditions` failures ignore `failurePolicy` altogether (`W:529-562`).

| Contributing finding | PR | path:line |
|---|---|---|
| [Important][code] Constructor fail-closed ignores the webhook `failurePolicy` | #137513 A Sec | `AZ/conditionsmap.go:139-146,150-174`; `encoding.go:134-142`; `AZ/conditionsunion.go:138-141` |
| [Important][KEP] KEP: the FailureMode governs invalid conditions | #137513 A KEP | `kep.md:744-745,754-755,761-763,793-795` |
| [Important][code] DV-valid, constructor-rejected maps skip `failurePolicy=Deny` | #137633 A S1 | `encoding.go:134-142` |
| [Important][test] No test for the above | #137633 A Tests | `AS/pkg/apis/authorization/v1/encoding_test.go` |
| [Important][code] Explicit or implied Deny weakened to `failurePolicy` on the conditions-aware path only | #137633 B S1 | `W:323-329,349-354` vs `W:258-267` |
| [Important][test] No conditions-aware failure test with `decisionOnError=NoOpinion` | #137633 B Tests | `webhook_conditional_test.go:258-267` |
| [Important][code] Conditions-aware ≠ `FromParts(Authorize)` without ACR; `evaluationError` → 500 + leak | #137204 Sec | `W:286-292,326-345` |
| [Important][test] No equivalence test | #137204 Tests | (none) |
| [Important][code] Client-controlled `fieldSelector==x` trips spec validation and flips Deny → NoOpinion | #140714 Sec | `W:327`; `AS/pkg/apis/authorization/validation/validation.go:37`; `staging/src/k8s.io/apimachinery/pkg/fields/selector.go:418-428`; `W:604-607` |
| [Important][test] No negative test for the above | #140714 Tests | `webhook_conditional_test.go` |
| related [Question] empty user fails the spec check on the conditions-aware path only | #140714, #137633 A | `validation.go:45-47`, `W:276-283` |
| related [Question] unknown type follows `failurePolicy`; v1beta1 uses Deny | #137633 A | `encoding.go:149-150` |
| related [KEP] ACR failures use `FailureDecision`, not `failurePolicy` | #137633 B KEP | `W:529-562` |
| related threads | F-47 | |

- **Fix carried by:** follow-up on the #137633 webhook code (`W`) and `AS/pkg/apis/authorization/v1/encoding.go`; validation package (#140714).
- **Disposition:** must-fix before beta:
  1. Validate only the response status (`ValidateSubjectAccessReviewStatus` + status DV), not the locally built spec.
  2. Route constructor errors to `failClosed`, or make DV match the constructor.
  3. On a validation failure, return Deny if `denied` is set or any deny condition is present.
  4. When `!handlesConditional`, make `ConditionsAwareAuthorize` return `FromParts(Authorize)`.
  5. Add the equivalence and negative tests.

### R-4 Unbounded decision trees; DV vs constructor limit mismatch

`MaxConditionsPerMap=128` applies per map. A Union has no width or depth limit in DV, the decoder, or the builder (`API/v1/types.go:584-593` has no `maxItems`). Decode, DV, `PossibleDecisions`, `String()` and `collectReasonsAndErrors` all recurse without bound (`encoding.go:143-147`, `AZ/conditions.go:271-286`, `AZ/conditionsunion.go:187-208`), and `Add` checks duplicates in O(n²). There is also no webhook body limit (`W:812` TODO). One bad SAR or ACR response therefore costs unbounded CPU and memory on every replica.

The two validation layers disagree:

| Rule | DV | In-process constructor |
|---|---|---|
| Condition count | 128 per list | 128 in total |
| ID uniqueness | per list | across lists |
| Empty `conditionsMap: {}` | accepted | rejected |

The API doc promises the constructor's rules (`API/v1/types.go:470-475`).

| Contributing finding | PR | path:line |
|---|---|---|
| [Important][code] No bound on decision tree size | #137513 A Sec | `AZ/conditionsmap.go:116,154`; `AZ/conditionsunion.go:58-90` |
| [Important][code] Union width and depth unbounded; no response size limit | #137633 A S2 | `API/v1/types.go:584-593`; `W:812` |
| related [Question] per-map limits only | #140715 S6 | `AZ/conditionsunion.go:58` |
| related [KEP] API doc claims "128 in total" | #140715 K4 | `API/v1/types.go:472` |
| related threads | F-38, F-40, F-47 | thread #48 agreed on 16 per level "for beta" |

- **Fix carried by:** API types (#137633 code), the builder (`AZ/conditionsunion.go`), and `W`.
- **Disposition:** must-fix before beta, as maintainer-agreed in #137633 thread #48:
  - `+k8s:maxItems=16` on `union`;
  - a depth cap and a total-conditions cap in DV and the builder;
  - DV rules for ≥1 condition, ≤128 in total, and cross-list ID uniqueness;
  - a response body limit.

### R-5 Reload TOCTOU between authorization and enforcement

The filter stores the *reloadable resolver* in the request context (`authorization.go:170`). `ConditionsAwareAuthorize` and `EvaluateConditions` each call `r.current.Load()` (`pkg/kubeapiserver/authorizer/reload.go:92-99`). A reload while the request sits in decode or mutating admission routes the named sub-decisions to the new chain (`union.go:188-194`). If the same name now points at a different webhook or ACR context, that endpoint evaluates conditions it never authored, and any answer within `PossibleDecisions`, including Allow, is accepted.

The KEP says the two stages are atomic (`kep.md:533-537`) and that "an authorizer only ever evaluates its own conditions" (`kep.md:1972-1975`).

| Contributing finding | PR | path:line |
|---|---|---|
| [Important][code] Reload between filter and enforcer | #137204 Sec | `reload.go:92-99` |
| [Important][code] Same; a renamed webhook can Allow | #137633 B S3 | `reload.go:92-98`, `authorization.go:170` |
| related [Question][code/KEP] Same, rated Question (severity disagreement across reviews) | #141959 Sec, #137513 B Sec | `reload.go:96-98`, `union.go:198-203` |

- **Fix carried by:** a #141959 follow-up (filter) + `reload.go`.
- **Disposition:** must-fix before beta. Have the filter store `current.Load().authorizer` (a `Snapshot()` method) instead of the resolver.

### R-6 Ungated 403 / SAR reason-text change, in three formats

With the gate off, union `Authorize` now prefixes aggregated NoOpinion reasons with `<name>: ` (`union.go:88-89`), while the short-circuit Allow/Deny reason stays unprefixed (`:92-93`). Combined with the #140715 renames, 1.38 emits new text:
- `alwaysdeny: Everything is forbidden.` for anonymous users;
- `rbac: RBAC: …`;
- `system-privileged-group.authorizer.kubernetes.io: …`;
- `webhook.authorizer.kubernetes.io: <reason>` in every delegating apiserver.

This discloses authorizer names to unauthenticated clients. The conditions-aware fold uses a third format, `name: {r}` joined by `", "` (`AZ/conditionsunion.go:192,162-170`), so writes and reads of the same user get differently formatted 403s (`IT:1212` vs `:1256`, Q9). No thread discussed it.

| Contributing finding | PR | path:line |
|---|---|---|
| [Important][code] Ungated, undiscussed reason change; three formats | #137513 B S1 | `union.go:88-93,99`; `AZ/conditionsunion.go:162-170,192` |
| [Important][KEP] KEP silent on reason format | #137513 B K6 | (none) |
| [Important][test] Prefix and asymmetry not unit-tested | #137513 B Tests | `union_test.go:36-38` (empty reasons); `test/integration/controlplane/synthetic_controlplane_test.go:179` only |
| [Important][code] Rename + prefix visible in 403s and SAR, ungated | #140715 C1 | `union.go:88-89`, `AS/pkg/authorization/authorizerfactory/builtin.go:117`, `AS/pkg/server/options/authorization.go:213` |
| related threads | F-7, F-24, F-48 | |

- **Fix carried by:** follow-up on `AS/pkg/authorization/union/union.go` and `AZ/conditionsunion.go`.
- **Disposition:** user decision (Part 5, D-4).

### R-7 Evaluation semantics drift from the KEP, and unverified algebraic properties

| Topic | KEP | Code |
|---|---|---|
| Deny-effect error | `failurePolicy` decides (`kep.md:811-813`) | always Deny + error (`AZ/evaluate.go:144-145`) |
| Allow-effect error | "ignored" (`kep.md:829-830`) | NoOpinion + error (`AZ/evaluate.go:182-183`), which becomes a 500 that echoes condition IDs and evaluator messages to the requester (`ENF:126-129`) |
| Chain evaluation | lazy (`kep.md:872-876,938-947`; the KEP contradicts itself at `:1124,1300-1306`) | eager (`union.go:114-125`) |

Partial-then-full evaluation is not confluent when the partial evaluator returns errors. In the Allow block, `{allow-err, allow-unevaluated}` gives NoOpinion+err and discards the unevaluated condition (`AZ/evaluate.go:182-187`). It is safe in-tree only because #143024 maps builtin errors to Unevaluatable (`W:966-971`).

The guard property that the filter, enforcer and union depend on is untested: `PossibleDecisions` soundness against evaluation, and `PD(partial(d)) ⊆ PD(d)`. So are union laziness (`union_test.go:930`: the counter is never asserted) and the union error paths.

| Contributing finding | PR | path:line |
|---|---|---|
| [Important][KEP] Deny-error FailureMode | #137513 B K1 | `kep.md:811-813` vs `AZ/evaluate.go:144-145` |
| [Important][KEP] Allow-error ignored vs surfaced | #137513 B K2 | `kep.md:829-830` vs `AZ/evaluate.go:182-183` |
| related [Question][code] Allow-error 500 leaks evaluator text | #137513 B Sec | `AZ/evaluate.go:182-183,217`; `ENF:126-129` |
| [Important][code/KEP] Partial evaluation non-confluent with errors | #137513 B Bugs | `AZ/evaluate.go:182-187` |
| [Important][KEP] Lazy vs eager | #137513 A KEP | `kep.md:872-876,938-947` vs `union.go:114-125` |
| [Important][test] No `PossibleDecisions` soundness test | #137513 A Tests | `AZ/conditions.go:204`, `AZ/conditionsmap.go:103`, `AZ/conditionsunion.go:116` |
| [Important][test] Union `EvaluateConditions` error paths untested | #137513 B Tests | `union.go:134-136,166-167,190-191` |
| [Important][test] Union laziness unasserted | #137513 B Tests | `union_test.go:930` |
| [Important][test] Allow-error + unevaluated Allow untested | #137513 B Tests | `AZ/evaluate.go:182-187` |
| related threads | F-22, F-30 | |

- **Fix carried by:** a #137513 code follow-up (`AZ/evaluate.go`, tests); KEP.
- **Disposition:**
  - KEP for K1 and lazy/eager.
  - The Allow-error case is a user decision (Part 5, D-3).
  - Before beta: fix the non-confluence (rank unevaluatable above error when same-effect unevaluated conditions exist), or document "evaluateConditionFn returns Error only if authoritative".
  - Add brute-force property tests over small trees.

### R-8 #143024 in-process CEL: cost, compilation, deferral semantics, ACR coupling

- **Cost.** Each `EvaluateCondition` gets the full `RuntimeCELCostBudget` and discards the remainder (`CEL:52` TODO, `:168`). One map can spend 128 × 10⁷ cost units per request.
- **Compilation.** Every call re-parses, re-checks and re-plans the expression (`CEL:163`), and compilation is outside the cost budget.
- **Deferral.** Every builtin error, runtime or budget included, is deferred to the webhook (`W:963-972`). The ACR carries no `namespaceObject` or `authorizer` handle (`W:494-516`), so outcomes diverge by replica or skew.
- **ACR coupling.** The builder is built only when `conditionsReview` is configured (`reload.go:189-190`), so a CEL-only webhook has no path (Q2). The KEP requirement that an authorizer can evaluate any condition it authored (`kep.md:1974-1976`) conflicts with the env variables.
- **Tests.** The refined-decision guard (`W:545-560`) is untested.

| Contributing finding | PR | path:line |
|---|---|---|
| [Important][code] Cost budget per condition, no per-request total | #143024 S1 | `CEL:52,168` |
| [Important][code] Recompiles on every `EvaluateCondition` | #143024 S2 | `CEL:163` |
| [Important][code] "Builtin error ⇒ webhook" is not outcome-preserving | #143024 S3 | `W:963-972`, `W:494-516` |
| [Important][KEP] In-process CEL only with ACR configured | #143024 KEP | `reload.go:189-190,204`; `W:287` |
| [Important][KEP] Authorizer requirement vs CEL env | #143024 KEP | `kep.md:1974-1976` vs `CEL:91-106` |
| [Important][test] Refined-decision guard untested | #143024 Tests | `W:545-560` |
| related [Question] `namespaceObject` from the informer cache; builder rebuilt per reload | #143024 | `CEL:91,133`; `reload.go:204-208` |
| related threads | F-9, F-60, F-62, F-63, F-64, F-65; Q2, Q3 | |

- **Fix carried by:** #143024 (open).
- **Disposition:**
  - Before merge: S1 (thread `remainingBudget`), S2 (bounded LRU of compiled programs), S3 (defer only compile-time errors), the guard test, and godoc / nil-condition (F-60, F-62).
  - Before beta: benchmarks and the skew runtime-error case (F-63, F-65).
  - CEL-without-ACR is a user decision (Part 5, D-5).

### R-9 Metrics: `decisions_total` double-counts and counts non-terminal decisions; tests are vacuous

Every authorizer in the union is instrumented. For one conditional write:
1. The webhook gets `conditional`.
2. RBAC gets `allowed` (non-terminal).
3. The webhook gets `allowed` or `denied` again at the enforcer.

The help text still says "terminal decisions" (`AS/pkg/authorization/metrics/metrics.go:39`). The metric records the pre-guard result (`metrics.go:119-131`). The new metric tests go through `Authorize` and never reach the new code (`metrics_test.go:58-123`).

| Contributing finding | PR | path:line |
|---|---|---|
| [Important][code] Double and non-terminal counting | #137204 Bugs | `metrics.go:39,97-133`; `union.go:114,193` |
| [Important][test] Metric tests never call `ConditionsAwareAuthorize` / `EvaluateConditions` | #137204 Tests | `AS/pkg/authorization/metrics/metrics_test.go:58-123,137` |
| related [Nit] no enforcer-side outcome metric; no ACR, latency or in-process metrics | #141959, #137204, #143024, #137633 B | `AS/pkg/endpoints/filters/metrics.go:139-148`; `W:523` TODO |

- **Fix carried by:** a #137204 follow-up (`metrics.go`).
- **Disposition:** should-fix before beta. Use distinct `conditional_allowed`/`conditional_denied` labels, fix the help text, add the real tests, and add the KEP's evaluation-latency metric or drop it from the KEP.

### R-10 Audit annotations are first-writer-wins

The enforcer writes `decision`/`reason` per evaluation (`ENF:116-121,135-138`). deletecollection and conflict retries evaluate several times, and the audit context ignores later writes (`AS/pkg/audit/context.go:351-353`). A request that ends 403 can therefore be audited `decision=allow`. The author left a TODO at `ENF:115-116`.

| Contributing finding | PR | path:line |
|---|---|---|
| [Important][code] First-writer-wins audit | #141959 Bugs | `ENF:115-121`; `AS/pkg/audit/context.go:351-353` |

- **Fix carried by:** a #141959 follow-up.
- **Disposition:** must-fix before beta. Write the final decision once (a deferred annotation keyed on the returned error), or use per-evaluation keys.

### R-11 Filter and enforcer read the feature gate from different sources

`server/config.go:1077` uses `utilfeature.DefaultFeatureGate`. The enforcer uses the gate injected by `InspectFeatureGates` (`ENF:63-65,74-80`). `RecommendedOptions` accepts a custom `FeatureGate` (`AS/pkg/server/options/recommended.go:73`). With the default gate on and the injected one off, the conditions-aware filter is installed but `Handles()` is false, so conditional Allows complete unenforced. This is unreachable in kube-apiserver (`pkg/controlplane/apiserver/config.go:434`); it is a latent fail-open in exported generic wiring.

| Contributing finding | PR | path:line |
|---|---|---|
| [Important][code] Gate source mismatch | #141959 Sec | `AS/pkg/server/config.go:1077` vs `ENF:63-65,74-80` |
| related [Nit] builder not gated in `newWithBackoff` | #143024 Clarity | `W:169` vs `W:153-157` |

- **Fix carried by:** a #141959 follow-up.
- **Disposition:** must-fix before beta (once default-on, custom gates make it reachable). Choose the filter from the gate the enforcer saw, or make the enforcer reject a conditional ctx decision even when its own gate is off.

### R-12 SAR and LocalSAR disclose another user's full conditions tree

For another subject, SAR and LocalSAR return `status.conditionalDecision`, which is policy source (`pkg/registry/authorization/subjectaccessreview/rest.go:100-102`, `localsubjectaccessreview/rest.go:109-111`, `util/helpers.go:276`). The webhook sees the subject, not the requester, so it cannot redact.
- LocalSAR create is granted to every namespace admin (`plugin/pkg/auth/authorizer/rbac/bootstrappolicy/policy.go:421`).
- Cluster SAR create is in the node authorizer's static rules (`policy.go:216`).

The KEP risk analysis covers SelfSAR only (`kep.md:1995-2011`).

| Contributing finding | PR | path:line |
|---|---|---|
| [Important][KEP] SAR/LSAR return other users' trees | #141959 Sec | `localsubjectaccessreview/rest.go:109-111`, `subjectaccessreview/rest.go:100-102` |
| [Important][KEP] Not in the KEP risk analysis | #141959 KEP | `kep.md:1995-2011` |
| related [Nit] SelfSAR exposes authorizer names and chain | #141959 Sec | `helpers.go:276`; `IT:1076-1101` |
| related [Question] ACR sends full object contents (Secret `data`) to the authz webhook | #137633 B Sec | `W:509-514` |

- **Fix carried by:** KEP; optionally a #141959 follow-up in `pkg/registry/authorization/*`.
- **Disposition:** should-fix. The KEP must state the exposure. Consider folding when subject ≠ requester, or a separate verb.

### R-13 The delegating authorizer advertises conditions to an unserved ACR endpoint

`AS/pkg/server/options/authorization.go:206` always passes `client.AuthorizationV1alpha1()`. `NewFromInterface` turns it into a reviewer (`W:107-111`), and the gate is the only filter (`W:153-157`). With the gate on, every generic/aggregated apiserver therefore advertises `handledDecisionTypes` (`W:287-292`). That breaks the invariant stated at `W:285-286`. kube-apiserver serves no ACR (`pkg/registry/authorization/rest/storage_authorization.go:44-49`). An out-of-tree `WantsAuthorizer` plugin calling `ConditionsAwareAuthorize` can receive a Map/Union whose evaluation always 404s and fails closed. If it tests `!IsDeny()`, it fails open.

| Contributing finding | PR | path:line |
|---|---|---|
| [Important][code] Gate is the only guard in generic apiservers | #140916 Sec | `AS/pkg/server/options/authorization.go:206`; `delegating.go:60-69`; `W:108-111,153-157,287-292` |
| [Important][code] Advertises to a non-existent endpoint | #137633 B S4 | same |
| [Important][KEP/code] KEP: kube-apiserver serves ACR; code does not | #137633 A KEP | `kep.md:1130-1131,1213-1214` vs `storage_authorization.go:44-49` |
| [Important][KEP] KEP omits the `SetAuthorizer` path for out-of-tree plugins | #140916 KEP | `kep.md:1614-1617` |
| [Important][test] No test of delegating advertisement with the gate on | #140916 Tests | `webhook_conditional_test.go:324` covers the leaf only |
| related | F-9, F-53; Q6 | |

- **Fix carried by:** follow-up on `AS/pkg/server/options/authorization.go` (#137633 code); KEP.
- **Disposition:** must-fix before beta. Leave `AuthorizationConditionsReviewClient` nil until kube-apiserver serves ACR (explicit opt-in). Document the `WantsAuthorizer` obligation.

### R-14 Enforcer position: mutating/validating admission and side effects run before authorization is final

The enforcer sits at position 37 of 40, after mutating admission, every built-in validator and VAP (`pkg/kubeapiserver/options/plugins.go:113-114`).
- `NamespaceAutoProvision` creates namespaces inside `Admit` ("if we're here … we're allowed", `plugin/pkg/admission/namespace/autoprovision/admission.go:65`).
- Side-effecting webhooks are called.
- Validator and VAP `messageExpression` output is returned to callers whose conditions evaluate to Deny.

The KEP puts the enforcer first among validators (`kep.md:469,977-979`) and never discusses side effects.

| Contributing finding | PR | path:line |
|---|---|---|
| [Important][code/KEP] Side effects and messages before final authz | #141959 Sec | `plugins.go:73-117`; `autoprovision/admission.go:65-95` |
| [Important][KEP] Enforcer position differs from the KEP | #141959 KEP | `kep.md:977-979,469` vs `plugins.go:113-115` |
| related [Nit] evaluation fan-out per item and retry | #141959 Sec | `update.go:229-237`; `ENF:112` |

- **Fix carried by:** a #141959 follow-up; KEP.
- **Disposition:** user decision (Part 5, D-6). Independent of the decision, make side-effecting in-tree plugins skip unless the ctx decision `IsAllow()`.

### R-15 Compound create-on-update is unconditional while the primary decision may be conditional

`withAuthorization` in `AS/pkg/endpoints/handlers/update.go:255-283` calls the unconditional `Authorize(create)`:
- A conditional create grant gives a 500.
- A conditional update grant is evaluated by the enforcer against a CREATE with no old object, so update conditions are enforced on a create.

Both cases fail closed. They contradict `kep.md:1657-1661`, and the integration rows are commented out and no longer compile (`IT:653-835`). shipped.md Q8.

| Contributing finding | PR | path:line |
|---|---|---|
| [Important][KEP/code] Compound create-on-update | #141959 KEP | `update.go:255-283`; `kep.md:1657-1661`; `IT:653-835` |
| related [Question] same, both cases | #138801 Sec | `update.go:258-279` |

- **Fix carried by:** a #141959 follow-up (endpoints handlers) + KEP.
- **Disposition:** fix the code before beta (a conditions-aware create check). For alpha, state the behaviour in the KEP.

### R-16 Union name validation is split across layers

`union.New` checks only empty and duplicate names (`union.go:57-68`), and does not check for a nil authorizer. `ConditionsAwareDecisionUnion.Add` additionally requires DNS-1123 (`AZ/conditionsunion.go:70-72`), so an out-of-tree `union.New("my_authz", …)` makes every conditions-aware request fail closed while `Authorize` works. Config validation only warns on reserved names (`AS/pkg/apis/apiserver/validation/validation.go:641-647`), so the built-in superuser name can collide (startup or reload failure).

| Contributing finding | PR | path:line |
|---|---|---|
| [Important][code] `union.New` accepts names the builder rejects; nil unchecked | #137513 B Bugs | `union.go:57-68` vs `AZ/conditionsunion.go:70-72` |
| [Important][test] `union.New` error paths untested | #137513 B Tests | `union.go:59-65` |
| related [Nit] built-in name collision; DNS-1123 at the wrong layer | #140715 B1, B2 | `reload.go:117-121,256-259`; `validation.go:639-642` |
| related threads | F-20 | |

- **Fix carried by:** follow-up on `AS/pkg/authorization/union/union.go` and the apiserver config validation.
- **Disposition:** should-fix. Validate DNS-1123 and non-nil in `New`. Reject exactly the built-in names in config validation.

### R-17 Nil-safety of exported helpers

`ConditionsMap.Evaluate` is documented "if set", but calls `evaluateConditionFn` unconditionally (`AZ/evaluate.go:99-111`). Every wire-decoded `GenericCondition` self-reports Unevaluatable, so a nil function panics. The reviews disagree on severity: #137513 A says Important, #137513 B and #140715 B3 say Nit. Same family:
- `union.EvaluateConditions` with nil data;
- typed-nil `data` at `W:437`;
- nil `result` at `W:532`;
- `ValidateConditionsReviewConfiguration(nil)` (F-44).

| Contributing finding | PR | path:line |
|---|---|---|
| [Important][code] `ConditionsMap.Evaluate` nil panic | #137513 A Bugs | `AZ/evaluate.go:99-111` |
| related [Nit] same | #137513 B, #140715 B3 | `AZ/evaluate.go:104-111` |
| related [Nit] nil data/result guards | #137513 B, #137633 B | `union.go:131`; `W:437,532` |
| related threads | F-19, F-44 | |

- **Fix carried by:** a #137513 code follow-up; webhook; apiserver validation.
- **Disposition:** should-fix. Fail closed with an error result, or document the parameter as required.

### R-18 Security guards pinned only by fakes, or not at all (test debt)

- The UID echo check (`W:540-543`) is vacuous: the fake overwrites the UID (`webhook_conditional_test.go:82-84`).
- No test sets legacy `allowed=true` with `conditionalDecision`. Swapping the case order at `W:264/268` is a fail-open that no test catches.
- The Disabled/EnforcerDisabled integration runs check only outcome and ACR count. The mock folds conditional decisions itself (`IT:1907-1918`), so the apiserver's fail-closed path is never exercised end to end.
- The integration matrix lacks DELETE, deletecollection, PATCH, apply, subresources, CONNECT, `failurePolicy: Deny`, ACR error, top-level Union, update-to-create, dry-run, conflict retry and reload.
- No end-to-end row where the **old** object alone decides (`hpa_conversion_test.go:173-206,243-287`; `crd_conversion_test.go:344-471`).

| Contributing finding | PR | path:line |
|---|---|---|
| [Important][test] UID echo untested; the fake makes it vacuous | #137633 B Tests | `webhook_conditional_test.go:82-84`; `W:540-543` |
| [Important][test] Legacy `allowed=true` + conditional untested | #137633 B Tests | `W:264,268`; `webhook_conditional_test.go:458-465` |
| [Important][test] Disabled runs do not prove 1.37 equality | #141959 Tests | `IT:974-995,1001-1006,1907-1918` |
| [Important][test] Missing integration coverage | #141959 Tests | `IT:653-835` (commented), `IT:1922-1924` |
| [Important][test] No end-to-end test where the old object alone decides | #142493 Tests | `test/integration/apiserver/conditionalauthorization/hpa_conversion_test.go:173-206`; `crd_conversion_test.go:344-471` |

- **Fix carried by:** #137633 tests (webhook unit), #141959 / #142493 integration tests (need etcd).
- **Disposition:**
  - Before beta: the UID, legacy-order and old-object-only rows, plus a mock mode that sends `conditionalDecision` to an unconditional SAR. These pin fail-open guards and are cheap.
  - Should-fix: the broad matrix.

### R-19 KEP interface and data-model drift (design changed deliberately)

The KEP still describes:
- a struct `Decision`, `Attributes.ConditionsMode()`, `ConditionSetEvaluator`, `Decision.Evaluate`/`CanBecomeAllowed`;
- no `UnconditionalAuthorizer` split;
- `status.conditionSetChain` instead of the `conditionalDecision` tree;
- `spec.conditionalAuthorization.mode` instead of `authorizationOptions.handledDecisionTypes`.

Each change was deliberate and reviewed (#137204 T9/T10/T11/T13; #137633 #3/#5/#13).

| Contributing finding | PR | path:line |
|---|---|---|
| [Important][KEP] Core interface section describes a different design | #138801 KEP | `kep.md:558-680` vs `AZ/interfaces.go:84-124` |
| [Important][KEP] Same | #137204 KEP | `kep.md:560-657` |
| [Important][KEP] KEP lacks the interface split | #140916 KEP | `kep.md:560-586` vs `AZ/interfaces.go:99-124` |
| [Important][KEP] Status shape: tree, not chain | #137633 A KEP | `kep.md:1000-1068` vs `API/v1/types.go:307,541-593` |
| [Important][KEP] Opt-in field | #137633 A KEP | `kep.md:1098-1113,592-610` vs `API/v1/types.go:412-429` |
| related [Nit][KEP] (≈30 rows) | all PRs | e.g. #140715 K1-K11, #141959 KEP Nits, #143024 KEP Nits, #142493 KEP Nits |
| related threads | F-6, F-14, F-27, F-34, F-36, F-58 | |

- **Fix carried by:** a KEP update (the Stage 3c deliverable).
- **Disposition:** KEP-only.

### R-20 Go API compatibility for out-of-tree consumers

Between `9d011e034bf` (2026-05-08) and `0d50fdfe28b` (2026-07-28), out-of-tree `SetAuthorizer` plugins silently received no authorizer. A plugin that guards with `if authz != nil` skipped its check (fail-open) in v1.37.0-alpha.1 … beta.0. #140916 restored only the interface. The concrete in-tree `SetAuthorizer` methods (`plugin/pkg/admission/gc/gc_admission.go:296`, `noderestriction/admission.go:170`, `certificates/*`, `AS/pkg/admission/plugin/policy/generic/plugin.go:158`, `AS/pkg/admission/plugin/webhook/generic/webhook.go:249`) are still renamed, and no release note mentions it.

| Contributing finding | PR | path:line |
|---|---|---|
| [Important][code] `SetAuthorizer` gap between merges | #138801 Sec | `AS/pkg/admission/initializer/initializer.go:95-99` |
| [Important][code] #140916 did not restore the concrete setters | #138801 Bugs | as listed above |
| related [Question] ungateable Go API break; #143024 `NewFromInterface` churn | #137204, #143024 | `AZ/interfaces.go:103-124`; `W:107,135` |

- **Fix carried by:** release notes (1.37 "action required" and 1.38); optionally shims on `generic.Webhook` / `generic.Plugin[H]`.
- **Disposition:** should-fix (documentation). I could not verify whether release-1.37 at rc.0 contains #140916: there are no tags or release branch locally.

---

## PART 3: Buckets

All clusters are Important, so within each bucket the order is by risk: fail-open first, then wrong-evaluator, then DoS, then audit/observability, then tests. Thread items (mostly Nit) come after the clusters.

### Must-fix-before-beta

1. **R-1** classifier holes: aggregated APIs, unsafe delete, CONNECT re-check (F-51, F-52). Fail-open once the gate is on.
2. **R-3** `failurePolicy` bypass and asymmetry; client-triggerable via `fieldSelector==x` (F-47).
3. **R-11** gate source mismatch (latent fail-open in exported wiring; reachable by default at beta).
4. **R-13** delegating authorizer advertises to an unserved ACR (F-53).
5. **R-5** reload TOCTOU (a different endpoint can Allow).
6. **R-14** (code part only): side-effecting in-tree plugins (NamespaceAutoProvision) must skip unless `IsAllow()`. The ordering itself is D-6.
7. **R-4** unbounded trees, DV/constructor mismatch, response size limit (F-38, F-40; maintainer-agreed in #137633 thread #48).
8. **R-8** #143024: cost budget, compile cache, error deferral, guard test. Before **merge** of #143024. F-63, F-64 and F-65 before beta.
9. **R-10** audit first-writer-wins.
10. **R-15** compound create-on-update (code before beta; KEP for alpha).
11. **R-7** non-confluence fix or precondition doc, plus `PossibleDecisions` soundness and laziness tests.
12. **R-18** (subset) UID echo, legacy `allowed+conditional` order, old-object-only end-to-end row, mock mode for unrequested conditionals.

### Should-fix

1. **R-2** after D-2: document the `Authorize` contract; caller or deletion for `OrFailClosed`; reason for the deny-only 403 (F-11).
2. **R-6** after D-4: single reason formatter (F-7, F-24, F-48 release note).
3. **R-12** SAR/LSAR disclosure (KEP text plus an optional fold for subject ≠ requester).
4. **R-9** metrics labels, help text and real tests.
5. **R-16** `union.New` validation; reject built-in names in config.
6. **R-17** nil-safety (F-19, F-44).
7. **R-18** remainder: the broad integration matrix.
8. **R-20** release notes for the Go API breaks.
9. Thread items (Nit unless stated):
   - F-1 TODO in public doc;
   - F-10 `EvaluateConditions` default/clamp doc;
   - F-13 reserved-prefix enforcement (Question-level);
   - F-17 `EvaluateFn` naming;
   - F-21 `FailureDecision` allocation;
   - F-23 admission doc;
   - F-26 union semantics Go doc;
   - F-32 stale test comment;
   - F-56 classifiability of SAR/TokenReview (decide);
   - F-60, F-61, F-62 #143024 godoc / dedupe / nil condition.

### KEP-only (design changed; document it)

1. **R-19** interface, status shape, opt-in field, condition model (F-6, F-14, F-27, F-34).
2. KEP halves of other clusters:
   - R-2: the fold-down contract and the 500.
   - R-7: Deny-error is always Deny; eager chain; K3-K5 wording.
   - R-13: ACR is a wire type and is not served; resource name.
   - R-14: enforcer position and its consequences.
   - R-1: the aggregated-API model.
   - R-12: SAR/LSAR exposure.
   - R-8: ACR carries a refined decision; condition type name; what the ACR-side evaluator sees.
   - R-15: alpha behaviour.
   - R-4: limits.
3. Thread items:
   - F-36: `kubeConfigContextName` optional, the same endpoint dispatches on TypeMeta.
   - F-58: wildcards are classified.
   - #141959 thread #4: gate on + enforcer off → warn, not fail start.
   - deletecollection per object.
   - GET connect not covered.
   - kubelet and pod connect are unconditional in alpha (Q5).

### Explicitly deferred by maintainers

| Item | Where deferred (thread) | Notes |
|---|---|---|
| Union `maxItems=16` | #137633 thread #48 ("for beta graduation") | No tracking issue; listed under must-fix (R-4) because of the beta timing |
| Unbounded `strings.Split` → `SplitN` | #140715 T2 (liggitt: "standalone PR") | No PR found (F-31) |
| "failed closed" wording | #140715 T7 (author: "separate PR") | No issue (F-33). Pick wording before beta |
| Delete nil-authorizer filter branches | #141959 #26 → kubernetes/kubernetes#143440 | F-57 |
| conversion-gen memory-identical; double conversion | #137633 #71/O5, #141959 #22 → #142345 | F-43 |
| Fuzz new fields | #137633 #59, #72 → #142346 | F-42 |
| Delete apiserver.config v1alpha1/v1beta1 authz config | #137633 #79, #80 → #142318 | Addressed otherwise |
| Builtin evaluator for delegating/aggregated servers | #143024 #23 ("next release") | F-9. No issue |
| ACR AuditAnnotations/Warnings parity | #137633 #44 | F-39. No TODO |
| Unify `AdmissionRequest` building with `CreateV1AdmissionReview` | #137633 O4 / B-O2 | F-50. No issue |
| Simplify DV exclusion mechanism | #137633 O3 | F-49. TODO `pkg/api/testing/validation_test.go:88` |
| matchConditions API-version TODO | #137633 #83 | F-45 |
| 403 vs 500 for errors with Deny/NoOpinion | #137513 B#69 | F-30. TODO `AZ/evaluate.go:139-141`; linked to D-2/D-3 |
| Partial error list on short-circuit | #137513 O-C21 | F-28 |
| Partial evaluation's first user | #137513 #22/#32 → #143024 | F-18 |
| Type-safe `EvaluateConditions` argument | #137204 O1 (declined by liggitt) | F-12 |
| GET connect requests | #137633 B#23 (author: "not … in 1.37") | Part of F-51 |

---

## PART 4: Unaddressed threads (checklist for the author)

- [ ] **F-52** (#137633 thread #24, liggitt): aggregated APIs are classified conditions-aware (`pkg/controlplane/apiserver/config.go:298-318`). Your planned direction ("always conditional") widens the hole. Fix per R-1 and reply on the thread.
- [ ] **F-47** (#137633 thread #87, liggitt): nothing checks that a `conditionsMap` has ≥1 condition. Relying on the constructor bypasses `failurePolicy` (R-3). Add DV/handwritten rules for non-empty, ≤128 total and cross-list unique IDs, or route constructor errors to `failClosed`.
- [ ] **F-56** (#141959 thread #18, your own): decide whether admission-excluded resources (SAR, TokenReview) stay non-classifiable (`config.go:296,307-309`). Record the decision in the KEP.
- [ ] **F-13** (#137513 A thread #0, micahhausler): the reserved `*.k8s.io`/`*.kubernetes.io` domain is unenforced (`AZ/conditionsmap.go:187-219`). Either enforce an allowlist of built-in types, or drop "reserved" from `AZ/interfaces.go:265,271` and `API/v1/types.go:437,454`.
- [ ] **F-21** (#137513 A thread #41, liggitt; resolved in the UI, code unchanged): `FailureDecision` builds the full `PossibleDecisions` set (`AZ/conditions.go:225`, `AZ/conditionsmap.go:51`, `AZ/conditionsunion.go:99`). Add a `canDeny()` fast path.
- [ ] **F-17** (#137513 A thread #13, deads2k): rename `GenericCondition.EvaluateFunc` → `EvaluateFn` (`AZ/conditionsmap.go:229`) while the API is alpha, or reply that you are keeping it.
- [ ] **F-63** (#143024 thread #13): add `Benchmark*` for `EvaluatorForData` + `EvaluateCondition` (none in `authorization_conditions_test.go`). Needed to size R-8.
- [ ] **F-65** (#143024 thread #20): add a skew case that compiles but errors at runtime, and a budget-exhaustion case (only the compile-error prefix exists, `IT:1574`).
- [ ] **F-61** (#143024 thread #11): de-duplicate `getNamespace` with VAP (`CEL:118-140`), or note why the copy stays.
- [ ] **F-2** (#138801 overview, lint): `self` receivers in `AS/pkg/admission/initializer/initializer_test.go`. Already declined as pre-existing, so just close the loop.

---

## PART 5: Open user-level decisions

**D-1 Scope of conditional authorization: aggregated APIs and unsafe delete (R-1).**

Options for aggregated APIs:
- (a) Classify aggregated groups false. kube-apiserver answers them unconditionally, and the conditional decision folds to `FailureDecision`.
- (b) Keep classifying them, but make the proxy reject any non-`IsAllow()` ctx decision.
- (c) Implement the KEP model: pass-through, with the aggregated server re-authorizing and serving ACR.

Options for unsafe delete:
- (a) Refuse unless `IsAllow()`.
- (b) Evaluate conditions against no object.

Recommendation: (a) for both in alpha and beta. (c) needs ACR to be served and every aggregated server to re-authorize, which the KEP can only ask of third parties ("MUST"), not enforce. Conditions cannot be evaluated on an undecodable object, so refusing is the only correct answer for unsafe delete. Revisit (c) together with D-5 and R-13 when ACR is served.

**D-2 Unrequested conditional answer to a conditions-unaware caller: 403 or 500 (R-2, Q1).**

Options:
- (a) Keep the current error, which gives a 500 at every narrowed site.
- (b) Fold with `UnconditionalPartsOrFailClosed`, which gives a 403 with a descriptive reason.
- (c) Split by cause: 500 when a webhook violates the protocol (it answered conditionally although `authorizationOptions` was not sent), and 403 via `OrFailClosed` in the filter's non-Allow conditional branch, where the decision is legitimate but cannot reach Allow.

Recommendation: (c).
- A protocol violation by a configured webhook is a server-side fault and should page someone, so 500 is right there. The KEP should say so.
- The filter's reasonless 403 (`authorization.go:208-221`) is the case `OrFailClosed` was written for. Wiring it in gives `OrFailClosed` its call site (liggitt's T21 rule).
- Decide separately whether the "possible outcomes [Allow …]" text may reach unprivileged clients. I would keep it in the audit annotation only.

**D-3 Allow-effect condition errors: ignored or surfaced (R-7, K2).**

Options:
- (a) Current code: NoOpinion + aggregated error, so a 500 echoing condition IDs and evaluator messages when nothing later allows.
- (b) KEP: ignore the error, which gives NoOpinion with no error and so a 403; log it and add an audit annotation.
- (c) NoOpinion + an error marked non-fatal, which the filter and enforcer log but do not turn into a 500.

Recommendation: (b) for alpha, which matches the KEP. The requester often controls the input that makes an Allow expression error (e.g. a missing field), so (a) gives clients a 500 lever and an information channel. An Allow error can never correctly grant access anyway. Keep Deny-effect errors as Deny + error (stricter than the KEP's FailureMode wording; update the KEP), and resolve the TODO at `AZ/evaluate.go:139-141` the same way.

**D-4 Ungated union reason prefix: ship or revert (R-6).**

Options:
- (a) Ship it, unify all three formats on `name: reason` (short-circuit included), and add a release note.
- (b) Revert the prefix in legacy `Authorize` so that gate-off output matches 1.37, and keep names only on the conditions-aware path.
- (c) Gate the prefix behind `ConditionalAuthorization`.

Recommendation: (b), with one formatter for the conditions-aware path:
- The change is user-visible with the gate off, so it breaks "gate off = 1.37".
- It discloses admin-chosen authorizer names and chain topology to anonymous clients (`alwaysdeny: …`).
- No reviewer discussed it.

If the names are wanted for debuggability, they belong in the audit annotation, not the 403 body. (c) is acceptable if the maintainers want the prefix eventually, but it still needs one format.

**D-5 In-process CEL without an ACR endpoint (R-8, Q2).**

Options:
- (a) Current: build the builtin evaluator only when `webhook.conditionsReview` is configured.
- (b) Build it whenever the gate is on, and let a webhook with no ACR receive conditional types; non-CEL conditions fail closed (`W:455-456`).
- (c) Add an explicit config knob, e.g. `conditionsReview.inProcessOnly`.

Recommendation: (c), or (b) with a validation warning. The KEP sells in-process CEL as a way to avoid a second webhook (`kep.md:1247-1255,1518`), and nothing in the threads says the coupling is deliberate.

Two blockers stand in the way. Each needs its own decision first:
- The authorizer-can-always-evaluate requirement (`kep.md:1974-1976`) conflicts with CEL variables that ACR does not carry (`namespaceObject`, `authorizer`).
- The "every builtin error ⇒ webhook" rule (`W:963-972`) is unsafe when there is no webhook to fall back to.

So: defer only compile errors; treat runtime errors as `Error`. Then a CEL-only mode is consistent: conditions are authoritative in-process, and anything unevaluatable fails closed.

**D-6 Enforcer position vs side-effecting admission (R-14).**

Options:
- (a) Keep the enforcer after VAP and the built-in validators (current). This avoids ACR calls for requests VAP would reject anyway. Document the changed invariant, and make side-effecting in-tree plugins check the ctx decision.
- (b) Move it to be the first validating plugin, as the KEP says. Mutating plugins and webhooks still see unauthorized requests.
- (c) Evaluate conditions before mutating admission, against the unmutated object. That contradicts the KEP's "fully-mutated object" design.

Recommendation: (b) plus the side-effect guard.
- The ordering gain of (a) is an optimisation.
- Its cost is a security-visible regression: validator and VAP rejection messages, including `messageExpression` output over params and objects, go to callers whose conditions deny. A long-standing invariant ("admission only sees authorized requests") is also broken for every built-in validator.
- Mutating admission before evaluation is inherent in the design and must be documented. `NamespaceAutoProvision` and any `sideEffects: Some` webhook remain the residual risk, so the guard in Part 3 item 6 is needed whichever option is chosen.

**D-7 (additional) SAR/LocalSAR disclosure of other users' condition trees (R-12).**

Options:
- (a) Keep it and document it in the KEP.
- (b) Return the folded unconditional status unless subject == requester.
- (c) Require a separate verb (e.g. `create` on a `subjectaccessreviews/conditions` subresource) for the conditional form.

Recommendation: (b) for alpha. It keeps SelfSAR useful and closes the namespace-admin and kubelet channels (`policy.go:421`, `:216`) at no cost to the main use case. (c) can come later if cluster-level tooling needs other users' trees.

---

## Nit findings (counts only)

Counts are the number of `[Nit]` tags in section 3 of each Stage 2 file. For #137513 and #137633 the count is Part A + Part B. KEP-table Nits are included.

| PR | Nits | Pointer |
|---|---|---|
| #138801 | 9 | `review/pr-138801.md` §3 |
| #137204 | 9 | `review/pr-137204.md` §3 |
| #137513 | 45 | `review/pr-137513.md` Part A §3, Part B §3 |
| #140916 | 7 | `review/pr-140916.md` §3 |
| #140715 | 15 | `review/pr-140715.md` §3 |
| #140714 | 6 | `review/pr-140714.md` §3 |
| #142493 | 9 | `review/pr-142493.md` §3 |
| #137633 | 42 | `review/pr-137633.md` Part A §3, Part B §3 |
| #141959 | 27 | `review/pr-141959.md` §3 |
| #143024 | 20 | `review/pr-143024.md` §3 |
| **Total** | **189** | |

Important tags by PR, as merged in Part 2: 5, 7, 17, 4, 3, 2, 1, 13, 13, 6 (total 71). Question tags: 24. They are not listed individually; the relevant ones appear as "related" in Part 2.

## Not checked

- Nothing was built or executed (this stage does not build).
- Whether release-1.37 rc.0 / 1.37.0 contains #140916, and whether the PRs carry release notes: there are no local tags or release branch, the overview JSON has no PR bodies, and there was no network access.
- Thread replies beyond the first exported comment are often missing. Unclear rows (F-15, F-29, F-54) stay unclear for that reason.
- No instruction-like text addressed to the reviewer appeared in the JSON exports I read.
