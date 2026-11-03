# pipeline

Scope: `lean/filters/authorization.lean`, `lean/filters/featuregate.lean`,
`lean/conditionsenforcer/conditionsenforcer.lean`, theorem statements of
`lean/conditionsenforcer/conditionsenforcer_properties.lean`.
Go: `S/pkg/endpoints/filters/authorization.go:55-225`, `S/pkg/endpoints/request/context.go:86-110`,
`S/pkg/admission/plugin/authorizer/conditionsenforcer/conditionsenforcer.go` (whole file),
`S/pkg/server/config.go:1070-1095` (`S/` = `staging/src/k8s.io/apiserver/`).

Build: `lake build filters.authorization filters.featuregate conditionsenforcer.conditionsenforcer
conditionsenforcer.conditionsenforcer_properties` succeeds. No `sorry`. One axiom
(`P_68_enforcer_runs`). One linter warning (unused simp arg `hd`, `conditionsenforcer_properties.lean:115`).

## Definitions

| Lean def | Go file:line | verdict | note |
|---|---|---|---|
| `filters.Attributes` | `authorizer/interfaces.go` (`Attributes`) | Abstraction | opaque; fine, no theorem inspects attributes |
| `filters.Authorizer` | `interfaces.go:86-124` | Abstraction | `ctx` dropped (README §9); pure functions |
| `filters.fromParts` | `conditions.go:102-118` | Equivalent | uncurried `ConditionsAwareDecisionFromParts`; unknown-Decision branch unreachable (README §8) |
| `filters.AuthorizerFunc` | `interfaces.go:133-145` | Equivalent | `CAA = FromParts ∘ f`; `EvaluateConditions = (Deny, "", ErrorConditionEvaluationNotSupported)` as in Go |
| `ConditionalAuthorizationRequestClassifier` | `authorization.go:55` | Equivalent | |
| `filters.Context` | `request/context.go:86-89` | Abstraction | context reduced to the one slot; ok |
| `ConditionallyAuthorizedDecisionFrom` | `context.go:105-108` | Equivalent | Go `ok` ⇔ Lean `some` |
| `WithConditionallyAuthorizedDecision` | `context.go:92-101` | Equivalent | error iff already set; else stores tuple. (Go returns `parent` on error; Lean's `.error` drops it, but every Go caller discards ctx on error) |
| `FilterOutcome` | `responsewriters.Forbidden` / `InternalError` / `ServeHTTP` | Abstraction | |
| `conditionsAwareDecisionFor` | `authorization.go:161-167` | Equivalent | classifier true → CAA, false → FromParts(Authorize) |
| `withConditionsAwareAuthorization` | `authorization.go:153-221` | Equivalent | same order: compute d → attach (error → 500, :170-174) → `IsAllow` → next (:190-199) → `PD.Has(Allow)` → next (:202-208) → `Error() ≠ nil` → 500 (:210-214) → 403. `Error` is `nil` for map/union in both (`conditions.go:266-268`, `conditions.lean:93-95`) |
| (not modelled) `a == nil` short-circuit | `authorization.go:67-70, :155-158` | Gap | documented in the module header only. Go passes the request through with no authorization and no tuple; see `end_to_end_safety` note below. No catalogued property depends on it (P-65 has `authorizer ≠ nil` as hypothesis) |
| (not modelled) `GetAuthorizerAttributes` error → 500 | `authorization.go:76-80, :164-168` | Abstraction | documented; only adds a non-admitting 500 |
| `WithConditionsAwareAuthorization` | `authorization.go:143-151` | Equivalent | `gate ∧ classifier ≠ nil` else error |
| `withAuthorization` | `authorization.go:66-125` | Equivalent | Allow checked before err (:93); on Allow with gate on attaches `(AuthorizerFunc(a.Authorize), ConditionsAwareDecisionAllow(reason, err))` (:71, :101-110); **attach error is handled** in Go (:105-108 → 500) and in Lean (`.error _ => .internal500`); gate off → next with unchanged ctx; non-Allow: err → 500 else 403 |
| `WithAuthorization` | `authorization.go:61-64` | Equivalent | gate read at :101 is the `gateOn` argument |
| `featuregate.Wiring` | (various) | Abstraction | |
| `featuregate.GateSwitches` | (various, P-80 a–h) | Abstraction | |
| `GateSwitches.of` | `config.go:1077`; `conditionsenforcer.go:74-82`; `webhook.go:152-157`; `reload.go:188-211`; `subjectaccessreview/rest.go:78-80`; `validation.go:759-761`; `zz_generated.validations.go:1114-1124`; `cel/compile.go:218` | Equivalent | (a) and (b) checked in full; (c), (d), (e), (f), (h) spot-checked at the cited lines and agree; (g) not opened (outside scope) |
| `GateOffConsequences` | properties.md P-80 | Equivalent | specification, not Go |
| `PluginName` | `conditionsenforcer.go:40` | Equivalent | |
| `conditionsEnforcer` | `:59-61` | Equivalent | `*bool` ↦ `Option Bool` |
| `InspectFeatureGates` | `:63-65` | Equivalent | |
| `ValidateInitialization` | `:67-72` | Equivalent | |
| `Handles` | `:74-76` | Equivalent | `featureEnabled != nil && *featureEnabled` ⇔ `== some true`; independent of operation |
| `AdmissionOutcome` | `Validate` return | Abstraction | plain `error` ↦ 500 is correct: `ErrorToAPIStatus` (`responsewriters/status.go:60-66`) maps a non-`APIStatus` error to 500 (409 only for `storage.IsConflict`, impossible for the two plain errors here); `NewInternalError` = 500; `ForbiddenStatusError` = `apierrors.NewForbidden` = 403 (`responsewriters/errors.go:45-57`) |
| `evaluateWithReturnGuard` | `:145-153` | Equivalent | `r ∉ PD(d)` ⇒ `(Deny, "failed closed", non-nil)`, original err discarded, as in Go |
| `ValidateWith` / `Validate` | `:78-142` | Equivalent | gate off/nil → nil; no tuple → plain error (500); `IsDeny ∨ IsNoOpinion ∨ ¬PD.Has(Allow)` → InternalError; `IsAllow` → nil (before `NewVersionedAttributes`, as in Go); map/union → `NewVersionedAttributes` error → plain error (500); guarded result `Allow` → nil; err → InternalError; else 403. Go `default` (:101-103) unreachable: the Lean inductive has exactly the five variants |
| (not modelled) 403-path `GetAuthorizerAttributes` error | `:131-134` | Abstraction | documented; would turn 403 into 500, never into admit. RequestInfo is always in the admission ctx anyway |
| `Config` | `config.go:1077` inputs | Abstraction | single `gateOn` for filter and enforcer (Go: `DefaultFeatureGate` vs initializer-supplied gate, the same object in kube-apiserver) |
| `Config.usesConditionsAwareFilter` | `config.go:1077` | Equivalent | three-way conjunction, same operands |
| `Filter` | `config.go:1077-1087` | Equivalent | `klog.Fatalf` branch unreachable, correctly dropped |
| `filterDecision` | `authorization.go:79` / `:161-167` | Equivalent | legacy path: `FromParts(Authorize)` is an equivalent view of the triple |
| `Config.enforcer` | admission init | Abstraction | |
| `Outcome` | filter → admission | Abstraction | assumes the enforcer runs for every request that leaves the filter (reads too, and ignores `Handles`, other admission plugins, storage). Harmless for safety (`Handles = gate`, and read requests reaching `Validate` in the model only admit when Go also admits at the filter); the gap is exactly what `P_68_enforcer_runs` covers |
| `OutcomeReloaded` | P-72 | Abstraction | evaluator `ev z` replaces the stored authorizer |

## Divergences

None. For every input I constructed (fresh / pre-populated context × gate × classifier × plugin
enabled × each CAD variant × error nil/non-nil × `NewVersionedAttributes` ok/error × evaluator
result in/out of `PD(d)`), Lean and Go produce the same `next`/403/500/admit and the same tuple.

## Theorem statement review

- `P_64_filter_next_iff`: matches; adds "fresh context" (`ctx = none`), which the catalogue leaves implicit (a pre-populated context gives 500 in Go too). The 403/500 half is `P_70_filter_codes`.
- `P_64_legacy_next_iff`: matches (legacy analogue, fresh context, any gate).
- `P_65_second_attach_fails`: matches.
- `P_65_conditionsAware_one_tuple`: matches (fresh ctx).
- `P_65_legacy_one_tuple`: matches; states the exact tuple `(AuthorizerFunc(Authorize), allow(reason, err))`.
- `P_65_legacy_tuple_is_allow`: matches the catalogue's "`AuthorizerFunc.EvaluateConditions` unreachable" via `IsAllow` (enforcer returns before evaluation).
- `P_65_one_tuple`: matches (gate on, fresh ctx, any installed filter). Catalogue's `authorizer ≠ nil` is implicit (nil not modelled).
- `P_66_validate_admitted`: matches (`allow d ∨ (r = A ∧ A ∈ PD(d))`, `r` unguarded evaluator result; also exposes `x = ok`).
- `P_66_missing_tuple`: matches.
- `P_66_handles_constant`: matches (trivially `rfl`).
- `P_66_return_guard`: matches (`r ∈ PD(d) ∨ (Deny ∧ err)`, Deny even if `D ∉ PD`).
- `P_69_unclassified_unconditional`: matches the first clause; the webhook fold-down clause (P-49) is out of this file, correctly.
- `P_70_filter_codes`, `P_70_legacy_codes`: match.
- `P_70_enforcer_codes`: matches; hypotheses `¬uncond d ∧ A ∈ PD(d)` only select the evaluation path, they do not weaken the claim.
- `P_72_evaluator_may_differ` (negative): the negation is of "outcome is independent of which authorizer evaluates", i.e. of `∀ ev, ValidateWith ev = Validate`. That is a correct but model-level statement; the HEAD fact that makes it relevant (the stored authorizer is the reload wrapper, so on HEAD `ev ≠ id` is possible, `reload.go:93-99`) lives only in the doc comment. Acceptable given the catalogue's "Lean: later (model reload as non-deterministic swap)". Nit: the counterexample `conditionsMap {denyConditions := [default], allowConditions := [default]}` is built directly, not via `mkMap`, so it may not satisfy `WFMap` (duplicate ids); the counterexample would equally work with a well-formed map, so not a soundness issue.
- `P_72_clamp_survives_reload`, `P_72_guard_in_PD`: match the catalogue's surviving guarantee.
- `P_80_gate_off` (featuregate): matches the catalogue's eight items; it is true by definition of `GateSwitches.of`, so its evidential value is only the per-field Go citations (checked above for a–f, h).
- `P_80a_gate_off_legacy`: matches (a), and additionally proves no tuple is attached.
- `P_80b_gate_off_enforcer`: matches (b).
- `P_82_no_enforcer_legacy`: matches (the "warning logged" part is logging, omitted).
- `end_to_end_safety`: sound statement about `Outcome`. Implicit assumptions not in its doc comment: authorizer non-nil (Go `a == nil` admits with no decision at all) and the enforcer being reached (named). Suggest adding "authorizer configured (non-nil)" to the doc comment.
- `served_safety_classified`: correct given the axiom.

## Axioms

`P_68_enforcer_runs : ∀ cfg ctx a x cl, usesConditionsAwareFilter → classifier = some cl → cl a → ServedOutcome cfg ctx a x = Outcome cfg ctx a x`.

Consistency: `ServedOutcome` is an `opaque` constant without body, the kernel never unfolds it,
and no other file mentions it (grep over `lean/`). Interpreting `ServedOutcome := Outcome` satisfies
the axiom, so the theory stays consistent. Its falsity on HEAD is a statement about the
*intended* meaning of `ServedOutcome`, which Lean cannot express; it cannot be used to derive
`False`. Doc comment correctly marks it as false on HEAD and lists both catalogued
counterexamples.

Concerns:
1. **Stronger than P-68.** P-68 says the enforcer runs before any state change; the axiom says the
   real server's *entire* outcome equals the model's. That is false for reasons unrelated to P-68
   (another admission plugin or storage rejecting a request `Outcome` admits), so it would stay
   false even after the aggregator and corrupt-delete bypasses are fixed. Only the admit direction
   is used. Proposed replacement:
   ```lean
   axiom P_68_enforcer_runs :
     ∀ (cfg : Config) (ctx : Context) (a : Attributes) (x : Except Err ConditionsData)
       (cl : ConditionalAuthorizationRequestClassifier),
       cfg.usesConditionsAwareFilter = true → cfg.classifier = some cl → cl a = true →
       ServedOutcome cfg ctx a x = .admitted → Outcome cfg ctx a x = .admitted
   ```
   `served_safety_classified` then becomes `end_to_end_safety cfg ctx a x (P_68_enforcer_runs … h)`.
2. **Fragility.** If someone later gives `ServedOutcome` a definition (e.g. models the aggregator
   proxy), the global axiom becomes inconsistent. Safer: drop the `axiom` and take it as a
   hypothesis of `served_safety_classified` (`(hP68 : ∀ …, …)`), which keeps every dependent
   theorem explicit and is unconditionally safe.

## Verdict

The filter, context slot, enforcer and server wiring are faithful to the Go code branch by branch:
no divergence in decisions, attached tuples, error nil-ness or the 403/500 mapping (the plain
`error` ↦ 500 choice is confirmed by `ErrorToAPIStatus`). The legacy filter's gate-on attach and its
error handling are modelled exactly. The only unmodelled Go behaviours are the `a == nil`
pass-through (worth one line in `end_to_end_safety`'s doc) and attribute-extraction failures that
can only produce 500. Theorem statements match the catalogue; `P-72` is a model-level negation, as
the catalogue anticipated. The single axiom is consistent but stronger than P-68 and should be
weakened to the admit direction, preferably as a hypothesis. For the properties it proves, the model
is trustworthy.
