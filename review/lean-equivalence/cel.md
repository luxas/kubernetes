# cel

Scope: `lean/cel/authorization_conditions.lean` (all definitions) and the theorem statements of
`lean/cel/authorization_conditions_properties.lean`, against
`staging/src/k8s.io/apiserver/pkg/admission/plugin/cel/authorization_conditions.go` (PR #143024,
read in full, 188 lines). Helpers I checked against Go: `compile.go:165-223` (`CompileCELExpression`,
`ReturnTypes` handling), `compile.go:225-291` (env per `OptionalVariableDeclarations`),
`activation.go:52-212` (`newActivation`, `Evaluate`), `condition.go:162` (`CreateNamespaceObject`),
`webhook/predicates/namespace/matcher.go:47-54`, `admission/plugin/authorizer/caching_authorizer.go:48-157`,
`pkg/cel/environment/base.go:88-96`, `apis/cel/config.go:20-35`, `plugin/pkg/authorizer/webhook/webhook.go:949-973`,
`pkg/kubeapiserver/authorizer/reload.go:188-211`, and cel-go's `common/cost/tracker.go:190-258`,
`cel/program.go:236-246,473-512`, `ext/sets.go:227-255` (vendored).

Build: `lake build cel.authorization_conditions cel.authorization_conditions_properties` succeeds.
No `sorry`/`admit`/`native_decide`. Two `axiom`s (`oAuthor`, `P_76_O3_builtin_agrees_with_author`).

| Lean def | Go file:line | verdict | note |
|---|---|---|---|
| `Attributes` | `authorizer/interfaces.go` | Abstraction | Opaque (README 3/9). |
| `UnconditionalAuthorizer` | `interfaces.go:86-88` | Abstraction | Pure function, no `ctx`. Result type is the 3-valued `Decision`, same as Go: there is no conditional variant. |
| `Authorizer` | `interfaces.go:84-125` | Abstraction | Only the two methods the cel path can reach. A Go typed-nil interface (non-nil interface, nil pointer) cannot be expressed; in Go it would set `HasAuthorizer=true` and then panic on first use. Not reachable from the webhook caller. |
| `Authorizer.toUnconditional` | implicit interface narrowing at `authorization_conditions.go:103` | Equivalent | `NewCachingAuthorizer` takes `UnconditionalAuthorizer`, so only `Authorize` is visible to it. Go matches this: `library.NewAuthorizerVal` / `NewResourceAuthorizerVal` (`activation.go:80-83`) get only that interface. |
| `NewCachingAuthorizer` | `caching_authorizer.go:48-53` (+ `Authorize` `:84-157`) | Abstraction | Identity. Under O1 (pure `Authorize`) caching is transparent, with two Go-only differences: (a) a JSON-encode failure of the cache key returns `(NoOpinion, "", err)` without calling the inner authorizer (`:139-141`); (b) the key drops the `GetLabelSelector` parse error (`:107`), so two checks that differ only by an invalid label selector share one cache entry. Neither changes a catalogued property: both only affect what a CEL `authorizer.check()` returns, and that value goes into the oracle. The cache lifetime (once per `EvaluatorForData`) is not modelled (see P-77). |
| `Namespace` | `*v1.Namespace` via `CreateNamespaceObject` (`condition.go:162-180`) | Gap | Carries only `name`. CEL reads `namespaceObject.metadata.labels`, `.spec`, `.status` (`CreateNamespaceObject` copies them). In the model, two lookups that return same-named namespaces with different labels give the oracle the same input, so they must give the same CEL outcome. No current theorem depends on this. It does weaken P-76's stated motivation, though: the model cannot express an informer snapshot that differs from what the webhook sees. Fix: add an opaque `payload : NamespacePayload` field. |
| `EvalData` | `ConditionsData` as `*admission.VersionedAttributes` (`:84`) | Gap | Holds only the five branch facts, with no object/oldObject/request/userInfo payload. `Activation.data` is the oracle's only view of the request, so for a fixed `Builder`, two requests with the same branch facts must give the same CEL outcome. In Go the builder is fixed across requests and outcomes depend on `object`. Theorems quantify over an arbitrary `Evaluator` (whose `celEval` is arbitrary), so none of P-74…P-79 is affected. A future theorem of the form "same builder, different objects" could not be stated. README §3 says `ConditionsData` is opaque, but here it is a closed record. Fix: add `payload : ConditionsData` (the opaque type from `authorizer/interfaces.lean`). |
| `OptionalVariableDeclarations` | `compile.go` / `:114` | Equivalent | Go also has `HasPatchTypes`, which is always `false` on this path. Omitting it is harmless. |
| `Activation` | `activation.go:87-100` (`evaluationActivation`) | Abstraction | Inherits the `EvalData`/`Namespace` gaps. `variables` (composition) is omitted. That is correct: `ctx.(CompositionContext)` is nil for an authorization request context, and the env from `createEnvForOpts` declares no `variables`. |
| `CELOutcome` | `compile.go:165-223` + `activation.go:141-212` | Abstraction | {compile error, runtime error, value Bool} is enough for P-74/P-75/P-78 (see "Oracle adequacy" below). `value : Bool` is justified: `ReturnTypes = [BoolType]` (`:186-188`), `IsExactType(BoolType)` at `compile.go:191` (the `cel.AnyType.IsExactType(returnType)` disjunct is inert because `returnType` is Bool), cel-go turns a `types.Err` result into `err` (`program.go` after `:512`), and no unknowns are configured. The model does not include unreachable Go branches: placeholder `ExpressionAccessor == nil` (`activation.go:143`; `validationCondition` is never nil), `Program == nil` (`:156`), `evalDetails == nil` / `ActualCost() == nil` (`:179-191`; unreachable because base env sets `OptTrackCost` (`base.go:90`) and `captureCostTracker` always fills `det` when a tracker exists, `program.go:236-246`). README §8. |
| `Builder` | `:73-77` | Abstraction | `runtimeCELCostBudget : Nat` vs Go `int64`. A negative Go budget would make every compiled expression an `E` (`activation.go:193`: any cost > negative). Production passes the constant `10,000,000` (`reload.go:207`). `compiler`/`nsmatcher` are folded into `celEval` / `EvalData.namespaceLookup`. |
| `NewAuthorizationConditionsEvaluatorBuilder` | `:53-69` | Equivalent | Nil informer factory checked first, then nil client. Values: `.error` ↔ `(nil, err)`. Doc nit: says `:53-71`; `:71` is the `var _` assertion. Not modelled: `informerFactory.Core().V1().Namespaces().Lister()` (`:64`) registers a namespace informer as a side effect. If the factory is already started, the new informer is not started, and `GetNamespace` falls back to a live GET (`matcher.go:49-52`). That affects latency, not the result. |
| `reloadBuiltinBuilder` | `reload.go:204-211` | Equivalent | Go returns an untyped `nil` interface on error, so `w.builtinConditionsEvaluatorBuilder == nil` (`webhook.go:952`) holds. |
| `getNamespace` | `:119-140` | Equivalent | Same order: the core/v1 `Namespace` kind clears the name, an empty name gives nil, otherwise the lookup error propagates. `namespaceLookup = none` ↔ `err ≠ nil`. Go cannot return `(nil, nil)` here (lister `NotFound` → client GET, which returns an object or an error). The I/O (lister vs live GET) is folded into one snapshot value. |
| `Evaluator` | `:142-146` | Abstraction | A public structure, so theorems over `Evaluator` include combinations that `EvaluatorForData` never builds (e.g. `HasParams = true`, `HasAuthorizer ≠ activation.authorizer.isSome`). This only makes the positive theorems stronger. |
| `EvaluatorForData` | `:79-116` | Equivalent | Order matches Go: nil data → not `*VersionedAttributes` → namespace → activation. `authz = map (NewCaching ∘ toUnconditional)` when non-nil, matching `:101-104`. `HasAuthorizer = isSome` matches `:114`. `CreateAdmissionRequest` (`:89`) cannot fail and is not modelled. Go-only: a typed-nil `*VersionedAttributes` passes `:80` and `:84` and then panics at `:89`. Not expressible in Lean, and not produced by the conditions enforcer. |
| `Evaluator.celEval` | `:163-168` | Equivalent | Compiles with the evaluator's declarations (`:163`), the same env choice as Go (`c.varEnvs[options]`, `compile.go:179`). |
| `Evaluator.celCost` | `activation.go:185` | Abstraction | Does not take `optionalVarsDecls`. That is harmless for evaluators built by `EvaluatorForData`, because the declarations are a function of `activation.authorizer`. |
| `Evaluator.EvaluateCondition` | `:148-178` | Equivalent | Branch by branch. The nil condition (`:150-152`) cannot be expressed (documented gap). Type ≠ CEL → U (`:153-155`). `String.length = 0` ⟺ Go `len = 0` → U (`:158-161`). Compile error → `EvalResult.Error`, nil `err` → E (`activation.go:148-155`, `:173-175`); Lean `.compileError` → `.error`, and no cost is charged, same as Go. A runtime error is E whether the cost is above the budget (Go `err`, `activation.go:193-199` → `:169-171`) or not (`activation.go:203-207` → `:173-175`). Go checks cost BEFORE `err`, but both are E, so error-nil-ness and decision agree. Value with cost > budget → E (`:193`). Cost = budget is accepted (`>`) in both. Otherwise `Boolean(b)` ↔ `evalResult.EvalResult == celtypes.True` (`:177`): the interface comparison of `types.Bool` with `types.True` is exact. |
| `Evaluator.conditionCost` | `activation.go:148-155,185` | Abstraction | Model-only accounting, consistent with Go: zero for U and compile errors, actual cost otherwise. Not charged: compile cost. Every condition is recompiled on every call (`:163`, no cache), and compilation is unbounded by the runtime budget except through the parser's 100k code-point limit (`base.go:70-74`). Also, unlike VAP, no static cost estimate is checked. |
| `mapCost` | — (model-only) | Abstraction | The sum over `m.all`. The doc calls it "an upper bound on what one `PartiallyEvaluate…` can spend", but no lemma ties it to `partiallyEvaluateConditionsMapInternal`. The bound holds in Go because each condition gets the evaluator at most once per map, but in Lean it is unproved. |
| `tryEvaluateUsingBuiltins` | `webhook.go:951-973` | Equivalent | `none` builder → unchanged. `EvaluatorForData` error → unchanged (`:958-961`). Otherwise peval with E ↦ U (`:968-970`). This is a second copy of the webhook model (`webhook/webhook.lean:157`, which uses an `Option` oracle), and no theorem shows the two agree (`w.builtin = (evaluatorFor? b data authz).map EvaluateCondition`). Gap in the cross-module link, not in this def. |
| `evaluatorFor?` | `webhook.go:952-961` | Equivalent | |

Counts (23 defs): Equivalent 10, Divergence 0, Abstraction 11, Gap 2.

## Divergences

None. For every input the model can express, Lean and Go agree on the `ConditionEvaluationResult`
tag (T/F/E/U), on error-nil-ness of `NewAuthorizationConditionsEvaluatorBuilder` and
`EvaluatorForData`, and on the evaluator's structure (authorizer variable and declarations).

Inputs Go accepts that Lean cannot express (none is reachable from the production caller):
nil `Condition`, which Go maps to U (documented); negative `runtimeCELCostBudget`; typed-nil
`Authorizer` or `*VersionedAttributes` (Go panics).

## Oracle adequacy (P-74, P-75, P-78)

- P-74 needs four outcomes: U before CEL, E for compile errors, E for runtime errors including
  cost exceeded, and T/F for values. `CELOutcome` × `celCost` gives each of them, and gives
  `cost ≤ budget` vs `> budget` for both `runtimeError` and `value`. That covers Go's
  cost-before-err ordering. Nothing in the result depends on the compile vs runtime distinction
  (both are E). That distinction is still observable in Go, as different `Detail` text and
  because compile errors charge no cost, so keeping it is correct, not over-fitting.
- P-75: the oracle cannot return a non-bool success. The Go claim behind this is verified above
  (`CELOutcome` row).
- P-78: `celCost` gives the per-condition cost. The model has no `PerCallLimit`, so `value b`
  with a cost in (1M, 10M] is allowed even though Go cannot produce it (cel-go would abort at
  1M and report a runtime error). This over-approximation only matters for negative theorems,
  and the P-78 counterexample is realisable (see below). The model cannot state the realistic
  production bound per map (≈ 128 × (PerCallLimit + one step's overshoot)), because
  `PerCallLimit` is not modelled.
- Over-observation: the oracle cannot see anything Go hides. Its inputs (activation, declared
  variables, expression) are a subset of what Go's `Program.ContextEval` sees. The problem is
  the reverse (Gaps above): it sees too little of the request.

## Wave-1 claim: "the `runtimeCELCostBudget` check cannot trigger in production because PerCallLimit (1,000,000) aborts first"

Incorrect. The constants are correct (`PerCallLimit = 1000000`, `RuntimeCELCostBudget = 10000000`,
`config.go:22,26`; `cel.CostLimit(celconfig.PerCallLimit)` at `base.go:91`, with `OptTrackCost` at
`:90`). The failure is that cel-go charges a call's cost after the call returns and only then
checks the limit (`tracker.go:221-224` `recordCallCost` → `checkLimit` `:252-258`). A single call
whose cost exceeds the remaining ~9M therefore pushes the actual cost past both limits in one
step. The panic is recovered with `det` still populated (`program.go:494-507` via
`captureCostTracker`), and `activation.Evaluate` tests `*rtCost > remainingBudget` (`:193`)
before `err` (`:203`), so the budget branch fires and returns a Go `err`.

Example: `sets.intersects(l1, l2)` costs `1 + |l1|·|l2|` (`ext/sets.go:246-255`), so two lists of
~3,200 elements are enough. I confirmed this with a throwaway in-package probe test (since deleted)
using the production budget:

- `sets.intersects(object.metadata.finalizers, object.metadata.finalizers)` with 900 finalizers
  gives T, remaining 9,189,993.
- With 3,500 finalizers (cost 12,250,001) it gives a Go `err` "validation failed due to running out of
  cost budget", `EvalResult.Error = nil`, remaining −1, and `EvaluateCondition` = Error.

It is also reachable whenever the budget argument is below `PerCallLimit`, which the doc
comment at `:51` allows for tests.

Consequence for the model: none. Both paths give `ConditionEvaluationResultError`, and the
webhook maps it to U. Lean's `EvaluateCondition` already handles `runtimeError` with
`cost > budget`. The module doc should not say the PerCallLimit abort is the only way out.
Separate observation for P-78: because cost is charged after the call, neither limit bounds
the CPU spent inside that one over-budget call.

## Theorem statement review

- `P_74_non_cel_type_unevaluatable`: matches.
- `P_74_empty_expression_unevaluatable`: matches.
- `P_74_compile_error`: matches.
- `P_74_runtime_error`: matches (holds for any cost).
- `P_74_cost_exceeded`: matches the "(incl. cost exceeded)" clause for value outcomes. The runtime-error-and-over-budget case is covered by `P_74_runtime_error`.
- `P_74_value`: matches. The `cost ≤ budget` premise is the catalogue's "else".
- `P_74_true_iff`: stronger (full characterisation). Like all P-74 theorems, it is weaker than the catalogue by the nil-condition case, which cannot be expressed and is documented.
- `P_75_value_is_bool`: about something else. It is true by construction of `CELOutcome.value : Bool`. The catalogue's actual claim (the compiler enforces `bool`) is an assumption built into the oracle type, and I verified it in Go (`compile.go:189-205`).
- `P_77_authorizer_answer_unconditional`: matches, but it holds by the type alone. It is faithful because Go's `UnconditionalAuthorizer.Authorize` also returns a plain `Decision`.
- `P_77_authorizer_variable`: weaker. "Declared iff non-nil" and "wraps `Authorize` of the context authorizer" match. "Cached for one `EvaluatorForData` call" is not stated and cannot be, because `NewCachingAuthorizer` is the identity, so the word "caching" in the statement has no content.
- `P_77_conditions_aware_authorize_unused`: stronger than the catalogue (extra). True of Go.
- `P_78_cost_per_condition_witness`: matches for one map. The catalogue also multiplies by union width (P-40) and retries (P-67); the narrower statement is enough for a negative claim. `costlyMap` is a raw structure, not built by the constructor; it could be, given 128 valid IDs (opaque predicate). The witness for a general `budget` includes unrealisable instances (a value with cost > PerCallLimit), but each instance is realisable for `budget ≤ ~1M`.
- `P_78_not_per_request_bound`: correct negation of "∀ e m, |m| ≤ 128 → mapCost ≤ budget". The counterexample (budget 1, 128 conditions of cost 1) is realisable through the test-only budget parameter, e.g. `has(object.x)` costs 1 with `PresenceTestHasCost(false)`. The production counterexample (128 × ~1M > 10M) is also realisable. Caveat: `mapCost` is model accounting (see the `mapCost` row). The code fact behind P-78, that the remaining budget is discarded per condition (`:168`, `evalResult, _, err`), is verified.
- `P_79_builder_requires_informer_and_client`: matches (stronger: iff).
- `P_79_evaluator_none_iff`: matches; exactly the four causes.
- `P_79_no_evaluator_skips_partial_evaluation`: matches.
- `P_79_builder_failure_skips_partial_evaluation`: matches.

## Axioms

- `axiom oAuthor : Evaluator → Condition → ConditionEvaluationResult`: consistent, because the target type is inhabited (`Inhabited` derived). Its index is wrong, though. The authoring authorizer's verdict should depend on the request data and the condition only. Indexing it by `Evaluator` (which includes the API server's own CEL oracle and budget) lets it vary with the API server's CEL implementation.
- `axiom P_76_O3_builtin_agrees_with_author`: consistent. `oAuthor := Evaluator.EvaluateCondition` satisfies both axioms, as the doc comment says, and `oAuthor` is a fresh constant with no other constraints. That same fact makes the pair vacuous. Together the axioms are equivalent to `∃ f, ∀ e c, EC e c ∈ {T,F} → EC e c = f e c`, which is provable, so they assert nothing about Go. They also contradict the catalogue's "status: unknown". `oAuthor` is used nowhere else (grep across `lean/`), and in particular it is not connected to the webhook's ACR oracle `o` used by P-26 (`webhook/webhook_properties.lean:246`). So nothing in the build depends on O3, and the claim "Confluence (P-27) and the FD-drop safety (P-26) rest on it" has no counterpart in Lean.
  - Proposed fix (matches catalogue §4.2, "hypothesis, not axiom"): replace both axioms with a definition and use it as a premise wherever P-26/P-27 are composed with the builtin path:
    ```lean
    /-- Axiom O3 as a hypothesis: on its boolean outputs the builtin oracle agrees with the
    authoring authorizer's oracle `o` for the same request data. -/
    def O3 (builtin : Condition → ConditionEvaluationResult) (o : Condition → ConditionEvaluationResult) : Prop :=
      ∀ c, (builtin c = .true_ ∨ builtin c = .false_) → builtin c = o c
    -- use: (h : O3 ev.EvaluateCondition o) where `o` is the same oracle the ACR/webhook theorems use
    ```

## Doc nits

- `NewAuthorizationConditionsEvaluatorBuilder` doc: `:53-71` → `:53-69`.
- Module doc: "the per-call abort … surfaces as `CELOutcome.runtimeError`". That is true when the
  abort happens below the budget. When a single step overshoots the budget, Go reports the budget
  `err` instead (see the wave-1 claim section). The model is still correct; only the wording is
  incomplete.
- `NewCachingAuthorizer` doc: transparency also needs the two key-construction caveats above.
- `properties.md` line references: §1.12 `:76-120` → `:79-116`, `:100-104` → `:101-104`,
  `:149-161` → `:150-161`; P-75 `:183-188` → `:186-188`; P-77 `:98-118` → `:99-115`.
  P-74/75/77/78/79 still say "Lean: no", but they are now covered.

## Verdict

The model is faithful to the Go code for what P-74, P-77 (wiring), P-78 and P-79 prove. I found no
divergence in decision, error-nil-ness or evaluator structure, and the cost/error orderings agree.
That holds for the PerCallLimit abort, for a single-step overshoot of the per-condition budget,
which I showed is reachable despite the wave-1 claim, and for cost equal to the budget. Two caveats
limit how far it can be trusted.

1. P-75, P-77 (shape) and P-76 are true by construction or vacuous. The P-76 axioms are consistent
   but say nothing, and they are not connected to the webhook oracle, so no Lean result actually
   depends on O3. They should become a named hypothesis.
2. `EvalData` and `Namespace` drop the request and namespace payload. CEL outcomes are therefore
   modelled per `Evaluator`, not per (builder, request), so any future theorem that relates
   different requests under one builder, or informer-snapshot skew, cannot be stated until an
   opaque payload is added.
