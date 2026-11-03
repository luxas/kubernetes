# Go ↔ Lean equivalence review (merged)

Seven independent reviewers, one per component, compared every definition in `lean/` with its Go source branch by branch, then reviewed each theorem statement against `properties.md`. Method and report format: the brief in each file's header. Per-component reports:

## authorizer-core (`lean-equivalence/authorizer-core.md`)

The authorizer-core model is a faithful, branch-for-branch model of `interfaces.go`, `conditionsmap.go` and `conditions.go`. It covers:
- the check order and fail-closed effect of `ConditionsAwareDecisionConditionsMap`;
- the check order of `validateConditions`, with byte-length semantics exact on valid UTF-8;
- the nil-ness of the errors returned by both splitters;
- the `DecisionSet` operations.

## authorizer-eval (`lean-equivalence/authorizer-eval.md`)

`conditionsunion.lean` and `evaluate.lean` follow the Go source branch by branch. The details the brief asked about all match Go:
- `Add`'s check order, error accumulation, unconditional append, and the flag computed from the incoming child.
- `ToDecision`'s errs-first test, the `Len==1` fold through `theOnly`, depth-first leaf collection, and recomputing the dropped caches (proved equal for reachable builders).
- The map evaluator's `len != 0` guards, first-true short circuit, errored-before-unevaluated precedence, and `mkMap` called on the original N/A lists.
- The sticky `collectTail` in `PartiallyEvaluateConditionsAwareDecision`.

## cel (`lean-equivalence/cel.md`)

The model is faithful to the Go code for what P-74, P-77 (wiring), P-78 and P-79 prove. I found no
divergence in decision, error-nil-ness or evaluator structure, and the cost/error orderings agree.
That holds for the PerCallLimit abort, for a single-step overshoot of the per-condition budget,
which I showed is reachable despite the wave-1 claim, and for cost equal to the budget. Two caveats
limit how far it can be trusted.

## encoding (`lean-equivalence/encoding.md`)

The v1 types and both codec functions are a faithful model of `encoding.go`. Every branch was checked, no divergence was found, and the abstractions cannot be observed by the decoder:
- nil vs empty slices;
- `EvaluateFunc` dropped;
- the unreachable encoder `default`;
- the redundant `unknown "<known>"` tags.

## pipeline (`lean-equivalence/pipeline.md`)

The filter, context slot, enforcer and server wiring are faithful to the Go code branch by branch:
no divergence in decisions, attached tuples, error nil-ness or the 403/500 mapping (the plain
`error` ↦ 500 choice is confirmed by `ErrorToAPIStatus`). The legacy filter's gate-on attach and its
error handling are modelled exactly. The only unmodelled Go behaviours are the `a == nil`
pass-through (worth one line in `end_to_end_safety`'s doc) and attribute-extraction failures that
can only produce 500. Theorem statements match the catalogue; `P-72` is a model-level negation, as
the catalogue anticipated. The single axiom is consistent but stronger than P-68 and should be
weakened to the admit direction, preferably as a hypothesis. For the properties it proves, the model
is trustworthy.

## union (`lean-equivalence/union.md`)

`union/union.lean` is a faithful model of `union.go`. Every function matches branch by branch on
decision, PD/FD, whether the error is nil, early returns, and builder side effects (`Add` before
the cua early return). The differences are covered abstractions: the association-list map with
first-wins lookup is equivalent under `New`'s duplicate rejection, and error text is
approximate. The only behaviours not modelled (nil authorizers panicking, `RulesFor`) carry no
catalogued property. The theorem statements match or are stronger than P-41, P-44, P-45, P-46
and P-47, with no axioms and no `sorry`. Two weaknesses:
- P-42 is parametric in a name the opaque DNS-1123 predicate rejects, so on its own it does not
  refute the desirable property.
- P-44's "every error path returns FD of u or a child" clause is not stated.

## webhook (`lean-equivalence/webhook.md`)

The webhook model is trustworthy for the properties it proves. Branch order and outcomes
match Go in all six modelled functions:

## Result

**No divergence found in any component.** Hardening applied in `lean/` after the reviews: `ConditionEvaluationResult` zero value, `composeOracle`/`compose_decoded` precondition for `tryEvaluateUsingBuiltins`, `P_68_enforcer_runs` as hypothesis rather than axiom, corrected CEL cost note. Remaining proposals are coverage items listed in `lean/STATUS.md`.
