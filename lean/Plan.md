# Lean 4 Formalization of the Kubernetes Authorization Stack

## Overview

This formalization models the Kubernetes authorization decision pipeline in Lean 4,
both before and after KEP-5681 (Conditional Authorization). The goal is to:

1. Precisely specify the authorization semantics as pure functions over algebraic data types
2. State and prove key safety properties (e.g., deny-precedence, backward compatibility)
3. Show that the pre-KEP model is a refinement of the post-KEP model (when no conditions are used, the two models agree)

## File Structure

```
lean/
  Plan.md                 -- this file
  AuthzBefore.lean        -- pre-KEP authorization model
  AuthzAfter.lean         -- post-KEP authorization model with conditions
  Properties.lean         -- shared properties, safety invariants, and theorems
  Refinement.lean         -- refinement relation: before ⊆ after
```

## What We Formalize

### AuthzBefore.lean — Pre-KEP Model

Models the authorization stack as it existed before KEP-5681 (and after Phase 0):

- **Decision**: An inductive type `{allow, deny, noOpinion}` carrying a reason string.
- **Authorizer**: A function from `Attributes → Decision × Option Error`.
- **Union authorizer (chain)**: Iterates authorizers; first `allow` or `deny` short-circuits. If all return `noOpinion`, the chain returns `noOpinion`. Errors from `noOpinion` authorizers are aggregated.
- **WithAuthorization filter**: If `allow`, request proceeds. Otherwise, 403 Forbidden.

Key properties to state:
- The chain is a fold with short-circuit semantics.
- A single `allow` or `deny` anywhere in the chain determines the outcome if all prior authorizers returned `noOpinion`.
- The chain is monotonic in the sense that removing an authorizer that returns `noOpinion` does not change the result.

### AuthzAfter.lean — Post-KEP Model

Extends the model with conditional authorization:

- **ConditionEffect**: `{deny, noOpinion, allow}` — how a condition evaluating to `true` affects the decision.
- **Condition**: A triple `(id, effect, eval)` where `eval : ConditionData → Bool ⊕ Error`.
- **ConditionSet**: A list of conditions, all of the same type, from a single authorizer.
- **Decision**: Extended to `{allow, deny, noOpinion, conditional(conditionSets, remainingChain)}`.
- **ConditionSet evaluation algorithm** (3-step):
  1. If any `effect=deny` condition is `true` → `deny`. If error → `deny` (fail closed).
  2. If any `effect=noOpinion` condition is `true` → `noOpinion`. If error → `noOpinion` (fail closed).
  3. If any `effect=allow` condition is `true` → `allow`. Errors ignored. If none true → `noOpinion`.
- **Chain evaluation with conditions** (lazy):
  - On `conditional` with at least one `effect=allow` condition (conditional allow): short-circuit, save remaining chain.
  - On `conditional` without `effect=allow` (conditional deny): continue to next authorizer.
  - On concrete `allow`/`deny`: short-circuit as before.
  - On `noOpinion`: continue.
- **Condition enforcement** (at admission time):
  - Evaluate each condition set in order.
  - If concrete `allow` or `deny`, short-circuit.
  - If `noOpinion`, continue to next set or lazily evaluate remaining chain.

### Properties.lean — Safety Properties and Theorems

1. **Deny precedence within a ConditionSet**: If any deny-effect condition is true, the set evaluates to deny regardless of other conditions.
2. **Effect ordering**: deny > noOpinion > allow within a ConditionSet.
3. **Backward compatibility**: When `conditionsMode = none`, the post-KEP chain behaves identically to the pre-KEP chain.
4. **Fail-closed safety**: Errors in deny/noOpinion conditions never produce an allow.
5. **Chain short-circuit correctness**: A chain `[noOpinion, ..., noOpinion, allow]` returns `allow`.
6. **Conditional allow soundness**: A conditional allow can only become `allow` or `noOpinion` after enforcement, never `deny` (unless a deny-effect condition fires).

### Refinement.lean — Refinement Proof

Proves that the pre-KEP model is embedded in the post-KEP model:

- Define an injection from pre-KEP `Decision` to post-KEP `Decision` (allow/deny/noOpinion map directly).
- Define an injection from pre-KEP `Authorizer` to post-KEP `Authorizer` (one that never returns conditional).
- Prove: for a chain of non-conditional authorizers, `chainAfter(inject(authzs)) = inject(chainBefore(authzs))`.
- Prove: when `conditionsMode = none` in every attribute, the `WithAuthorization` filter in the post-KEP model agrees with the pre-KEP model.

## Modeling Decisions

1. **Errors**: Modeled as `Option Error` alongside the decision, not mixed into the decision type. This matches the Go interface `(Decision, error)`.
2. **Lazy evaluation**: Modeled by carrying the remaining authorizer chain inside the `conditional` constructor. Enforcement unfolds this lazily.
3. **ConditionData**: Left abstract (an opaque type). Conditions are modeled as `ConditionData → Except Error Bool`.
4. **Reason strings**: Included in the model as `String` fields but not central to the proofs.
5. **Attributes**: Modeled as a structure with `conditionsMode` field plus opaque request metadata.

## Non-Goals

- We do not formalize the CEL expression language itself.
- We do not formalize the webhook transport or serialization.
- We do not formalize the Kubernetes API machinery (admission plugins, HTTP filters) beyond the authorization decision logic.
- We do not formalize caching behavior.
