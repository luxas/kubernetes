# Plan: Lean 4 Formal Model of Kubernetes Conditional Authorization

## Context

KEP-5681 introduces conditional authorization to Kubernetes — a two-phase mechanism where authorizers can return conditions (residuals) during the authorization phase that are later evaluated against request/stored objects during the admission phase. The implementation lives on the `lean-test` branch.

We want to prove that this two-phase split is semantically equivalent to a simpler, single-phase model where each authorizer has access to all data upfront. This is the fundamental correctness property of conditional authorization.

**Simplifications for v1 (relaxed later):**
- No `Union` decision variant — only `Allow | Deny | NoOpinion | Conditional`
- A temporary axiom: conditional decisions never evaluate to `NoOpinion` (needed because without `Union`, the chain can't resume after a conditional evaluates to `NoOpinion`)

## File to create

`plan/ConditionalAuthz.lean` — a single self-contained Lean 4 file (no Mathlib dependency).

## Architecture of the Lean Model

### Part 1: Core Decision Types

Mirror the implementation's type hierarchy:

```
UnconditionalDecision  = Allow | Deny | NoOpinion     -- authorizer.Decision (int enum)
Decision CM            = Allow | Deny | NoOpinion      -- authorizer.ConditionsAwareDecision
                       | Conditional (cm : CM)           (without Union for now)
```

Also define `ConditionEffect = Allow | Deny | NoOpinion` and a concrete `ConditionsMap` structure with conditions sorted by effect (mirroring `ConditionsMap.denyConditions/noOpinionConditions/allowConditions`). The concrete `ConditionsMap` is defined for documentation/reference but the main theorem is abstract over `CM`.

Define `canBecomeAllowed` on `Decision CM` (returns true for `Allow` and `Conditional`, false otherwise — mirrors `ConditionsAwareDecision.CanBecomeAllowed()` without Union).

### Part 2: Authorizer Abstraction

An `Authorizer` structure parameterized over abstract types `Attrs`, `Data`, `CM`:

```lean
structure Authorizer (Attrs Data CM : Type) where
  fullAuthorize      : Attrs → Data → UnconditionalDecision   -- ideal, all data at once
  authorize          : Attrs → Decision CM                     -- phase 1
  evaluateConditions : CM → Data → UnconditionalDecision       -- phase 2
  -- Four correctness axioms linking the two phases to the ideal
  ax_allow       : authorize = Allow       → fullAuthorize = Allow
  ax_deny        : authorize = Deny        → fullAuthorize = Deny
  ax_noOpinion   : authorize = NoOpinion   → fullAuthorize = NoOpinion
  ax_conditional : authorize = Conditional cm → fullAuthorize = evaluateConditions cm data
  -- Temporary axiom (relaxed when Union is added)
  ax_no_noop     : authorize = Conditional cm → evaluateConditions cm data ≠ NoOpinion
```

The four separate axioms (instead of one match-based axiom) are used because they're much cleaner for `rw`-based proofs in Lean 4.

### Part 3: Ideal Chain Evaluation

```lean
def idealChain (chain : List Authorizer) (attrs) (data) : UnconditionalDecision :=
  match chain with
  | []        => NoOpinion
  | a :: rest => match a.fullAuthorize attrs data with
                 | Allow     => Allow
                 | Deny      => Deny
                 | NoOpinion => idealChain rest attrs data
```

This is the "gold standard" — what the authorizer chain would compute if every authorizer had access to all data upfront. Short-circuits on Allow/Deny, continues on NoOpinion. Directly mirrors `union.Authorize()`.

### Part 4: Implementation Model — Three Components

Mirror the three implementation components:

#### 4a. Authorization Phase (union authorizer's `ConditionsAwareAuthorize`)

```lean
structure AuthzPhaseResult where
  decision : Decision CM
  conditionalAuthorizer : Option Authorizer   -- stored in ctx via WithConditionallyAuthorizedDecision

def authzPhase (chain) (attrs) : AuthzPhaseResult :=
  -- iterate, short-circuit on Allow/Deny/Conditional, continue on NoOpinion
```

Key implementation reference: `union.go:73-96` — iterates authorizers, appends decisions, short-circuits when `decision.ContainsAllowOrDeny()` (in our simplified model without Union, this is `Allow | Deny | Conditional`).

#### 4b. WithAuthorization HTTP Filter

```lean
inductive FilterVerdict where
  | Proceed (conditions : Option (CM × Authorizer))  -- request continues to admission
  | Reject (d : UnconditionalDecision)                -- 403 or 500

def withAuthorizationFilter (result : AuthzPhaseResult) : FilterVerdict :=
  match result.decision with
  | Allow          => Proceed none
  | Conditional cm => Proceed (some (cm, result.conditionalAuthorizer))
  | Deny           => Reject Deny
  | NoOpinion      => Reject NoOpinion
```

Key implementation reference: `filters/authorization.go:70-151` — the `withAuthorization` function. Flow:
1. If `unconditionallyAuthorized` (Allow) → proceed
2. If conditional and `CanBecomeAllowed()` → store in context, proceed
3. Otherwise → 403 Forbidden

#### 4c. AuthorizationConditionsEnforcer Admission Plugin

```lean
def conditionsEnforcer (verdict : FilterVerdict) (data : Data) : UnconditionalDecision :=
  match verdict with
  | Reject d                => d
  | Proceed none            => Allow  -- unconditionally authorized, nothing to enforce
  | Proceed (some (cm, a))  => a.evaluateConditions cm data
```

Key implementation reference: `conditionsenforcer.go:87-147` — the `Validate` function. Flow:
1. Get `(authorizer, decision)` from context
2. If not present → unconditionally authorized, pass through (`return nil`)
3. Otherwise → call `authorizer.EvaluateConditions(ctx, decision, data)`
4. If result is Allow → pass through
5. Otherwise → return Forbidden error

#### 4d. Pipeline Composition

```lean
def pipeline (chain) (attrs) (data) : UnconditionalDecision :=
  conditionsEnforcer (withAuthorizationFilter (authzPhase chain attrs)) data
```

### Part 5: Simplified Implementation (for proof convenience)

Collapse the three stages into a single recursive function:

```lean
def implChain (chain) (attrs) (data) : UnconditionalDecision :=
  match chain with
  | []        => NoOpinion
  | a :: rest => match a.authorize attrs with
                 | Allow          => Allow
                 | Deny           => Deny
                 | NoOpinion      => implChain rest attrs data
                 | Conditional cm => a.evaluateConditions cm data
```

### Part 6: Proofs

Two theorems:

**Theorem 1: `pipeline_eq_implChain`** — the composed pipeline equals the simplified version. Proof by structural induction on the chain, case-splitting on `a.authorize attrs`.

**Theorem 2: `authorization_equivalence`** (main) — `idealChain = pipeline`. Proof by:
1. Rewrite `pipeline` to `implChain` (using Theorem 1)
2. Structural induction on the chain
3. For each authorizer, case split on `a.authorize attrs`:
   - `Allow`: use `ax_allow` to rewrite `fullAuthorize` to `Allow`, both sides match
   - `Deny`: use `ax_deny`, same reasoning
   - `NoOpinion`: use `ax_noOpinion` to show `fullAuthorize = NoOpinion`, both sides recurse, apply IH
   - `Conditional cm`: use `ax_conditional` to rewrite `fullAuthorize` to `evaluateConditions cm data`. The ideal side then matches on this result. Sub-case split on `evaluateConditions cm data`:
     - `Allow` → both sides produce `Allow`, `rfl`
     - `Deny` → both sides produce `Deny`, `rfl`
     - `NoOpinion` → contradiction with `ax_no_noop`

### Part 7: Concrete ConditionsMap Model (reference section)

Define `ConditionEffect`, `ConditionEntry`, `ConcreteConditionsMap`, and `evaluateConditionsMap` that mirrors `ConditionsMap.Evaluate()` from the implementation — processing Deny conditions first, then NoOpinion, then Allow. Also define `canBecomeAllowed` on the concrete map (checks if any `effect=Allow` condition exists).

This section is not used by the main theorem but provides the groundwork for a future refinement proof that instantiates the abstract `CM` with `ConcreteConditionsMap` and shows `evaluateConditions` matches `evaluateConditionsMap`.

### Part 8: Future Extension Stubs

Add `sorry`-marked stubs for:
- `Union` variant of `Decision`
- Relaxation of `ax_no_noop` (the chain-resumption property Union provides)
- Proof that `evaluateConditionsMap` implements the priority semantics correctly

## Proof strategy notes

- All proofs use structural induction on `List Authorizer`
- The key technique is using the four `ax_*` hypotheses with `rw` to rewrite `fullAuthorize` in the ideal chain, aligning it with the implementation's case analysis on `authorize`
- `ax_no_noop` is only needed in the `Conditional` case to exclude the divergent `NoOpinion` branch
- The proof should be completable without Mathlib — only standard Lean 4 tactics (`rfl`, `rw`, `cases`, `exact`, `absurd`, `simp`, `unfold`)

## Verification

1. Install Lean 4 (elan + lake)
2. Create a minimal `lakefile.lean` alongside the file, or compile standalone with `lean plan/ConditionalAuthz.lean`
3. Verify no `sorry` remains in the core theorems (the stubs in Part 8 are expected to have `sorry`)
