# Plan: Make the `Id.run do … for … in … do …` transliterations provable

## Context

`ConditionalAuthorization/Go.lean` ports the Go authorizer functions in `staging/src/k8s.io/apiserver/pkg/authorization/` to Lean using the **`Id.run do … for … in … do …` style** — for-loops, early `return`s, mutable accumulators. The current file already contains:

| Go function | Lean Do-form |
|---|---|
| `ConditionsAwareDecision.FailClosedDecision` | `ConditionsAwareDecision.FailClosedDecisionDo` (top-level if-chain) |
| `unionSlice.FailClosedDecision` | `unionSliceFailClosedDecisionDo` *(uses `Id.run do for ... if ... return .Deny; return .NoOpinion`)* |
| `ConditionsAwareDecision.ContainsAllowOrDeny` | `ConditionsAwareDecision.ContainsAllowOrDenyDo` |
| `unionSlice.ContainsAllowOrDeny` | `unionSliceContainsAllowOrDenyDo` *(simple `if p x then return true; return false`)* |
| `ConditionsAwareDecision.CanBecomeAllowed` | `ConditionsAwareDecision.CanBecomeAllowedDo` |
| `unionSlice.CanBecomeAllowed` | `unionSliceCanBecomeAllowedDo` *(four-way `match` with mixed `return true/false`)* |
| `unionAuthzHandler.Authorize` | `UnionAuthorizer.authorizeDo` *(per-handler match-return)* |
| `unionAuthzHandler.ConditionsAwareAuthorize` | `UnionAuthorizer.conditionsAwareAuthorizeDo` *(`let mut acc; for; acc := acc ++ [d]; if … return acc; return acc`)* |
| `unionAuthzHandler.EvaluateConditions` | `UnionAuthorizer.evaluateConditionsDo` *(`for (sub, handler) in ds.zip handlers do match …`)* |

Mathlib is now available (`lake-manifest.json` shows it under `.lake/packages/mathlib`).

**Hard constraint from the user**: do *not* fall back to recursive `match` for the Do-versions. The Do-versions stay in `Id.run do … for … in … do …` shape.

**Problem**: Lean's `do for x in xs do if p x then return v` desugars through `forIn` with an `MProd Option`-style accumulator (so an inner `return` exits the surrounding `do`). The result is *not* definitionally equal to `if xs.any p then v_t else v_f` — Lean's automation can't `rfl` through the accumulator. We need a dedicated set of bridge lemmas.

## Strategy

Introduce **three** for-loop-shape bridge lemmas in `Go.lean`. Each maps a specific Go-loop idiom to a clean Lean expression. After that, every `XxxDo_eq` is a one-liner.

### Bridge lemma 1 — the workhorse `if-return-v_t; … ; return v_f` pattern

```lean
/-- A `for`-loop in `Id` that short-circuits on a predicate equals an `ite` on `List.any`. -/
@[simp] lemma forIn_id_short_circuit_eq_any_ite
    {α β : Type} (xs : List α) (p : α → Bool) (v_t v_f : β) :
    (Id.run do
       for x in xs do
         if p x then return v_t
       return v_f)
    = (if xs.any p then v_t else v_f) := by
  induction xs with
  | nil => simp [Id.run, List.forIn_nil]
  | cons hd tl ih =>
    by_cases hp : p hd
    · simp [hp, List.any_cons, List.forIn_cons, Id.run]
    · simp [hp, List.any_cons, List.forIn_cons, Id.run, ih]
```

Mathlib provides the simp lemmas `List.forIn_cons`, `List.forIn_nil`, `Id.run_pure`, `Id.bind_eq`. If `by_cases hp : p hd` + the four-element simp set doesn't close the cons step in one shot, we drop to a hand proof: `match (← f hd init)` with `ForInStep.done` (when `p hd`) or `ForInStep.yield` (otherwise) — each is one application of the relevant lemma. Worst case ~10 lines.

Covers:
- `unionSliceFailClosedDecisionDo` (predicate is `· .FailClosedDecisionDo == .Deny`, `v_t = .Deny`, `v_f = .NoOpinion`)
- `unionSliceContainsAllowOrDenyDo` (predicate is `· .ContainsAllowOrDenyDo`, `v_t = true`, `v_f = false`)

### Bridge lemma 2 — match-with-multiple-returns (`findSome?`-shape)

```lean
/-- A `for`-loop in `Id` where each iteration may early-return any value (via `match → return`)
    equals `(xs.findSome? f).getD v_default`. -/
@[simp] lemma forIn_id_findSome_eq_getD
    {α β : Type} (xs : List α) (f : α → Option β) (v_default : β) :
    (Id.run do
       for x in xs do
         match f x with
         | some v => return v
         | none => pure ()
       return v_default)
    = (xs.findSome? f).getD v_default := by
  induction xs with
  | nil => simp [Id.run, List.forIn_nil, List.findSome?]
  | cons hd tl ih =>
    cases hf : f hd with
    | some v => simp [hf, List.findSome?, List.forIn_cons, Id.run]
    | none => simp [hf, List.findSome?, List.forIn_cons, Id.run, ih]
```

Covers `unionSliceCanBecomeAllowedDo`. The `f` for that case:
```lean
fun d => match d with
  | .Deny => some false
  | .Allow => some true
  | .ConditionsMap _ => if d.CanBecomeAllowedDo then some true else none
  | .Union _       => if d.CanBecomeAllowedDo then some true else none
  | .NoOpinion => none
```
…with `v_default = false`.

### Bridge lemma 3 — mutable-accumulator pattern (`let mut acc := []; for; acc := acc ++ [d]; if … return acc; return acc`)

```lean
/-- A `for`-loop in `Id` that grows an accumulator and early-returns the current acc
    equals a structural recursion that threads the same accumulator. -/
lemma forIn_id_growing_acc_eq
    {α β : Type} (xs : List α) (compute : α → β) (cond : β → Bool) (init : List β) :
    (Id.run do
       let mut acc : List β := init
       for x in xs do
         let d := compute x
         acc := acc ++ [d]
         if cond d then return acc
       return acc)
    = collectHelper xs init compute cond
where
  collectHelper (xs : List α) (acc : List β) (compute : α → β) (cond : β → Bool) : List β :=
    match xs with
    | [] => acc
    | x :: rest =>
      let d := compute x
      let acc' := acc ++ [d]
      if cond d then acc'
      else collectHelper rest acc' compute cond
```

Covers `UnionAuthorizer.conditionsAwareAuthorizeDo`'s `let mut decisions := []; …` pattern. The proof is induction on `xs`, generalizing over `init` (to handle the non-empty starting accumulator in the cons-step recursion).

If the proof of this lemma turns into too much yak-shaving, the **fallback** (still per the user's "Id.run do for" requirement) is to slightly modify `conditionsAwareAuthorizeDo` to use a *tail-recursive helper* with an explicit accumulator parameter rather than `let mut`, written still inside `Id.run do for` — see "Possible target modifications" below. But first attempt: keep `let mut`, prove the lemma.

### Variant: zipped iteration for `evaluateConditionsDo`

`UnionAuthorizer.evaluateConditionsDo`'s loop runs over `ds.zip u.handlers`. The shape is *still* `if-return-v_t; … ; return v_f` once we treat the pair as the element type. Bridge lemma 1 applies directly with `α = ConditionsAwareDecision × Authorizer`, `p (sub, handler) := match sub with | .Allow => true | … | _ => match handler.evaluateConditions sub data with | .Allow => true | …`. (We may need a small adapter — `p` returns whether to short-circuit, plus a separate function for *which* value to return. For the `match` with multiple possible return values, we use bridge lemma 2 instead.)

## File structure & names

Only `ConditionalAuthorization/Go.lean` is *added to*. No new files. The three bridge lemmas live near the top of Go.lean's `-- Equivalence …` section, before any `XxxDo_eq`.

### Each `XxxDo_eq` after the bridges

Pattern (`unionSliceContainsAllowOrDenyDo_eq` shown):
```lean
theorem unionSliceContainsAllowOrDenyDo_eq (xs : List ConditionsAwareDecision) :
    unionSliceContainsAllowOrDenyDo xs
    = ConditionsAwareDecision.ContainsAllowOrDeny.anyContainsAllowOrDeny xs := by
  unfold unionSliceContainsAllowOrDenyDo
  rw [forIn_id_short_circuit_eq_any_ite]
  -- Now: if xs.any (·.ContainsAllowOrDenyDo) then true else false
  --    = anyContainsAllowOrDeny xs
  simp only [if_true_left, if_false_right]   -- ite ... = xs.any ...
  -- Bridge from `xs.any (·.ContainsAllowOrDenyDo)` to `anyContainsAllowOrDeny xs`
  -- via mutual induction with `ContainsAllowOrDenyDo_eq` (already in the same mutual block).
  induction xs with
  | nil => rfl
  | cons sub rest ih =>
    simp [List.any_cons, ih, sub.ContainsAllowOrDenyDo_eq]
    rfl  -- or: simp [ConditionsAwareDecision.ContainsAllowOrDeny.anyContainsAllowOrDeny]
```

The other slice-eqs follow the same pattern with the appropriate bridge lemma.

The top-level `ConditionsAwareDecision.FailClosedDecisionDo_eq`, `…ContainsAllowOrDenyDo_eq`, `…CanBecomeAllowedDo_eq` stay as five-arm `cases d` proofs, delegating the `.Union ds` arm to the slice lemma. These are essentially the proofs already in place.

`UnionAuthorizer.authorizeDo_eq`, `…conditionsAwareAuthorizeDo_eq`, `…evaluateConditionsDo_eq` each become short obtain-induction proofs that apply the relevant bridge lemma and then chain with the existing `UnionAuthorizer.authorize` / `entries` / `evaluateConditions` definitions.

## Possible target Lean modifications (only if a bridge proof refuses to close)

These are **stretch options**, used only as a fallback to keep the Id.run do for style while making proofs go through. The user has authorised slight modifications.

1. **`unionSliceCanBecomeAllowedDo`** — keep the `Id.run do for` shape, but rewrite the inner `match` to a single `option`-returning lambda followed by the bridge-2 pattern. Concretely, push the `match` into a helper `cbaStep : ConditionsAwareDecision → Option Bool` and have the loop body be `match cbaStep subDecision with | some v => return v | none => pure ()`. This is **still** Go-faithful (it just names the per-iteration result decision) and unlocks bridge lemma 2 directly.

2. **`UnionAuthorizer.conditionsAwareAuthorizeDo`** — if bridge lemma 3 stalls, refactor from `let mut decisions; ...; decisions := decisions ++ [d]; ...` to a tail-recursive helper expressed *inside* a `do` block, e.g. `Id.run do return UnionAuthorizer.collectDecisionsDoAux u.handlers attrs []`. The helper is one definition; the `Do` function still reads as a Go transliteration with explicit accumulator threading. This avoids the `let mut` semantics under mathlib.

3. **Companion shape lemma for `ContainsAllowOrDeny`-as-`xs.any`** — if `anyContainsAllowOrDeny`'s `||` form doesn't unify with `List.any`, add a tiny structural lemma `anyContainsAllowOrDeny_eq_any : anyContainsAllowOrDeny xs = xs.any (·.ContainsAllowOrDeny)` proved by `induction xs` (one-liner cons-step using `List.any_cons`). Cheap, isolates the conversion.

## Strengthened assumptions surfaced

After tracing the proof obligations end-to-end, **no axioms or invariant strengthenings are required**. The equivalences are pure restructuring:

- `unionSliceXxxDo` and the proof-friendly `anyXxx` are *extensionally* equal on every input (both walk the list, both early-exit on the same predicate). The equivalence holds for *all* `List ConditionsAwareDecision`, including the empty list and arbitrarily nested unions.
- `UnionAuthorizer.authorizeDo` and `UnionAuthorizer.authorize` agree on every `UnionAuthorizer` and every `Attributes`. No need to assume "well-formedness" or any non-trivial structure on the handlers list.
- For `evaluateConditionsDo` vs. `evaluateConditions`: both reduce to walking `u.handlers.zip ds`. They agree pointwise; no strengthened assumption.
- `conditionsAwareAuthorizeDo` vs. `conditionsAwareAuthorize`: both produce `.Union (entries.map Prod.snd)` semantically, but **the order of accumulation matters**. The Do-version uses `decisions ++ [d]` (back-append); the proof-friendly `entries` uses `(h,d) :: entries rest` (front-cons). These produce the *same* final list because the do-version starts with `[]` and front-appending vs. back-appending on a *single* growth path yields the same result. The bridge lemma 3 (or the fallback restructuring) captures this; no axiom needed.

## Spec theorem restatement (Spec.lean, Union.lean)

Once all `_eq` lemmas land, restate the main spec theorems to be stated *about* the Do-functions:

- `failClosed_not_deny_implies_ideal_not_deny` (Spec.lean) — change hypothesis from `d.FailClosedDecision ≠ .Deny` to `d.FailClosedDecisionDo ≠ .Deny`. Proof: `rw [ConditionsAwareDecision.FailClosedDecisionDo_eq] at h; <existing proof>`.
- `conditionsMap_failClosed_deny_or_noOpinion` — change to `FailClosedDecisionDo`. `rfl_eq` makes this trivial.
- `failClosed_deny_or_noOpinion` — change to `FailClosedDecisionDo`. Wrap with `_eq` rewrite.
- `UnionAuthorizer.metadata_allow_implies_ideal_allow` (Union.lean) — hypothesis becomes `u.authorizeDo attrs = .Allow`. Proof: `rw [UnionAuthorizer.authorizeDo_eq] at h; <existing proof>`.
- `UnionAuthorizer.satisfies_contract` — final theorem says the Do triplet `(authorizeDo, conditionsAwareAuthorizeDo, evaluateConditionsDo)` satisfies `AuthorizerContract`. Internally rewrite all three via their `_eq` lemmas to fall back to the already-proved version on the proof-friendly triplet.

The `Authorizer.xxx_implies_yyy` per-authorizer lemmas in Spec.lean are about an abstract `Authorizer` field, *not* about a concrete Go-transliterated function — they don't need restatement.

## Critical files

- `ConditionalAuthorization/Go.lean` — add 3 bridge lemmas; complete the `_eq` proofs using them; possibly refactor 1-2 Do-defs to fit (see "Possible target modifications").
- `ConditionalAuthorization/Spec.lean` — restate the four FailClosed-related theorems to use Do-versions (internally rewrite to the existing proofs).
- `ConditionalAuthorization/Union.lean` — restate the union spec theorems to use Do-versions.
- `ConditionalAuthorization/Authorizer.lean` — **untouched**. Proof-friendly defs remain the reference implementation.

## Verification

From `/Users/luxas/upbound/kubernetes/`:

1. `lake build` exits `0`, **no `sorry`s, no warnings, no `admit`s**.
2. `grep -n "sorry\|admit" ConditionalAuthorization/Go.lean` returns nothing.
3. The build output prints the new `#check` lines for the Do-typed signatures:
   ```
   ConditionalAuthorization.Authorizer.ConditionsAwareDecision.FailClosedDecisionDo : … → Decision
   ConditionalAuthorization.Authorizer.ConditionsAwareDecision.ContainsAllowOrDenyDo : … → Bool
   ConditionalAuthorization.Union.UnionAuthorizer.authorizeDo : UnionAuthorizer → Attributes → Decision
   ConditionalAuthorization.Union.UnionAuthorizer.evaluateConditionsDo : UnionAuthorizer → ConditionsAwareDecision → ConditionsData → Decision
   ```
4. The restated spec theorems in Spec.lean and Union.lean still type-check, demonstrating that the Do-versions satisfy `AuthorizerContract` and the FailClosed invariants.
