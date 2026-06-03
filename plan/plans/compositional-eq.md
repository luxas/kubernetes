# Plan: Close the Go-Do composition equality `evaluateConditionsDo ∘ conditionsAwareAuthorizeDo = idealAuthorize`

## Context

After the two `where`-clause refactors, `UnionAuthorizer`'s public surface is clean and the helpers (`conditionsAwareAuthorize.subDecisions`, `evaluateConditions.walk`) are scoped. On the Go-Do side, three `_eq` lemmas are still open:

| Go-Do function | Proof-friendly counterpart | Status |
|---|---|---|
| `conditionsAwareAuthorizeDo` (`let mut` accumulator, short-circuit on `ContainsAllowOrDenyDo`) | `conditionsAwareAuthorize` (recursive, short-circuit on top-level `.Allow \| .Deny` only) | **Not pointwise-equal**: differ on inputs where individual authorizers return nested `.Union ds` containing Allow/Deny leaves. |
| `evaluateConditionsDo` (`for (sub, h) in ds.zip u.handlers do match …`) | `evaluateConditions` (recursive `walk`) | Pointwise equal; needs a bridge lemma stepping the Do for-loop. |
| Composition: `evaluateConditionsDo (conditionsAwareAuthorizeDo attrs) data` | `idealAuthorize attrs data` (== contract third leg by `satisfies_contract`) | **Provable**, despite the first row not being provable. |

The user is asking specifically about closing the **composition** equality. The key insight is the third row — the composition is achievable *because* `walk` is monotone over short-circuit-truncated decision lists: when `conditionsAwareAuthorizeDo` short-circuits early on a `.Union ds'` whose `ContainsAllowOrDeny` is true, the corresponding `walk` step already produces a definitive `.Allow` / `.Deny` for that sub-decision (since `Ideal` of any decision with a reachable Allow/Deny leaf is forced to one of those two values). The earlier truncation just doesn't matter for the final result.

## Strategy

Two layers of bridge lemmas, then the composition theorem.

### Helper lemma — "ContainsAllowOrDeny forces Ideal"

```lean
/-- If a sub-decision contains an Allow or Deny leaf in its tree, then evaluating its
    `Ideal` at *any* data yields exactly `.Allow` or `.Deny` — never `.NoOpinion`. -/
mutual
theorem containsAllowOrDeny_implies_ideal_AllowOrDeny
    (d : ConditionsAwareDecision) (data : ConditionsData)
    (h : d.ContainsAllowOrDeny = true)
    : d.Ideal data = .Allow ∨ d.Ideal data = .Deny

theorem anyContainsAllowOrDeny_implies_unionIdealAuthorize_AllowOrDeny
    (ds : List ConditionsAwareDecision) (data : ConditionsData)
    (h : ConditionsAwareDecision.ContainsAllowOrDeny.anyContainsAllowOrDeny ds = true)
    : unionIdealAuthorize ds data = .Allow ∨ unionIdealAuthorize ds data = .Deny
end
```

Standard structural induction with case-split on the leaf shape. The Union case delegates to the list version; the list version recurses on `ds` and uses the inductive case on each non-NoOpinion element.

Lives in `ConditionalAuthorization/Go.lean` next to the existing bridge lemmas.

### Bridge — `evaluateConditionsDo` Union case equals `walk`

```lean
/-- The Go-Do `evaluateConditionsDo` for the `.Union ds` case unfolds to the same
    parallel walk that the proof-friendly `evaluateConditions.walk` uses. -/
lemma evaluateConditionsDo_union_eq_walk
    (u : UnionAuthorizer) (ds : List ConditionsAwareDecision) (data : ConditionsData) :
    u.evaluateConditionsDo (.Union ds) data
    = UnionAuthorizer.evaluateConditions.walk data u.handlers ds
```

Proof by induction on `ds` paralleled with `u.handlers`, stepping the `for-in` desugaring of `evaluateConditionsDo` via `List.forIn_cons` (already-known core simp lemma) and reducing the inner `match` case-by-case. This mirrors the bridge-2 pattern (`forIn_id_findSome_eq_getD`) we already use for `unionSliceCanBecomeAllowedDo`, just with a `ds.zip u.handlers` driver.

With this in hand, the *full* `evaluateConditionsDo_eq` lemma falls out:

```lean
theorem UnionAuthorizer.evaluateConditionsDo_eq (u : UnionAuthorizer)
    (decision : ConditionsAwareDecision) (data : ConditionsData) :
    u.evaluateConditionsDo decision data = u.evaluateConditions decision data := by
  cases decision with
  | Allow | Deny | NoOpinion => rfl
  | ConditionsMap _ =>
    simp [UnionAuthorizer.evaluateConditionsDo, UnionAuthorizer.evaluateConditions,
          decision.FailClosedDecisionDo_eq]
  | Union ds => exact evaluateConditionsDo_union_eq_walk u ds data
```

### Bridge — `conditionsAwareAuthorizeDo` factors via a recursive helper

The `let mut decisions := []; …; decisions := decisions ++ [d]; …` pattern doesn't unfold cleanly. Introduce a normal recursive helper that captures the same behaviour:

```lean
/-- Recursive equivalent of `conditionsAwareAuthorizeDo`'s `let mut` accumulator. -/
private def subDecisionsDo : List Authorizer → Attributes → List ConditionsAwareDecision
  | [], _ => []
  | h :: rest, attrs =>
    let d := h.conditionsAwareAuthorize attrs
    if d.ContainsAllowOrDenyDo then [d]
    else d :: subDecisionsDo rest attrs

/-- The Do version's accumulator builds exactly `subDecisionsDo`. -/
lemma conditionsAwareAuthorizeDo_eq_union_subDecisionsDo (u : UnionAuthorizer) (attrs : Attributes) :
    u.conditionsAwareAuthorizeDo attrs = .Union (subDecisionsDo u.handlers attrs)
```

The bridge needs a *third* `Id.run do`-bridge lemma for the `let mut acc; for x in xs do … acc := acc ++ [f x]; if g (f x) then return acc; return acc` pattern. Generic form:

```lean
lemma forIn_id_growing_acc_eq
    {α β : Type} (xs : List α) (compute : α → β) (cond : β → Bool) (init : List β) :
    (Id.run do
       let mut acc : List β := init
       for x in xs do
         let v := compute x
         acc := acc ++ [v]
         if cond v then return acc
       return acc)
    = init ++ collectAux xs compute cond
where
  collectAux : List α → (α → β) → (β → Bool) → List β
    | [], _, _ => []
    | x :: rest, compute, cond =>
      let v := compute x
      if cond v then [v] else v :: collectAux rest compute cond
```

Proof: induction on `xs`, generalising over the starting accumulator `init`. Apply the same `List.forIn_cons` / `Id.run`-cleanup tactic chain we used for bridges 1 and 2.

Once `forIn_id_growing_acc_eq` is in hand, `conditionsAwareAuthorizeDo_eq_union_subDecisionsDo` is a one-line application with `init = []`.

### Composition theorem

```lean
/-- **Main result**: the Go-Do composition equals the spec function. -/
theorem UnionAuthorizer.composition_do_eq_ideal (u : UnionAuthorizer)
    (attrs : Attributes) (data : ConditionsData) :
    u.evaluateConditionsDo (u.conditionsAwareAuthorizeDo attrs) data
    = u.idealAuthorize attrs data := by
  rw [conditionsAwareAuthorizeDo_eq_union_subDecisionsDo]
  rw [evaluateConditionsDo_union_eq_walk]
  exact walk_subDecisionsDo_eq_idealAuthorize u.handlers attrs data
```

where the core induction lives in:

```lean
theorem walk_subDecisionsDo_eq_idealAuthorize
    (handlers : List Authorizer) (attrs : Attributes) (data : ConditionsData) :
    UnionAuthorizer.evaluateConditions.walk data handlers (subDecisionsDo handlers attrs)
    = UnionAuthorizer.idealAuthorize ⟨handlers⟩ attrs data
```

Proof: induction on `handlers`.

- **`nil`**: both sides reduce to `.NoOpinion` by `simp [subDecisionsDo, walk, idealAuthorize]`.
- **`cons h rest`**: let `d := h.conditionsAwareAuthorize attrs`. Case-split on `d.ContainsAllowOrDenyDo`.
  - **`true`**: `subDecisionsDo = [d]`, so `walk handlers [d] data` processes a single pair `(h, d)`. Case on `d`:
    - `d = .Allow`: walk returns `.Allow`. By contract `h.idealAuthorize attrs data = d.Ideal data = .Allow`. idealAuthorize matches and returns `.Allow`. ✓
    - `d = .Deny`: symmetric. ✓
    - `d = .Union _`: walk falls into the `ConditionsMap | Union` arm and computes `h.evaluateConditions d data = d.Ideal data` (by `contract_eval_eq_ideal`). By the **helper lemma**, this is in `{.Allow, .Deny}`. Both walk and idealAuthorize evaluate `d.Ideal data` and return it (idealAuthorize's match on `.Allow`/`.Deny` short-circuits). ✓
    - `d = .NoOpinion` or `.ConditionsMap _`: impossible because `ContainsAllowOrDeny` would be `false`. Discharge via the case hypothesis.
  - **`false`**: `subDecisionsDo = d :: subDecisionsDo rest`, walk processes the head and falls through. Sub-cases on `d`:
    - `d = .Allow | .Deny`: impossible (ContainsAllowOrDeny would be true).
    - `d = .NoOpinion`: walk recurses on `rest`, idealAuthorize recurses on `rest` (both because the head returns NoOpinion). Use induction hypothesis.
    - `d = .ConditionsMap c`: walk computes `h.evaluateConditions d data = c.Ideal data`. idealAuthorize computes `d.Ideal data = c.Ideal data`. Case on `c.Ideal data`: Allow/Deny short-circuit identically; NoOpinion recurses identically. Use IH.
    - `d = .Union ds`: walk computes `h.evaluateConditions d data = d.Ideal data`. Same as ConditionsMap; case on `d.Ideal data`. ✓

Total ~70-100 lines of Lean for the composition theorem, factoring out one IH-use per sub-case.

## File-by-file impact

### `ConditionalAuthorization/Go.lean`

1. Add the helper lemma `containsAllowOrDeny_implies_ideal_AllowOrDeny` + list version (mutual).
2. Add bridge `evaluateConditionsDo_union_eq_walk` and use it to land the full `UnionAuthorizer.evaluateConditionsDo_eq` (1 of the 2 outstanding `_eq`s closes).
3. Add `forIn_id_growing_acc_eq` (the third bridge lemma for `let mut` accumulators).
4. Add `subDecisionsDo` recursive helper + `conditionsAwareAuthorizeDo_eq_union_subDecisionsDo`.
5. Add `walk_subDecisionsDo_eq_idealAuthorize` (the inductive core).
6. Add `UnionAuthorizer.composition_do_eq_ideal` (the headline theorem).
7. Update the trailing comment block to reflect: composition is now closed; `conditionsAwareAuthorizeDo_eq` remains *not pointwise-provable* by design (semantic mismatch surfaced earlier).

### Files unaffected

- `ConditionalAuthorization/Union.lean` — already in its final shape.
- `ConditionalAuthorization/Spec.lean` — abstract per-authorizer lemmas untouched.
- `ConditionalAuthorization/Authorizer.lean` — already aligned (CanBecomeAllowed semantic fix from earlier still stands).

## Surfaced design fact (not a bug, just worth noting)

`conditionsAwareAuthorizeDo` and `conditionsAwareAuthorize` are **not pointwise equal** by design — Go short-circuits on `ContainsAllowOrDeny` (recursively into nested Unions), the proof-friendly Lean side short-circuits on top-level `.Allow | .Deny` only. The two are *observationally equivalent under composition with `evaluateConditions(Do)`* — which is what the contract cares about — but not individually. The composition theorem is the right statement to make for "the Go transliteration is semantically correct".

(If we ever wanted pointwise equivalence here, the fix would be: change `subDecisions` (proof-friendly) to short-circuit on `ContainsAllowOrDeny`. That cascades through `evaluate_eq_ideal`, `idealAuthorize_eq_unionIdealAuthorize_subDecisions`, and `satisfies_contract` proofs in Union.lean. Out of scope for this task — the composition theorem is sufficient.)

## Feasibility estimate

- Helper lemma: ~30 lines (mutual induction, straightforward).
- `evaluateConditionsDo_union_eq_walk`: ~25 lines (mirrors existing bridge proofs).
- `forIn_id_growing_acc_eq`: ~30 lines (most involved bridge — `let mut` + appending accumulator).
- `subDecisionsDo` + `conditionsAwareAuthorizeDo_eq_union_subDecisionsDo`: ~15 lines.
- `walk_subDecisionsDo_eq_idealAuthorize`: ~70 lines (the inductive core with eight sub-cases).
- `UnionAuthorizer.composition_do_eq_ideal`: ~5 lines (three rewrites + the core lemma).
- `UnionAuthorizer.evaluateConditionsDo_eq` (bonus): ~10 lines (a free win once the union bridge is in).

Total: **~185 lines added to `Go.lean`**. No changes to other files. All bridges follow patterns already established by the existing bridges 1 and 2.

## Risk

- **Termination of mutual helper**: needs `sizeOf`-based decrease through `Union ds → ds`. Mirrors the existing `failClosed_deny_or_noOpinion` mutual block, which compiles, so this should work.
- **`forIn_id_growing_acc_eq` proof complexity**: `let mut` desugars to an explicit accumulator state in `forIn`'s `MProd`. Will require care with the `simp` set; falling back to step-by-step `forIn_cons` unfolding is the bailout. If it stalls, we can change `conditionsAwareAuthorizeDo` to use an explicit recursive helper inside `Id.run do` (still Go-shaped, but easier to prove about).

## Critical files

- `/Users/luxas/upbound/kubernetes/ConditionalAuthorization/Go.lean` — the only file modified.

## Verification

From `/Users/luxas/upbound/kubernetes/`:

1. `lake build` exits `0`, no `sorry`s, no warnings.
2. `grep -n "composition_do_eq_ideal\|evaluateConditionsDo_eq" ConditionalAuthorization/Go.lean` shows both new theorems.
3. `#check (UnionAuthorizer.composition_do_eq_ideal : ∀ u attrs data, u.evaluateConditionsDo (u.conditionsAwareAuthorizeDo attrs) data = u.idealAuthorize attrs data)` (or equivalent) added to confirm the headline signature.
4. The trailing comment in Go.lean now lists only `conditionsAwareAuthorizeDo_eq` as outstanding (with the explanation that it isn't pointwise-provable by design).
