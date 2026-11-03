# authorizer-eval

Scope: `lean/authorizer/conditionsunion.lean`, `lean/authorizer/evaluate.lean` ↔
`staging/src/k8s.io/apiserver/pkg/authorization/authorizer/{conditionsunion,evaluate}.go`;
theorem statements in `lean/authorizer/conditions_properties.lean` and
`lean/authorizer/conditionsunion_properties.lean`.

Build: `lake build authorizer.conditionsunion authorizer.evaluate authorizer.conditions_properties authorizer.conditionsunion_properties`
→ `Build completed successfully`. `grep sorry|axiom lean/authorizer/*.lean` → no matches.

| Lean def | Go file:line | verdict | note |
|---|---|---|---|
| `namedConditionsAwareDecision` | conditionsunion.go:30-33 | Equivalent | Unused; the builder stores `String × CAD` pairs. Doc nit: says `:30-34`. |
| `ConditionsAwareDecisionUnion` (structure) | conditionsunion.go:37-50 | Equivalent | `{}` = Go zero value. Go's nil `subDecisionsPossibleDecisions` and the Lean `.empty` behave the same in `PossibleDecisions` (Go `:121-123`). Doc nit: says `:37-56`. |
| `hasConditionalAuthorizerName` | conditionsunion.go:86-90 | Equivalent | `List.any` = `slices.ContainsFunc` over `inner`. |
| `ContainsUnconditionalAllowOrDeny` (builder) | conditionsunion.go:108-110 | Equivalent | |
| `PossibleDecisions` (builder) | conditionsunion.go:116-129 | Equivalent | `{N} ∪ sub`, then delete N if flag. |
| `FailureDecision` (builder) | conditionsunion.go:98-103 | Equivalent | |
| `Add` | conditionsunion.go:58-84 | Equivalent | Same flag check first (it returns `u` unchanged, so no validation happens). The three name checks run in Go order (empty, duplicate against the pre-append `inner`, DNS-1123) and are not short-circuited. Each check appends one error to the accumulated `errs`. The child is appended even when there are errors. `flag ‖= cua(d)` is computed from the incoming `d`. `sub ∪= PD(d)`. Error text is abstracted (README 1). |
| `collectReasonsAndErrors` | conditionsunion.go:187-208 | Abstraction | Same control flow: a matching leaf collects its reason when it is non-empty and its error when it is non-nil. A union recurses depth-first in `inner` order (`UnionedDecisions`, conditions.go:246-254, keeps order) with prefix `prefix ++ [n]`. A map, or a leaf of another kind, contributes nothing. The Go "match first, then IsUnion" order is harmless because a union never matches a leaf kind. `%w` wrapping is modelled as a string (README 1). |
| `ToDecision` | conditionsunion.go:135-185 | Abstraction | `errs ≠ []` is tested first → `FromParts(FD_B, "failed closed", agg errs)`. Otherwise `theOnly` (= `Len==1` + `UnsortedList()[0]`) folds by running `collectReasonsAndErrors [nᵢ] cᵢ X` over `inner` in order, joined with `", "`. `FromParts X` gives the same result as Go's per-case `ConditionsAwareDecision{Deny,NoOpinion,Allow}`, and the Go `default` is unreachable (README 8). If not folded, the result is `.union inner`. The clone is free (value semantics). The emitted union drops the copied caches (README 6); `Reachable.cua_eq`/`sub_eq` prove the caches equal what is recomputed from `inner` for every reachable builder, so nothing is lost. |
| `ConditionEvaluationResult` | evaluate.go:29-97 | Equivalent | Four exact variants (README 8). Doc nit / latent hazard: the doc comment says "The zero value is `unevaluatable`", but `deriving Inhabited` makes `default = .true_` (checked with `#eval`). Nothing uses `default` today. |
| `Boolean` | evaluate.go:48-53 | Equivalent | |
| `Error'` | evaluate.go:56-67 | Equivalent | A nil error is normalised to a non-nil error. |
| `Unevaluatable` | evaluate.go:70-74 | Equivalent | Doc nit: says `:70-75`. |
| `IsTrue`/`IsFalse`/`IsError`/`IsUnevaluatable` | evaluate.go:77-97 | Equivalent | |
| `MaybeEvaluateConditionFunc` | interfaces.go:302 | Abstraction | Folded oracle `ev₀ ▷ fn` with `data` applied (README 2). A nil `fn` corresponds to `p = ev₀`. |
| `EvaluateConditionFunc` | interfaces.go:299 | Abstraction | |
| `MaybeEvaluateConditionFunc.Total` | properties.md §1.1 | Abstraction | Model-only predicate. |
| `reasonOf` | evaluate.go:205-208 | Abstraction | Same structure; `%q` quoting is dropped (README 1). |
| `phaseResult` | evaluate.go:197 (return triple) | Abstraction | `hit c` ≙ `(reason≠"", nil, nil)`. `miss errs unev` ≙ `("", errs, unev)`. |
| `conditionsToAppliedErroredUnevaluated` | evaluate.go:197-225 | Equivalent | Scans in order and returns on the first `true`, discarding earlier errors and unevaluated conditions (Go `:211`). `false` → skip. Unevaluatable conditions and errors are each appended in list order. Go's `default` is unreachable (README 8). Doc nit: says `:197-224`. |
| `evaluationErrorsReason` | evaluate.go:145,163,183 | Equivalent | |
| `partiallyEvaluateConditionsMapInternal` | evaluate.go:121-192 | Equivalent | Each phase is guarded by `len(list) != 0`. The guard is semantically redundant (an empty scan is `miss [] []`) but it is reproduced. Within a phase the checks run hit, then errored, then unevaluated, so errors take precedence over unevaluated conditions. The `mkMap` calls are `mkMap(unev, c.noOpinionConditions, c.allowConditions)`, `mkMap([], unev, c.allowConditions)` and `mkMap([], [], unev)`, i.e. the ORIGINAL N/A lists, exactly as Go. The Allow phase's errored result is `noOpinion` (Go `:182-184`). The final result is `noOpinion "no conditions matched" none`. The `evalCond` wrapper (`:122-131`) is folded into `p` (README 2). |
| `ConditionsMap.Evaluate` | evaluate.go:102-112 | Abstraction (+ Gap) | The adapter matches Go: `(_, some e) → .error e`, `(b, none) → Boolean b`, then `UnconditionalPartsOrError`. The Lean `evaluateConditionFn` stands for the combined `ev₀ ▷ fn`. Go first consults the condition's own `Evaluate` (`:125`) and calls the parameter only on `U`. The Lean doc should say so. Gap: the Go nil-function panic when `ev₀ = U` is not modelled. No property depends on it: `review/properties.md:354` marks it "Lean: no (operational)", and no Lean theorem mentions `ConditionsMap.Evaluate`. |
| `PartiallyEvaluateConditionsAwareDecision` | evaluate.go:235-282 | Equivalent | A map goes to `pmap`. An unconditional decision is returned unchanged. For a union, `loop l {} false`. Once `collectTail` is true, every later child is `Add`ed unevaluated and `true` is passed on, so the flag is sticky (Go never resets it). Otherwise the child is evaluated and `Add`ed. If `cua(evaluated)` → `ToDecision` (this check comes first, as in Go `:266`). Else recurse with `!evaluated.IsUnconditional`. Because the current flag is `false` in this branch, that equals Go's `collectTail = collectTail ∨ ¬uncond`. At the end of the list → `ToDecision`. When `Add` is a no-op after a raw cua tail child, the behaviour is the same in both. |
| `refSem` / `refSem.seq` | properties.md §1.7 | Equivalent | `seq [] = N`, and `seq` returns the first child result `≠ N`: exactly first-non-NoOpinion-wins. The map case is `(pmap m o).dec?.getD (pmap m o).FailureDecision`, which is `(UnconditionalPartsOrError (pmap m o)).1`, i.e. the decision `ConditionsMap.Evaluate` returns when `o` is its adapter. For total `o`, `pmap` never reaches `mkMap` (unev = []), so it is unconditional and `getD` never fires. The fallback is a harmless total extension for non-total `o`. |

Counts: Equivalent 20, Divergence 0, Abstraction 8, Gap 1 (the `ConditionsMap.Evaluate` nil-fn panic, which is part of that row's verdict).

## Divergences

None. I found no input for which the Lean model computes a different decision, PD, FD, error-nil-ness or tree structure than Go.

Doc fixes I propose (no semantic change):

```lean
-- evaluate.lean: make the doc claim true (Go zero value = unevaluatable)
inductive ConditionEvaluationResult where
  | unevaluatable
  | true_
  | false_
  | error (err : Err)
  deriving DecidableEq, Repr, Inhabited
-- (or keep the order and add `instance : Inhabited ConditionEvaluationResult := ⟨.unevaluatable⟩`)

/-- `ConditionsMap.Evaluate`, `evaluate.go:102-112`. `evaluateConditionFn` here is the
EFFECTIVE oracle `c ↦ if ev₀ c ≠ U then ev₀ c else fn c` (README §Abstractions 2): Go
consults `cond.Evaluate` first (`:125`) and calls its parameter only on `U`. -/
```

Line-number nits: `namedConditionsAwareDecision` → `:30-33`; `ConditionsAwareDecisionUnion` → `:37-50`; `Unevaluatable` → `:70-74`; `conditionsToAppliedErroredUnevaluated` → `:197-225`; `ConditionsMap.Evaluate` → `:102-112`.

## Theorem statement review

conditions_properties.lean
- `P_1_zero_is_deny`: matches.
- `P_35_noOpinion_possible_iff`: stronger. It holds for all trees, while the catalogue assumes `∀ WF d`.
- `P_3_possibleDecisions_nonempty` / `P_3_Len_pos` / `P_3_Len_le_three`: stronger (no WF hypothesis). `⊆ {D,A,N}` holds by the type.
- `P_5_failureDecision_spec`: matches.
- `P_9_splitters_unconditional`, `P_9_splitters_conditional`: match. The second also proves "never Allow". The catalogue's "Lean: no" is out of date.
- `P_13_mkMap_WF`: matches, and additionally proves `m = ⟨D,N,A⟩`.
- `P_14_mkMap_ne_allow`: matches.
- `P_14_mkMap_empty`: matches.
- `P_14_mkMap_noOpinion_only_skips_validation`: matches. `N ≠ []` and `|N| ≤ 128` are exactly the catalogue's `1 ≤ total ≤ 128`.
- `P_14_mkMap_fallback`: weaker. It gives the variant (`deny ⟺ D ≠ []`) but not the catalogue's `err ≠ nil` for the empty, too-many and invalid fallbacks. The Lean is too weak; the catalogue is right. Proposed addition:
  ```lean
  theorem P_14_mkMap_fallback_err (D N A : List Condition)
      (h : (ConditionsAwareDecisionConditionsMap D N A).IsConditionsMap = false)
      (hN : ¬ (D = [] ∧ A = [] ∧ N ≠ [] ∧ N.length ≤ MaxConditionsPerMap)) :
      (ConditionsAwareDecisionConditionsMap D N A).Error.isSome = true
  ```
- `P_15_map_PD`: matches.
- `P_15_map_Len`, `P_15_mkMap_Len`: match. The `m.WF` hypothesis is the catalogue's implicit "maps are only built by mkMap" (§1.3).
- `P_15_map_Len_not_all_maps`: a correct negative for arbitrary maps (`{}`).
- `P_4_unconditional_iff_singleton`: matches (WF).
- `P_4_not_all_trees`: a correct negation of the all-trees strengthening, not of the catalogue claim (which needs WF). Labelled accordingly.
- `P_6_failureDecision_ne_allow`: stronger (all trees).
- `P_6_failureDecision_mem_WF`: matches.
- `P_6_failureDecision_allow`: matches.
- `P_6_failureDecision_mem_of`: a helper.
- `P_6_not_all_trees`: a correct negative for non-WF trees.

conditionsunion_properties.lean
- `P_33_add_noop`: matches. Equality of the whole builder also covers inner, errs and PD, so there is no name validation either.
- `P_5_builder_failureDecision_spec`: matches.
- `P_35_builder_noOpinion_possible_iff`: matches (all builder states).
- `P_34_errs_fail_closed`: matches. The "errs records empty/duplicate/non-DNS-1123" half is given by `Add_of_not_cua` (the `errs = [] ↔ …` clause).
- `P_34_errs_unconditional`: extra and consistent.
- `P_34_allow_with_empty_name_becomes_noOpinion`: matches the P-34 note.
- `P_36_union_shape`: weaker. It omits the catalogue conjunct "the tree contains at least one map leaf". That conjunct is false for arbitrary `P`: a child `union [("a", allow), ("b", deny)]` (non-WF) gives `PD = {A,D}`, and the result is emitted unfolded with no map. It does hold when the children are WF (a tree with no map leaf has singleton PD and is folded). The catalogue is right for WF unions; the Lean is too weak. Proposed addition:
  ```lean
  def hasMapLeaf : ConditionsAwareDecision → Bool
    | .conditionsMap _ => true
    | .union l => l.attach.any (fun ⟨p, _⟩ => hasMapLeaf p.2)
    | _ => false
  theorem P_36_has_map_leaf {u} (hr : Reachable ConditionsAwareDecision.WF u)
      {l} (h : u.ToDecision = .union l) : hasMapLeaf (.union l) = true
  ```
- `P_4_ToDecision_unconditional_iff`, `P_4_mkMap_unconditional_iff`: match P-4 for constructor outputs.
- `WF_ToDecision`, `ToDecision_union_WF_except_children`, `Reachable.*`: support lemmas, consistent with §1.3 `WFUnion`.

## Axioms

None in the covered files (`grep axiom` is empty). No `sorry`.

## Verdict

`conditionsunion.lean` and `evaluate.lean` follow the Go source branch by branch. The details the brief asked about all match Go:
- `Add`'s check order, error accumulation, unconditional append, and the flag computed from the incoming child.
- `ToDecision`'s errs-first test, the `Len==1` fold through `theOnly`, depth-first leaf collection, and recomputing the dropped caches (proved equal for reachable builders).
- The map evaluator's `len != 0` guards, first-true short circuit, errored-before-unevaluated precedence, and `mkMap` called on the original N/A lists.
- The sticky `collectTail` in `PartiallyEvaluateConditionsAwareDecision`.

`refSem` is exactly §1.7, and its map case equals `ConditionsMap.Evaluate`'s decision. The only unmodelled Go behaviour is the nil-`evaluateConditionFn` panic, which no property relies on. Folding `cond.Evaluate` into the `ConditionsMap.Evaluate` parameter is covered by README abstraction 2 but should be stated in that definition's doc. The model is trustworthy for the properties it proves. Two theorem statements are weaker than the catalogue: P-14 lacks `err ≠ nil` on the fallbacks, and P-36 lacks the "at least one map leaf" conjunct. In both cases the catalogue is correct and an additive theorem is proposed above. Neither invalidates any theorem that is proved.
