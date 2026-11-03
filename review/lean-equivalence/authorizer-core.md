# authorizer-core

Scope: `lean/authorizer/interfaces.lean`, `lean/authorizer/conditionsmap.lean`,
`lean/authorizer/conditions.lean`, and the theorems in `lean/authorizer/conditions_properties.lean`,
against `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/{interfaces,conditionsmap,conditions}.go`
(plus `conditionsunion.go:58-129,176-184` for the union caches).

Build: `lake build authorizer.interfaces authorizer.conditionsmap authorizer.conditions authorizer.conditions_properties`
completed successfully. There is no `sorry` and no `axiom` in any of the four files.

| Lean def | Go file:line | verdict | note |
|---|---|---|---|
| `Decision` | interfaces.go:231-242 | Abstraction | Go `int`. Unknown values cannot be represented (README #8). Deny is constructor 0, so it is the zero value, as in Go. |
| `DecisionDeny/Allow/NoOpinion` | interfaces.go:233-242 | Equivalent | |
| `Decision.String` | interfaces.go:244-255 | Abstraction | The `Unknown (%d)` default branch is unreachable (#8). Doc nit: the doc says `244-257`. |
| `DecisionSet` | `sets.Set[Decision]` | Equivalent | Three Bools model a subset of a 3-element universe exactly. The universe is closed because of #8. |
| `DecisionSet.empty` | `sets.New[Decision]()` | Equivalent | |
| `DecisionSet.singleton` | `sets.New(x)` | Equivalent | |
| `DecisionSet.Has` | `Set.Has` | Equivalent | |
| `DecisionSet.Insert` | `Set.Insert` | Equivalent | Go mutates in place. Every Go call site uses a fresh set or a builder-owned set, so pure is fine. |
| `DecisionSet.Delete` | `Set.Delete` | Equivalent | Only used at conditionsunion.go:126, on a fresh set. |
| `DecisionSet.union` | `Insert(other.UnsortedList()...)` (conditionsunion.go:83,122) | Equivalent | `nil` receiver/argument: a nil `subDecisionsPossibleDecisions` is skipped at :121, and `empty` is the identity for `union`, so the result is the same. |
| `DecisionSet.Len` | `Set.Len` | Equivalent | |
| `DecisionSet.Subset` (+ `DecidableRel`) | `Set.IsSuperset` (flipped) | Equivalent | |
| `DecisionSet.theOnly` | `UnsortedList()[0]` when `Len()==1` (conditionsunion.go:144-145) | Equivalent | Defined only for `Len = 1`, which has a unique member, so the iteration order of `UnsortedList` does not matter. `theOnly_eq_some_iff` proves `theOnly s = some x ↔ s = {x}`. |
| `Err` | `error` | Abstraction | #1 |
| `aggregate` | `utilerrors.NewAggregate` | Abstraction | #1. Go filters `nil` entries. `List Err` has no nil, so the only nil-ness question is `[]` → `none`, and that is exact. Callers must pre-filter, and `collectReasonsAndErrors` does. |
| `ConditionsData` | interfaces.go:313-345 | Abstraction | #3. Doc nit: the doc says `313-348`. |
| `Condition` | interfaces.go:262-296 | Abstraction | Go has an interface, Lean a structure: #2 (no `Evaluate`). Getter purity is a contract (interfaces.go:261). The nil-Condition panic (conditionsmap.go:137) is excluded by construction. Invalid-UTF-8 strings: see the gap row below. |
| `Condition.GetID/GetType/GetCondition/GetDescription` | interfaces.go:267-283 | Equivalent | |
| `ConditionTypeAuthorizationCEL` | interfaces.go:350 | Equivalent | |
| `ErrorConditionEvaluationNotSupported` | interfaces.go:128 | Equivalent | |
| `IsDomainPrefixedKey` | apimachinery validation | Abstraction | #4. Go returns `field.ErrorList` and Lean returns `Bool`; `true` ⇔ `len(errs)==0`. |
| `IsDNS1123Subdomain` | apimachinery validation | Abstraction | #4, same mapping. |
| `ConditionsMap` | conditionsmap.go:34-43 | Equivalent | `nil` and empty slices are indistinguishable to every consumer (only `len` and range are used). Doc nit: the doc says `34-47`. |
| `MaxConditionsPerMap`, `MaxConditionBytes`, `MaxConditionDescriptionBytes` | conditionsmap.go:116,119,122 | Equivalent | |
| `ConditionsMap.Length` | conditionsmap.go:59-61 | Equivalent | |
| `ConditionsMap.Deny/NoOpinion/AllowConditions` | conditionsmap.go:65-97 | Equivalent | Same order. The early-stop iterator behaviour has no observable counterpart. Doc nit: the doc says `65-99`. |
| `ConditionsMap.PossibleDecisions` | conditionsmap.go:103-112 | Equivalent | Same insertion order (irrelevant for a set). |
| `ConditionsMap.FailureDecision` | conditionsmap.go:50-56 | Equivalent | |
| `ConditionsMap.all` | (helper) evaluate order D, N, A | Equivalent | No Go counterpart. Used only in `WF`. |
| `Condition.valid` | conditionsmap.go:196-216 | Equivalent | `utf8ByteSize` is the same number as Go `len()` for every Lean-representable (valid UTF-8) string. `CondType.length == 0` vs `len(type) != 0`: both are zero exactly for `""`, so it does not matter that one counts chars and the other bytes. Invalid UTF-8: see the gap row. |
| `validateConditions` | conditionsmap.go:187-219 | Equivalent | Check order matches: dup, id, size, type, desc. Go inserts the ID into `seenIDs` before the format checks (:194). Lean inserts after all checks. This is unobservable, because any later failure aborts the whole constructor and `seenIDs` is local to it (:164). Duplicates within one list and across lists are both caught, because `seen` is threaded through D → N → A. |
| `ConditionsMap.WF` | properties.md §1.2 | Equivalent | Matches `WFMap` clause for clause. |
| `ConditionsAwareDecision` (inductive) | conditions.go:60-68 | Abstraction | #5, #6. For maps/unions Lean has no `reason`/`err` fields. Go leaves them zero (conditionsmap.go:176-184, conditionsunion.go:176-184), so `Reason`/`Error` agree. The union caches are discussed in the `PossibleDecisions` row. |
| `ConditionsAwareDecisionDeny/Allow/NoOpinion` | conditions.go:71-97 | Equivalent | |
| `ConditionsAwareDecisionFromParts` | conditions.go:102-118 | Abstraction | #8: the `default` branch (Deny + `NewAggregate([err, unknown])`, err non-nil) is unreachable. For the three real values the variant, reason and err (including nil-ness) are passed through unchanged. |
| `zero` | conditions.go:57,73-75 | Equivalent | |
| `IsAllow/IsNoOpinion/IsDeny/IsConditionsMap/IsUnion` | conditions.go:121-151 | Equivalent | |
| `IsUnconditional` | conditions.go:154-156 | Equivalent | |
| `ConditionsAwareDecision.ConditionsMap` | conditions.go:143-145 | Equivalent | The non-map variants carry the zero `ConditionsMap{}`, and so does Lean's `{}`. |
| `UnionedDecisions` | conditions.go:246-254 | Equivalent | `d.union.inner` is nil for non-unions. |
| `Reason` | conditions.go:259-261 | Equivalent | |
| `Error` | conditions.go:266-268 | Equivalent | |
| `ContainsUnconditionalAllowOrDeny` (+ `go`) | conditions.go:233-241; conditionsunion.go:75-77,108-110 | Equivalent | Go reads the cached flag. The only constructor of a union value is `ToDecision` (grep: conditionsunion.go:177 is the sole `conditionsAwareDecisionTypeUnion` literal), and it copies the builder flag. `Reachable.cua_eq` (conditionsunion_properties.lean) proves that flag = `go inner` for every reachable builder, including after `Add` no-ops, because the no-op neither appends nor updates the flag. |
| `PossibleDecisions` (+ `subPD`) | conditions.go:204-217; conditionsunion.go:116-129 | Equivalent | Go uses the cached `subDecisionsPossibleDecisions`, which is `.Clone()` of the builder set (:182). `Clone()` of nil gives an empty set; both are treated as ∅ at :121. `Reachable.sub_eq` proves cache = `subPD inner`, including through `Add` no-ops, which skip the `Insert` at :83 just as they skip the append at :78. `Reachable.PD_eq` closes the loop. Recursive children use their own caches, which are equal by induction. |
| `FailureDecision` | conditions.go:224-229 | Equivalent | Union variant: conditionsunion.go:98-103 goes through the same `PossibleDecisions`, so it is equal by the row above. |
| `UnconditionalPartsOrError` | conditions.go:162-173 | Equivalent | The conditional branch gives `(FD, "failed closed", some _)`; Go uses `fmt.Errorf`, which is non-nil. The error text differs (abstracted). The unconditional branches pass `d.Error()` through, keeping its nil-ness. Doc nit: the doc says `162-176`. |
| `UnconditionalPartsOrFailClosed` | conditions.go:181-198 | Equivalent | The conditional branch gives `(FD, non-empty reason, none)`, as in Go (:196). The reason omits the `%v` PD list (#1). |
| `dec?` | (helper) | Equivalent | |
| `ConditionsAwareDecisionConditionsMap` | conditionsmap.go:138-185 | Equivalent | Branch order checked for each case in the brief, see the notes below the table. |
| — `ConditionsAwareDecision.String` | conditions.go:270-321 | Gap | Not modelled. No property depends on it. |
| — `AuthorizerFunc` (Authorize/CAA/EvaluateConditions) | interfaces.go:133-145 | Gap | Not modelled. P-10 and P-11 are catalogued "Lean: no"; no theorem depends on them. |
| — `GenericCondition.Evaluate` nil ⇒ Unevaluatable | conditionsmap.go:249-254 | Abstraction | Absorbed into the single oracle `p` (#2). Theorems quantify over all `p`, so this is subsumed. |
| — Go strings with invalid UTF-8 in `Condition` fields | conditionsmap.go:202,214 (`len`) | Gap | A Lean `String` is always valid UTF-8, so a Go condition carrying raw invalid bytes (possible from an in-process authorizer, but not from JSON decoding, which substitutes U+FFFD) has no Lean counterpart. All byte checks are exact on the representable subset. No theorem relies on representing such strings, and P-13's `valid` is about representable values. |

Notes on `ConditionsAwareDecisionConditionsMap`, for each case in the brief:
- **0 conditions:** the `conditionsAmount == 0` branch runs first and returns `noOpinion "no conditions" (some _)`, matching :150-153. `makeFailClosedError` is not used, as in Go.
- **More than 128 conditions, no Deny:** the `> 128` branch runs before the NoOpinion-only check and returns `makeFailClosedError` = `noOpinion "failed closed" (some _)`, matching :154-156. With D = A = [] and 129+ N conditions, this also gives NoOpinion with a non-nil error, as in Go.
- **NoOpinion-only with invalid IDs, 1 to 128 conditions:** returns `noOpinion … none` with no validation, matching :160-162.
- **Duplicates across lists:** one `seen` list is threaded through D, then N, then A (:164-174), and the first error wins. `hasDenyEffect` depends only on `D ≠ []`, so a duplicate inside N or A still fails closed to Deny whenever D is non-empty, matching Go.

## Divergences

None found. For each Lean definition in scope I compared the decision, PD, FD, error nil-ness and structure for every branch, and found no input where they differ from Go.

Two optional hardening proposals. Neither is a fix, since nothing is wrong:

1. Make the union-cache equivalence visible from `conditions.lean`. The `union` doc comment could cite `Reachable.cua_eq` / `Reachable.sub_eq` / `Reachable.PD_eq` (conditionsunion_properties.lean), so a reader of `PossibleDecisions` sees that the recomputation is proven equal to Go's cache:
   ```lean
   /-- … Go reads cached copies of `go l` and `subPD l`; their equality with this
   recomputation for every builder-emitted union is `Reachable.cua_eq`/`Reachable.sub_eq`
   (`conditionsunion_properties.lean`). -/
   ```
2. Line-number doc nits (see the table): `Decision.String` 244-257 → 244-255; `ConditionsData` 313-348 → 313-345; `ConditionsMap` 34-47 → 34-43; iterators 65-99 → 65-97; `ConditionsMap` accessor 143-146 → 143-145; `UnconditionalPartsOrError` 162-176 → 162-173. In interfaces.lean the module doc cites `interfaces.go:298-310` for oracle purity, but the purity contract is at :276 and :293-294 (298-310 are the `EvaluateConditionFunc` type declarations). Also, catalogue §1.1 cites `interfaces.go:259-269` for Decision (actual: 229-242) and `:280-311` for Condition (actual: 257-296).

## Theorem statement review

- `P_1_zero_is_deny`: **matches** P-1.
- `P_35_noOpinion_possible_iff`: **stronger** than P-35 (all trees, not only WF). Sound, because the PD/cua clauses are total.
- `P_3_possibleDecisions_nonempty`, `P_3_Len_pos`, `P_3_Len_le_three`: **stronger** (all trees). The `⊆ {D,A,N}` part holds by the type.
- `P_5_failureDecision_spec`, `ConditionsMap.FailureDecision_spec`: **match** P-5 for the CAD and the map. The builder half of P-5 is in conditionsunion_properties.lean, which is outside this scope.
- `P_9_splitters_unconditional`: **matches**.
- `P_9_splitters_conditional`: **matches**, and adds `≠ Allow`. The catalogue says "Lean: no", so the Lean is ahead of the catalogue.
- `P_13_mkMap_WF`: **matches** P-13, and additionally proves `m = (D,N,A)`.
- `P_14_mkMap_ne_allow`: **matches** "never yields Allow".
- `P_14_mkMap_fallback`: **weaker** than P-14. It fixes the variant (deny ⇔ D ≠ []) but says nothing about error nil-ness. The catalogue states `noOp(err≠nil)` for total = 0 (proved separately by `P_14_mkMap_empty`) and `fc(err)` with err ≠ nil on the >128 and invalid branches, which no theorem states. Either the Lean is too weak or the catalogue should be explicit; the model itself has `some err` on every `makeFailClosedError` path. Proposed addition:
  ```lean
  theorem P_14_mkMap_fallback_err (D N A : List Condition)
      (h : (ConditionsAwareDecisionConditionsMap D N A).IsConditionsMap = false)
      (hN : ¬ (D = [] ∧ A = [] ∧ D.length + N.length + A.length ≠ 0
               ∧ D.length + N.length + A.length ≤ MaxConditionsPerMap)) :
      (ConditionsAwareDecisionConditionsMap D N A).Error.isSome = true
  ```
- `P_14_mkMap_empty`: **matches**. It states `some e`, i.e. a non-nil error.
- `P_14_mkMap_noOpinion_only_skips_validation`: **matches**. The hypotheses `N ≠ []` and `|N| ≤ 128` are exactly the catalogue's `1 ≤ total ≤ 128` with D = A = [].
- `P_15_map_PD`: **matches**.
- `P_15_map_Len`, `P_15_mkMap_Len`: **match**. The WF hypothesis is the catalogue's.
- `P_15_map_Len_not_all_maps`: extra negative for non-WF maps. Correct, and it does not contradict the catalogue.
- `P_4_unconditional_iff_singleton`: **matches** (WF).
- `P_4_not_all_trees`: extra negative for arbitrary trees. Correct, but its `-- status: does NOT hold` comment conflicts with the README convention that this marker means the *catalogued* property fails. P-4 holds as catalogued. **Doc nit:** reword to `-- note: fails only outside WF`.
- `P_6_failureDecision_ne_allow`: **stronger** (all trees).
- `P_6_failureDecision_mem_WF`, `P_6_failureDecision_allow`: **match** P-6.
- `P_6_failureDecision_mem_of`: an auxiliary generalisation. Fine.
- `P_6_not_all_trees`: extra negative. Correct, with the same status-marker doc nit as `P_4_not_all_trees`.
- `WF` (inductive): matches §1.3 `WFUnion` clause by clause. `l.dropLast` encodes `∀ i < k`. `WF_mkMap` and `WF_of_FromParts` check that it is closed under the public constructors.

## Axioms

None in `interfaces.lean`, `conditionsmap.lean`, `conditions.lean` or `conditions_properties.lean`. The only non-definitional constants are the `opaque` declarations `ConditionsData`, `IsDomainPrefixedKey` and `IsDNS1123Subdomain`. `opaque` asserts nothing beyond the type being inhabited (and `Bool` / the opaque type are inhabited), so these declarations cannot make the model inconsistent.

## Verdict

The authorizer-core model is a faithful, branch-for-branch model of `interfaces.go`, `conditionsmap.go` and `conditions.go`. It covers:
- the check order and fail-closed effect of `ConditionsAwareDecisionConditionsMap`;
- the check order of `validateConditions`, with byte-length semantics exact on valid UTF-8;
- the nil-ness of the errors returned by both splitters;
- the `DecisionSet` operations.

For the union variant, Lean recomputes the flag and PD set that Go caches. That is sound: Go builds union values only through `ToDecision`, and the builder invariant `Reachable.inv` proves the cache equals the recomputation through `Add` no-ops.

The remaining differences:
- Abstractions already declared in the README.
- Two unmodelled functions with no dependent property: `String` and `AuthorizerFunc`.
- The unrepresentable invalid-UTF-8 strings.
- One weak theorem, P-14: error nil-ness on the fail-closed branches is not stated.

The model is trustworthy for every property it proves in this scope.
