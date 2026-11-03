# encoding

Lean: `lean/encoding/encoding.lean`, theorem statements of `lean/encoding/encoding_properties.lean`.
Go: `staging/src/k8s.io/apiserver/pkg/apis/authorization/v1/encoding.go` (whole file),
`staging/src/k8s.io/api/authorization/v1/types.go:432-625`.

Build: `lake build encoding.encoding encoding.encoding_properties` succeeds. No `sorry` and no `axiom` in
either file. Both `ToAuthorizerConditionsAwareDecision` and `FromAuthorizerConditionsAwareDecision` are
ordinary (structurally recursive, non-`partial`) definitions.

| Lean def | Go file:line | verdict | note |
|---|---|---|---|
| `ConditionsAwareDecisionType` (+ `abbrev` constants) | types.go:511-537 | Abstraction | Go has an open `string`. Lean uses 5 constructors plus `unknown s`. Every Go value can be represented. Lean also has redundant values with no Go counterpart: `unknown "Deny"`, `unknown "Allow"`, … are distinct from `.Deny` and the rest, and they decode to `failClosed`. That is harmless only if the Go→Lean embedding always maps the five known strings to their constructors. The module doc says this, but no theorem enforces it (see Theorem statement review, P-58/P-57 unknown). |
| `ConditionsAwareDecisionType.String` | types.go:518-536 | Equivalent | Message text only (`%q` is approximated by a hand-written `\"…\"`). |
| `UnconditionalDecision` | types.go:612-625 | Equivalent | |
| `Condition` | types.go:432-468 | Equivalent | All four string fields are present. |
| `ConditionsMap` | types.go:470-509 | Abstraction | nil and empty slices are both `[]`. This is unobservable to the decoder (Go uses only `len`/`range`, encoding.go:154-165, and the constructor uses only `len`). It does make the P-57 class "nil vs empty condition slices" unstatable. |
| `ConditionsAwareDecision` / `NamedConditionsAwareDecision` (mutual) | types.go:539-610 | Abstraction | Pointers are `Option` and slices are `List`. Everything the brief asks about can be represented: `Type=ConditionsMap` with a nil map, `Type=Union` with `[]`, and members inconsistent with `Type` (every combination of the 5 members with every `Type`). Union nil vs empty is not distinguished, which is unobservable to the decoder. Go can build cyclic values (a slice element whose `Decision.Union` aliases the slice). Lean cannot represent them, and Go would recurse forever on them. They cannot arrive over JSON or protobuf, so nothing here depends on them. |
| accessors `«Type»`, `Deny`, `NoOpinion`, `Allow`, `ConditionsMap`, `Union`, `AuthorizerName`, `Decision` | types.go:546-609 | Equivalent | Field line numbers checked; all are correct. |
| `ConditionsAwareDecision.lit` | (Go composite literal with omitted fields) | Equivalent | Omitted pointers are `none` and the omitted `Union` is `[]`, which matches Go nil (nil vs empty is indistinguishable, see above). |
| `fromAuthorizerConditions` | encoding.go:96-107 | Equivalent | Order is preserved and the result is always a list (Go: non-nil `[]`). |
| `errString` | encoding.go:32-35 | Equivalent | `some ""` gives `""`, the same as Go `err.Error()==""`. |
| `FromAuthorizerConditionsAwareDecision` | encoding.go:31-94 | Equivalent | Branch order checked: IsDeny, IsNoOpinion, IsAllow, IsConditionsMap, IsUnion. The variants are mutually exclusive, so the order does not matter. Each variant sets only its own member pointer, and `Reason` and `EvaluationError` come from that variant's fields. Map lists are always present. The `default` branch (:82-92) is unreachable because the Lean variant type is exact (README Abstraction 8). In Go it is also unreachable, since the tag is unexported and the zero value is Deny. |
| `FromAuthorizerConditionsAwareDecision.go` | encoding.go:71-77 | Equivalent | Children are encoded in `UnionedDecisions()` order (conditions.go:246-254 iterates `inner`). Doc nit: the doc says `:70-76`; the loop is at :71-77. |
| `UnconditionalEvaluationError` | encoding.go:110-115 | Equivalent | `none`, or an empty string, gives no error; otherwise `some s` (`errors.New(s)`). `String.length` (code points) vs Go `len` (bytes) does not matter, because the code only tests for zero. |
| `UnconditionalReason` | encoding.go:118-123 | Equivalent | |
| `toAuthorizerConditions` | encoding.go:154-165 | Abstraction | `GenericCondition{…}` with `EvaluateFunc = nil`. This is README Abstraction 2 (oracle folding), and the loss is acknowledged in P-56. Doc nit: the doc says `:154-163`; the function ends at :165. |
| `ToAuthorizerConditionsAwareDecision` | encoding.go:126-152 | Equivalent | The switch on `Type` only: Allow uses the `allow` member, Deny the `deny` member, NoOpinion the `noOpinion` member. Other members are ignored, as in Go. For `ConditionsMap`: `some m` gives the constructor over the three converted lists; `none` gives the constructor over `[] [] []`, which matches Go `(nil,nil,nil)` because the constructor uses only lengths. For `Union`: a fresh builder `{}` (all fields match the Go zero value; the nil `sets.Set` is modelled as `.empty`), then `Add` for each child in order using the recursive decode with the same `fc`, then `ToDecision`. Unknown types give `fc err`. The decoder never calls `fc` except in the `unknown` branch, including inside nested children, which matches Go. |
| `ToAuthorizerConditionsAwareDecision.go` | encoding.go:144-147 | Equivalent | Builder state is threaded left to right, so the no-op-after-cua behaviour of `Add` is preserved. |

Summary: Equivalent 13, Divergence 0, Abstraction 4, Gap 0. The gaps are in the theorem coverage, not in the model (see below).

Line-number doc nits:
- `FromAuthorizerConditionsAwareDecision.go` cites `:70-76`; the loop is at :71-77.
- `toAuthorizerConditions` cites `:154-163`; the function is :154-165.
- The decoder section header cites `109-163`; it should be 109-165.
- The `ConditionsAwareDecisionType` comment starts at :511, not :510.

None of these change any meaning.

## Divergences

None found. Every branch of both functions was traced against Go, including:
- the nil-pointer and empty-string handling;
- the ConditionsMap nil-map path;
- member pointers inconsistent with `Type`, which both implementations ignore;
- union child order and builder threading;
- the placement of `failClosed`.

Proposed hardening (not a divergence). Rule out the redundant `unknown "<known>"` values so that theorems quantified over `unknown s` cannot be read as claims about Go's `"Deny"` and the other known strings:

```lean
/-- The Go string → Lean embedding; the only way a decoded `Type` should be built. -/
def ConditionsAwareDecisionType.ofString : String → ConditionsAwareDecisionType
  | "Deny" => .Deny | "Allow" => .Allow | "NoOpinion" => .NoOpinion
  | "ConditionsMap" => .ConditionsMap | "Union" => .Union | s => .unknown s

/-- A Lean `Type` value that is the image of a Go string. -/
def ConditionsAwareDecisionType.Canonical (t : ConditionsAwareDecisionType) : Prop :=
  ∀ s, t = .unknown s → ofString s = .unknown s
```

Then add `(hs : ConditionsAwareDecisionType.ofString s = .unknown s)` to `P_58_unknown_failClosed` and `P_57_unknown_type`. The proofs do not change; only the reading becomes faithful.

## Theorem statement review

- `P_58_decoder_total`: matches, but the statement is vacuous (`∃ d, dec v fc = d`). The real evidence for totality is that the definition is non-`partial` and structurally recursive, which holds.
- `P_58_unknown_failClosed`: matches "unknown type ⇒ `fc(err)`". It is slightly over-general (it also covers `unknown "Deny"`, which is not a Go value); see the hardening above.
- `P_58_map_independent_of_failClosed`: matches "independent of failurePolicy" for `type=ConditionsMap`.
- `P_58_map_never_allow`: matches, via P-14.
- P-58 as a whole is weaker than the catalogue. The clause "invalid maps ⇒ constructor fail-closed (`deny` iff deny conditions were present)" is not stated. Proposed statement, which is true of the model:
  ```lean
  theorem P_58_map_failclosed_by_effect (dn nn an u) (m : ConditionsMap) (fc) :
      let d := dec (.mk .ConditionsMap dn nn an (some m) u) fc
      d.IsConditionsMap = false → (d.IsDeny = true ↔ m.DenyConditions ≠ [])
  ```
- `P_56_roundtrip_deny` / `_allow` / `_noOpinion`: these match the catalogue, and are stronger in one respect: they hold for every error and state the loss exactly as `normErr`.
- `P_56_roundtrip_unconditional_exact`: matches. The extra hypothesis `d.Error ≠ some ""` corresponds exactly to the catalogue's stated loss.
- `P_56_roundtrip_empty_error_lost`: a correct positive witness of the documented loss (`dec(enc(deny r (some ""))) = deny r none`). This is a sound reading of "not the identity".
- `P_56_roundtrip_map`: matches. The hypothesis `m.WF` is necessary and sufficient for constructor acceptance: 0 conditions, more than 128, NoOpinion-only, an invalid condition or a duplicate across lists each makes the constructor reject the map. `1 ≤ Length` is redundant given `deny ≠ [] ∨ allow ≠ []`, but that is harmless.
- `P_56_roundtrip_union`: matches WFUnion (§1.3). `_hk : l ≠ []` is unused and implied by `hPD`, since `[]` has PD = {N} and therefore Len 1. The other hypotheses are all needed:
  - names non-empty, DNS-1123 and distinct (otherwise `errs ≠ []` and the decision fails closed);
  - `NoCuaBeforeLast` (otherwise later children are dropped);
  - `|PD| ≥ 2` (otherwise the union folds);
  - every child round-trips (the recursion).
- `P_56_roundtrip` (with `RoundTripWF`): this is the catalogue's WF plus "no unconditional leaf has error `some ""`" at every depth. That side condition is stronger than the catalogue's formal line `∀ WF d`. It is stated openly in the doc comment ("WF plus no error is `some ""`") and corresponds to the loss the catalogue lists. The catalogue's formal line is itself imprecise: its ≅ includes `Error()?.Error()`, so it does not actually hold for `some ""`. Neither the catalogue nor the Lean is wrong, but the full-WF version can be stated without the extra hypothesis:
  ```lean
  def normAll : authorizer.ConditionsAwareDecision → authorizer.ConditionsAwareDecision
    | .deny r e => .deny r (normErr e) | .allow r e => .allow r (normErr e)
    | .noOpinion r e => .noOpinion r (normErr e) | .conditionsMap m => .conditionsMap m
    | .union l => .union (l.map fun (n, c) => (n, normAll c))   -- (needs a `go` helper)
  theorem P_56_roundtrip_WF (d) (h : WF d) (fc) : dec (enc d) fc = normAll d
  ```
  Caveat: PD and cua are unchanged by `normAll`, so the union hypotheses carry over.
- `P_57_map_all_empty`, `P_57_map_nil`, `P_57_map_noOpinion_only`, `P_57_map_cross_list_duplicate`, `P_57_union_empty`, `P_57_unknown_type`, `P_57_unconditional_nil_member`: each matches its catalogue class. Each is a correct negation (`enc (dec v fc) ≠ v` for an explicit `v`, or for all `v` in the class). The noOpinion-only and cross-list theorems hold for an arbitrary condition `c`, which matches the catalogue's claim that validity does not matter. `P_57_unconditional_nil_member` covers only `Allow`. Deny and NoOpinion are symmetric but not stated.
- P-57 coverage is partial, so the catalogue's word "exhaustive" is not reflected in Lean. These classes have no theorem:
  - more than 128 conditions in total;
  - invalid id, type or size;
  - a foldable union (e.g. `[Map{allow}, Allow]`);
  - children after a cua child;
  - empty, duplicate or non-DNS-1123 union names;
  - a member set besides the one named by `type`;
  - nil vs empty slices (unrepresentable by design, see `ConditionsMap` above).
  
  All except the last can be represented. The "extra member ignored" class is a one-line `rfl`, for example `dec (.mk .Allow dn nn an cm u) fc = dec (.lit .Allow (Allow := an)) fc`, and should be added because the brief singles it out.
- Helper defs `normErr`, `NoCuaBeforeLast`, `RoundTripWF`: these are faithful to `encoding.go:33-35,111`, `conditionsunion.go:59-61` and §1.3 WFUnion respectively. `RoundTripWF.go` recurses into every child, as required by "∀i. WF(cᵢ)".

## Axioms

None in `encoding.lean` or `encoding_properties.lean`.

## Verdict

The v1 types and both codec functions are a faithful model of `encoding.go`. Every branch was checked, no divergence was found, and the abstractions cannot be observed by the decoder:
- nil vs empty slices;
- `EvaluateFunc` dropped;
- the unreachable encoder `default`;
- the redundant `unknown "<known>"` tags.

The model can represent all the malformed v1 shapes that matter (nil map, empty union, inconsistent members, nil member pointers), and the decoder ignores the members not named by `Type`, as Go does. The P-56 theorems are proved without `sorry` or axioms. They are at least as strong as the catalogue, with one side condition (no `some ""` error at any leaf) that is openly stated and corresponds to the catalogue's own listed loss. The P-58 theorems omit the "deny iff deny conditions present" clause, and P-57 covers 7 of roughly 14 classes. The model is trustworthy for what it proves. The remaining work is coverage, not correctness.
