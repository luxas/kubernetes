# union

Scope: `lean/union/union.lean` (all definitions) and the theorem statements of
`lean/union/union_properties.lean`, against
`staging/src/k8s.io/apiserver/pkg/authorization/union/union.go` (read in full, 231 lines).
Helpers these rely on and that I checked against Go: `ConditionsAwareDecisionUnion.Add` /
`ToDecision` / `PossibleDecisions` (`authorizer/conditionsunion.lean` vs
`conditionsunion.go:58-185`), `ConditionsAwareDecision.{IsUnion, UnionedDecisions,
ContainsUnconditionalAllowOrDeny, PossibleDecisions, FailureDecision}` (`conditions.go:224-254`),
`aggregate` (`utilerrors.NewAggregate`: `[] ↦ nil`).

Build: `lake build union.union union.union_properties` succeeds. No `sorry`, `admit`, `axiom`
or `native_decide` in either file.

| Lean def | Go file:line | verdict | note |
|---|---|---|---|
| `Attributes` | `interfaces.go` (Attributes) | Abstraction | Opaque; README 3/9. |
| `Authorizer` | `interfaces.go:80-124` | Abstraction | Three independent pure functions, no `ctx`. The three methods are NOT tied together (P-10 is not assumed), which suits the adversarial P-44. A nil interface value cannot be expressed (see Gap below). |
| `NamedAuthorizer` | `union.go:47-53` | Equivalent | |
| `unionAuthzHandler` | `union.go:41-45` | Abstraction | `map[string]Authorizer` as an association list. Go's type is unexported, so a value only comes from `New` (or the zero literal at `:39`); the Lean structure can be built with any `nameToAuthorizer`, even one unrelated to `chain`. Harmless: P-44/45/46/47 quantify over arbitrary `h` (stronger), and `P_46_New_lookup` ties the table to `New`. |
| `lookup` | `union.go:63,189` | Equivalent | `find?` returns the first match. Go maps hold one value per key, and `New` rejects duplicates before inserting, so the table built by `New` has unique keys and first-wins vs last-wins never shows up (`P_46_New_lookup` proves `lookup = first chain entry with that name`). Only differs from a Go map on hand-built tables with duplicate keys, which Go cannot produce. |
| `buildNameToAuthorizer` | `union.go:57-68` | Equivalent | Per handler, in order: empty name → error (`:59-61`), duplicate among earlier names → error (`:63-65`), insert (`:67`). No DNS-1123 check, same as Go. `String.length == 0` is equivalent to Go `len == 0` (both mean empty). |
| `New` | `union.go:56-73` | Equivalent | `chain` is the input list unchanged; on error Go returns `nil, err` and Lean returns `.error`. |
| `appendErr` | `union.go:85-87, 176-178` | Equivalent | |
| `appendReason` | `union.go:88-90, 179-181` | Equivalent | `name: reason` only when the reason is non-empty. |
| `authorizeLoop` | `union.go:82-99` | Equivalent | Accumulates err/reason BEFORE the switch, as Go does. The first Allow/Deny returns `(decision, reason, err)` exactly as the child gave them; otherwise `(N, join "\n", aggregate)`. Earlier errors are dropped on Allow/Deny, same as Go. |
| `unionAuthzHandler.Authorize` | `union.go:76-100` | Equivalent | Empty accumulators; an empty chain gives `(N, "", none)`, same as Go. |
| `caaLoop` | `union.go:107-122` | Equivalent | Calls `Add` first, then checks `ContainsUnconditionalAllowOrDeny` on the CHILD decision (`:118`) and returns early with `ToDecision`. Go's own no-op `Add` after a cua child never runs because of the early return; Lean has the same behaviour. |
| `unionAuthzHandler.ConditionsAwareAuthorize` | `union.go:104-127` | Equivalent | Go's zero builder (`subDecisionsPossibleDecisions == nil`) and Lean `{}` (`.empty`) give the same PD `{N}`. |
| `unionAuthzHandler.evaluateConditions` | `union.go:188-194` | Equivalent | A missing name gives `(FD(sub), "failed closed", some err)`, using the SUB-decision's FD. |
| `unionAuthzHandler.evaluateAndClamp` | `union.go:160-165` | Equivalent | The clamp tests `PD(sub)` and falls back to `FD(sub)` with an error, as Go does. A missing name runs through the clamp too, as in Go. |
| `unionAuthzHandler.evalChild` | `union.go:147-168` | Equivalent | deny/allow leaves pass `(D/A, Reason, Error)` through unchanged. Go returns at once (`:152-155`); Lean returns the triple and `evaluateLoop`'s match returns it, so the result is identical. noOp is collected; map/union are delegated and clamped. The `default` branch (`:166-167`) is unreachable (README 8). |
| `evaluateLoop` | `union.go:144-185` | Equivalent | The second switch (`:170-182`) runs on the post-clamp decision, so a clamp to `FD(sub)=Deny` returns Deny, as in Go. NoOpinion appends err and `name: reason`. At the end: `(N, join "\n", aggregate)`. Iterates in `inner` order (Go's `UnionedDecisions` keeps order, `conditions.go:246-254`). |
| `unionAuthzHandler.EvaluateConditions` | `union.go:131-186` | Equivalent | A non-union input gives `(FD(input), "failed closed", some err)` (`:134-136`). |
| `unionAuthzHandler.toAuthorizer` | `union.go:39` | Equivalent | |
| (not modelled) `NewRuleResolvers` / `RulesFor` | `union.go:196-231` | Gap | Out of scope by design. No catalogued property depends on it. |
| (not modelled) nil `Authorizer` in chain | `union.go:49,67,83,114,193` | Gap | `New` does not reject a nil `Authorizer` (only the doc comment forbids it); Go then panics at the call. Lean cannot express nil. No property depends on it: P-44's "arbitrary sub-authorizers" means arbitrary answers, not panics. |

Doc nits (wrong line numbers in Lean doc comments):
- `unionAuthzHandler` says `union.go:40-44`; the type is at `:41-45`.
- `NamedAuthorizer` says `:46-53`; it is at `:47-53`.
- `lookup` says `:62,189`; the map read is at `:63`.
- `New` says `:56-74`; it is at `:56-73`.
- `appendErr` / `appendReason` say `:86-88` / `:89-91`; they are at `:85-87` / `:88-90`.
- `Authorize` says `:77-100`; it starts at `:76`.
- `toAuthorizer` and the module doc say `:38`; the assertion is at `:39`.
- `Authorizer.Authorize` says `interfaces.go:94`; the method is at `interfaces.go:87`, in `UnconditionalAuthorizer`.
- Catalogue nit: properties.md marks P-45, P-46 and P-47 as "Lean: no" and P-42 as "Lean: no". All four now have theorems.

## Divergences

None found. Branch by branch, the model matches `union.go` on decision, PD/FD, whether the
error is nil, and structure. Checked points:
- `New` checks only empty and duplicate names, not DNS-1123.
- `Authorize` returns the first Allow/Deny exactly as the child gave it, aggregates `name: reason`
  only for non-empty reasons, and aggregates errors.
- `ConditionsAwareAuthorize` calls `Add`, then returns early on cua of the child.
- `EvaluateConditions` and `evaluateConditions`:
  - non-union input gives `FD(input)` plus an error;
  - a missing name gives `FD(sub)` plus an error;
  - the clamp uses `PD(sub)` and `FD(sub)`;
  - the second switch runs on the post-clamp decision;
  - all-NoOpinion results are joined with `\n` and their errors aggregated.

## Theorem statement review

- **`P_41_CAA_agrees_with_Authorize`**: matches. Hypotheses:
  - `LegacyLifted` is P-10's `zᵢ.CAA = FromParts ∘ zᵢ.Authorize`;
  - `Nodup` is "distinct";
  - `NameValid` is DNS-1123 plus non-empty. The extra non-empty conjunct is implied in Go and is
    needed only because `IsDNS1123Subdomain` is opaque (README 4).

  The conclusion compares the decision component only (`dec? = some …`), as catalogued. `h` is
  arbitrary, which is fine because neither method reads `nameToAuthorizer`.
- **`P_42_New_accepts_non_DNS1123`** (negative): mostly right, slightly weaker in form. Given any
  non-empty `n` that the opaque `IsDNS1123Subdomain` rejects, it shows:
  - `New [⟨n,z⟩]` succeeds;
  - for every `a`, CAA has a non-nil error and is not Allow;
  - the legacy `Authorize` allows when z is lifted and allows;
  - a child Allow becomes exactly `noOpinion "failed closed" (some _)`.

  All of this matches the catalogue (`PD_B={A}` ⇒ `FD_B = N`). Two caveats:
  - It is conditional on such an `n` existing. With the opaque predicate it is vacuous if
    `IsDNS1123Subdomain` is constantly true, so it does not by itself refute "New-valid ⇒ CAA
    well-behaved".
  - It is stated as an `∃` instance, not in the README's `¬ ∀ …` form.

  Proposed restatement, which follows directly from the current proof:
  ```lean
  theorem P_42_not_New_valid_implies_CAA_ok
      (hex : ∃ n, n.length ≠ 0 ∧ IsDNS1123Subdomain n = false) :
      ¬ ∀ (chain : List NamedAuthorizer) (h : unionAuthzHandler), New chain = .ok h →
          ∀ a, (h.ConditionsAwareAuthorize a).Error = none
  ```
  To prove it, instantiate with any `z`. `Attributes` is `opaque` and may be empty, so the `¬ ∀`
  form also needs a `[Nonempty Attributes]` hypothesis.
- **`P_44_EvaluateConditions_in_PD`**: stronger than the catalogue (good). It needs only `ChildWF`
  (`|PD(c)| ≥ 2` for union children), which is part of WF(u) via `∀i. WF(cᵢ)`. The outer union
  need not be WF: no `k ≥ 1`, name, or prefix-not-cua conditions. Both `h` and the sub-authorizers
  are arbitrary. The catalogue's second clause, "every error path returns `FD` of u or of a child,
  never A", is not stated as such. Only the never-Allow part is covered, by
  `P_44_never_allow_unless_possible`. Suggested addition: when the result comes from the union's
  own error paths (non-union, missing name, clamp), the decision equals `FD(u)` or `FD(c)`.
- **`P_44_never_allow_unless_possible`**: matches the fail-closed corollary. For non-union input
  the result is `FD`, which is never Allow. For a union, Allow requires `A ∈ PD`.
- **`P_44_needs_child_WF`** (negative): correct, and it does show what it claims. For
  `u = union [("x", union [("y", allow)])]`: `PD(inner) = {A}`, so `FD(inner) = N`. The name is
  missing, so the clamp falls back to N, and `N ∉ PD(u) = {A}`. Both conjuncts are proved by
  `rfl`/`decide`. Go's builder never emits this input (`ToDecision` folds the inner union to
  `allow`), so the theorem only justifies the `ChildWF` hypothesis; it shows no flaw reachable
  from Go. Side finding: the catalogue's P-44 proof sketch ("c conditional ⇒ c ≠ allow ⇒
  `FD(c) ∈ PD(c)`") is incomplete without `|PD(c)| ≥ 2` for nested unions. The Lean proof makes
  that dependency explicit.
- **`P_45_EvaluateConditions_short_circuit`**: matches, in extensional form. With a NoOpinion
  prefix, the first non-N child result is the loop's result whatever `post` holds. In a pure
  model this is the observable meaning of "not passed to their authorizer". It is stated on
  `evaluateLoop` with arbitrary accumulators rather than on `EvaluateConditions`; it carries over
  by unfolding (`es = rs = []`).
- **`P_46_routing_by_name`**: matches. Each child's result depends on the table only through
  `lookup … n`; `chain` is never read.
- **`P_46_nested_delegated_whole`**: matches "nested unions are delegated whole". The `hpd`
  hypothesis is needed, otherwise the clamp applies.
- **`P_46_New_lookup`**: matches "`nameToAuthorizer[n]` of this instance" for tables built by
  `New`: the first (and only) chain entry named `n`.
- **`P_47_NoOpinion_errors_propagate`**: matches. "N child carried an error" is read as the
  child's post-evaluation, post-clamp result having an error. That covers leaf noOp errors,
  delegated-evaluation errors and clamp/missing-name errors with fallback N, which is exactly
  what `union.go:176-178` appends. `∃ p ∈ l` is sound because a final N means every child was
  visited.

Definitions in the properties file:
- `ChildWF` is a faithful fragment of WFUnion (`|PD| ≥ 2`).
- `LegacyLifted` is P-10.
- `NameValid` is discussed under P-41.
- `Inv41` is a proof-internal invariant.

## Axioms

None in either file.

## Verdict

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

Neither undermines trust in the proved results.
