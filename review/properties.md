# KEP-5681 Conditional Authorization: properties catalogue (Stage 3e)

HEAD `57a6904a21a`. Paths are relative to the repo root. `A/` = `staging/src/k8s.io/apiserver/pkg/authorization/authorizer/`,
`S/` = `staging/src/k8s.io/apiserver/`. Every statement was re-checked against HEAD code by reading it; nothing was built or run.
Stage 2 P-statements are deduplicated into the catalogue; the mapping is in the Appendix.

Status vocabulary: **holds by construction** (types/unexported fields make it impossible to violate) / **holds, argued**
(proof sketch given, no test) / **holds, tested** / **does NOT hold** (counterexample given) / **unknown**.

---

# PART 1 — Abstract model of HEAD

## 1.1 Base types

- **Decision** `Dec = {D, A, N}` (Deny, Allow, NoOpinion). `A/interfaces.go:259-269` (Deny = 0 = zero value).
  Failure order on `{N, D}`: `N < D`. Permissiveness order used in safety statements: `D ≤ N ≤ A`.
- **Condition** `c = (id, type, expr, desc : String, ev₀ : Data → R4)`. `ev₀` is the condition's own `Evaluate`
  (`A/interfaces.go:280-311`; `GenericCondition.Evaluate` returns `U` when `EvaluateFunc = nil`, `A/conditionsmap.go:249-254`).
  Every condition decoded from the wire is a `GenericCondition` with `ev₀ ≡ U` (`S/pkg/apis/authorization/v1/encoding.go:154-163`).
- **EvalResult** `R4 = T | F | E(err) | U` (`A/evaluate.go:29-98`; zero value = `U`; `E(nil)` is normalised to
  `E("unspecified evaluation error")`, `:56-67`). `R3 = R4 \ {U}` is a *total* result.
- **Oracle**. A partial oracle is `p : Cond → R4`; a total oracle is `o : Cond → R3`. The code's effective per-condition
  result under fallback `f` is `r(c) = ev₀(c) if ev₀(c) ≠ U else (f ≠ nil ? f(c) : U)` (`A/evaluate.go:122-131`).
  The model folds `ev₀` and `f` into one oracle. **Axiom O1 (purity):** the oracle depends only on `(c, data)`, not on
  context, time or call count (contract only, `A/interfaces.go:298-310`).
- **valid(c)** :⇔ `domPrefixed(id) ∧ |expr| ≤ 10240 ∧ (type = "" ∨ domPrefixed(type)) ∧ |desc| ≤ 1024`, where
  `domPrefixed(s)` :⇔ `IsLabelKey(s) ∧ s` contains exactly one `/` (`A/conditionsmap.go:187-219`;
  `staging/src/k8s.io/apimachinery/pkg/util/validation/validation.go:125-144`). Treat as an opaque predicate in Lean.

## 1.2 ConditionsMap

`m = (D, N, A : List Cond)`. Well-formedness, exactly as the smart constructor enforces it (`A/conditionsmap.go:138-185`):

```
WFMap(D,N,A) :⇔ 1 ≤ |D|+|N|+|A| ≤ 128          -- :150, :154 (128 is TOTAL, not per list)
              ∧ |D|+|A| ≥ 1                    -- :160 (not NoOpinion-only)
              ∧ nodup(ids(D ++ N ++ A))        -- :164-174 with one shared seenIDs set (:191)
              ∧ ∀c ∈ D++N++A. valid(c)          -- :197-217
```

Smart constructor `mkMap(D,N,A)` (checks in this order; first failure wins):

```
fc(err)         = if D ≠ [] then Deny("failed closed", err) else NoOp("failed closed", err)       -- :140-146
total = 0       → NoOp("no conditions", err)                                                    -- :150-153
total > 128     → fc(err)                                                                       -- :154-156
D = [] ∧ A = [] → NoOp("only NoOpinion conditions always evaluate to NoOpinion", nil)           -- :160-162 (validation SKIPPED)
first invalid / duplicate condition, scanning D then N then A → fc(err)                         -- :166-174
otherwise       → Map(clone D, clone N, clone A)                                                -- :176-184
```

Deviation abstracted: only the first validation error is reported; error texts are not modelled. A nil `Condition`
panics (`GetID()` on nil interface, `:189`); the decoder never produces nil. Lean: precondition "no nil".

## 1.3 ConditionsAwareDecision (CAD)

```
inductive CAD
| deny (r : String) (e : Option Err) | allow (r) (e) | noOp (r) (e)
| map  (m : ConditionsMap)                 -- only via mkMap, so WFMap m
| union (l : List (Name × CAD))            -- only via the builder's toDecision
```

`A/conditions.go:27-99`; the variant tag is unexported (`:31-47`), the zero value is `deny("", none)` (`:36,57`).
Conditional variants carry `reason = ""`, `err = nil` (fields never set, `A/conditionsmap.go:176-184`, `A/conditionsunion.go:176-184`).

Derived functions (all mathematical, total):

```
uncond(d)  :⇔ d ∈ {deny, allow, noOp}                                                  -- conditions.go:155-157
cua(d)     (ContainsUnconditionalAllowOrDeny): allow/deny ↦ true; noOp/map ↦ false;
           union l ↦ ∃(n,c) ∈ l. cua(c)                                                 -- conditions.go:233-241; memo flag conditionsunion.go:75-77
PD(d)      deny ↦ {D}; allow ↦ {A}; noOp ↦ {N}
           map(D,N,A) ↦ {N} ∪ {A | A≠[]} ∪ {D | D≠[]}                                   -- conditionsmap.go:103-112
           union l ↦ ({N} ∪ ⋃ᵢ PD(cᵢ)) \ (if ∃i. cua(cᵢ) then {N} else ∅)             -- conditionsunion.go:116-129
FD(d)      = if D ∈ PD(d) then D else N                                                  -- conditions.go:224-229 (FailureDecision)
```

Union well-formedness for `union l` with `l = [(n₁,c₁)…(n_k,c_k)]` (what `toDecision` guarantees):

```
WFUnion(l) :⇔ k ≥ 1
            ∧ names nonempty, pairwise distinct, DNS-1123 subdomains    -- conditionsunion.go:63-72, :138-141
            ∧ ∀i < k. ¬cua(cᵢ)                                          -- Add no-op after cua, :59-61
            ∧ |PD(union l)| ≥ 2                                         -- not foldable, :144
            ∧ ∀i. WF(cᵢ)
```

## 1.4 Union builder (`A/conditionsunion.go`)

State `B = (inner : List(Name×CAD), errs : List Err, flag : Bool)`; `PD_B` and `FD_B` as for `union inner` (`:98-129`).

```
add(B, n, d) = if B.flag then B                                   -- :59-61 (no name validation either)
               else B{ errs  += checks(n, B.inner),               -- empty :63, duplicate :66, non-DNS-1123 :70
                       inner += [(n,d)],  flag ||= cua(d) }       -- :75-83
toDecision(B) =
  errs ≠ []         → FromParts(FD_B, "failed closed", agg(errs))                    -- :138-141
  PD_B = {X}        → X(join(", ", reasons_X), agg(errs_X))                           -- :144-171 ("fold")
                      where reasons_X/errs_X = depth-first over leaves of kind X,
                      formatted "n₁: n₂: {r}" and "n₁: n₂: e" (collectReasonsAndErrors :187-208)
  otherwise         → union(clone inner)                                              -- :176-184
```

## 1.5 Map evaluation (`A/evaluate.go:121-224`)

`phase(L, p)` scans `L` in order: on the first `T` return `Hit(c)`; otherwise return `(errs, unev)` = (the `E` results in
order, the `U` conditions in order) (`:197-224`).

```
pmap(m, p) =                                                      -- partiallyEvaluateConditionsMapInternal
  D ≠ [] : Hit c → deny(reasonOf c, nil)                 :138-143
           errs≠[] → deny("…errors…", agg errs)           :144-146
           unev≠[] → mkMap(unev, N, A)                    :147-149   (N, A not evaluated)
  N ≠ [] : Hit c → noOp(reasonOf c, nil)                 :158-161
           errs≠[] → noOp("…errors…", agg errs)           :162-164
           unev≠[] → mkMap([], unev, A)                   :165-168
  A ≠ [] : Hit c → allow(reasonOf c, nil)                :177-181   (earlier Allow errors discarded)
           errs≠[] → noOp("…errors…", agg errs)           :182-184   (errors win over U)
           unev≠[] → mkMap([], [], unev)                  :185-187
  else   → noOp("no conditions matched", nil)             :191
evalMap(m, o) = pmap(m, o)    for total o                 -- ConditionsMap.Evaluate :102-113 (no production caller)
```

Precedence: `Deny > NoOpinion > Allow`; within one effect `T > E > U > F`. Abstracted: reason texts, error wrapping
(`condition %q with effect=%s …`, `:217`), the unreachable `default` branch (`:219-221`). `ConditionsMap.Evaluate` panics if
its `evaluateConditionFn` is nil and some `ev₀` returns `U` (`:105`).

## 1.6 Partial evaluation over trees (`A/evaluate.go:235-282`)

```
peval(map m, p)   = pmap(m, p)
peval(union l, p) = loop over l with B := ∅, tail := false:                      :248-277
                      tail      → B := add(B, n, c)                               :252-255
                      ¬tail     → c' := peval(c, p); B := add(B, n, c')           :262-263
                                  cua(c')         → return toDecision(B)          :266-268
                                  ¬uncond(c')     → tail := true                  :271-273
                    return toDecision(B)                                          :277
peval(d, p)       = d  for uncond d                                               :278-280
```

## 1.7 Reference semantics ⟦·⟧ (the meaning every evaluator must agree with)

```
⟦deny⟧ₒ = D, ⟦allow⟧ₒ = A, ⟦noOp⟧ₒ = N
⟦map m⟧ₒ = dec(evalMap(m, o))
⟦union l⟧ₒ = seq(l)   where seq([]) = N,  seq((n,c)::t) = let r = ⟦c⟧ₒ in if r ≠ N then r else seq(t)
```

`seq` is the KEP's "first non-NoOpinion wins" (`kep.md:861-869`). It is what `union.EvaluateConditions` computes
(`S/pkg/authorization/union/union.go:131-185`) **given Axiom O2**: every named sub-authorizer's `EvaluateConditions(c, x)`
returns `⟦c⟧ₒ` for its own oracle `o`. The code does not trust O2: it clamps each sub-result into `PD(c)` (`union.go:161-165`).

## 1.8 Union authorizer (`union.go`)

```
Authorize(chain, a)       = first (dᵢ,rᵢ,eᵢ) with dᵢ ∈ {A,D}, returned verbatim (:83-93);
                            else (N, join("\n", ["nᵢ: rᵢ" | rᵢ≠""]), agg(eᵢ))                   :99
CAA(chain, a)             = B := ∅; for i: dᵢ := zᵢ.CAA(a); B := add(B,nᵢ,dᵢ); if cua(dᵢ) break;  :104-126
                            toDecision(B)
EvaluateConditions(u, x)  = ¬union u → (FD u, "failed closed", err)                             :134-136
                            for (n,c) ∈ u: deny/allow leaf → its parts                         :152-155
                                           noOp leaf → collect                                  :157-158
                                           map/union → r := z_n.EvaluateConditions(c,x);        :160-165
                                                       r ∉ PD(c) ⇒ (FD c, "failed closed", err)
                                                       z_n missing ⇒ (FD c, …, err)             :188-194
                                           r ∈ {A,D} → return; N → collect                      :170-182
                            (N, join("\n","n: r"), agg)                                         :185
```

Deviations from `seq`: reason/error aggregation; the routing table `nameToAuthorizer` is single-level (nested unions are
delegated whole to the named child).

## 1.9 Webhook authorizer (`S/plugin/pkg/authorizer/webhook/webhook.go`)

- `Authorize` (legacy; no `authorizationOptions` in the spec): `both → (D, r, err)`; `denied → (D, r, nil)`;
  `conditionalDecision ≠ nil → (FD(dec(cd)), r, err)`; `allowed → (A, r, nil)`; else `(N, r, nil)` (`:258-272`).
- `CAA`: advertises all five types iff `reviewer ≠ nil` (`:287-292`); reviewer is non-nil only if the gate was on at
  construction (`:152-157`). Malformed/unrequested response ⇒ `failPol(err)` = `noOp`/`deny("failed closed")` per
  `decisionOnError` (`:327-329`, `:349-354`); else `denied → deny(r, evalErr)`, `cd → dec(cd, failPol)`, `allowed → allow(r, evalErr)`,
  else `noOp(r, evalErr)` (`:337-346`).
- `EvaluateConditions(d, x)`: `uncond d ∨ x = nil → (FD d, err)` (`:430-439`); `d' := peval(d, p_b)` where
  `p_b = builtin` with `E ↦ U` (`:951-973`, map at `:968-970`); `uncond d' → parts(d')` (`:443-445`); else
  `ACR(d', x)` with guard `r ∈ PD(d')` else `(FD d', err)`, and every transport/validation/UID failure ⇒ `(FD d', err)`
  (`:453-563`). **Note:** ACR failures use `FD(d')`, not `decisionOnError`.

## 1.10 Encode / decode (`S/pkg/apis/authorization/v1/encoding.go`)

`enc : CAD → V1` (`:31-94`): unconditional ↦ `{type, X: {reason, evaluationError = e?.Error() or ""}}`; map ↦ three condition
lists (always non-nil, `:96-107`); union ↦ list of `(authorizerName, enc c)`. `dec(v, fc) : CAD` (`:126-152`):
unconditional ↦ constructor with `errors.New(evaluationError)` if non-empty; map ↦ `mkMap(…)` (nil map ↦ `mkMap([],[],[])`);
union ↦ fold of `add` then `toDecision`; unknown type ↦ `fc(err)`.

## 1.11 Filter + enforcer composition

```
Filter(req)   (S/pkg/endpoints/filters/authorization.go:143-221)
  d := classifier(a) ? z.CAA(a) : FromParts(z.Authorize(a))        :163-167
  ctx := attach(z, d)  (error if already attached)                 :170-174; request/context.go:92-100
  allow d          → next  (audit allow)                           :190-199
  A ∈ PD(d)        → next  (audit is-conditional=true)             :202-208
  err(d) ≠ nil     → 500;  else 403                                :210-220
Enforcer.Validate(attrs)   (S/pkg/admission/plugin/authorizer/conditionsenforcer/conditionsenforcer.go:78-142)
  gate off → nil;  no ctx tuple → error                            :80-88
  d ∈ {deny,noOp} ∨ A ∉ PD(d) → 500;  allow d → nil                :91-104
  x := NewVersionedAttributes(attrs, attrs.GetKind(), o)            :106
  (r,_,e) := z.EvaluateConditions(d, x);  r ∉ PD(d) ⇒ (D, err)      :112, :145-153
  r = A → nil (audit allow);  e ≠ nil → 500;  else 403              :116-141
Outcome(req) ∈ {proceed-to-storage, 403, 500}
```

Server wiring: the conditions-aware filter is installed iff gate on ∧ classifier ≠ nil ∧ enforcer plugin enabled
(`S/pkg/server/config.go:1077-1087`). kube-apiserver classifier: resource request ∧ verb ∈ {create, update, patch, delete,
deletecollection} ∧ GR not admission-excluded (`pkg/controlplane/apiserver/config.go:293-321`).

## 1.12 In-process CEL oracle (`S/pkg/admission/plugin/cel/authorization_conditions.go`, PR #143024, unmerged)

`p_cel(c) = U` if `c = nil ∨ type ≠ "authorizer.kubernetes.io/cel" ∨ expr = ""` (`:149-161`); `E` on compile/runtime error
(`:170-175`); else `T` iff the result is CEL `true` (`:177`). Built once per `EvaluatorForData(x, z)` call (`:76-120`), with a
per-call caching `UnconditionalAuthorizer` for compound checks (`:100-104`).

---

# PART 2 — Property catalogue

Format per property: informal · formal · status · code · test · Lean.
"WF d" means: d was produced by the public constructors (§1.2–1.4), which is the only way to obtain a CAD outside package
`authorizer` (`A/conditions.go:31-47`, tag unexported).

## A. Decision types

**P-1 Zero value is Deny.**
- Formal: `CAD{} = deny("", nil)`, `PD = {D}`, `FD = D`.
- Status: holds by construction (`A/conditions.go:36,57,131-133`). Test: `A/conditions_test.go:TestConditionsAwareDecision` (zero-value row).
- Lean: yes (fixes the default; trivial).

**P-2 Exactly one variant predicate holds.**
- Formal: `∀d. exactly one of IsAllow, IsDeny, IsNoOpinion, IsConditionsMap, IsUnion`.
- Status: holds by construction (tag only set at `A/conditions.go:75,84,93`, `A/conditionsmap.go:177`, `A/conditionsunion.go:177`; IsDeny is `tag = 0`).
- Test: `TestConditionsAwareDecision` (per-variant loop `A/conditions_test.go:1025-1100`). Lean: no (free from the inductive type).

**P-3 PD is a non-empty subset of {D,A,N}.**
- Formal: `∀ WF d. ∅ ≠ PD(d) ⊆ {D,A,N}`.
- Status: holds, argued (every clause of §1.3 inserts at least one element; the union clause removes N only when some `cua(cᵢ)`, and then that cᵢ contributes A or D by P-39). Code: `A/conditions.go:204-217`, `A/conditionsunion.go:116-129`.
- Test: hand-written rows only (`TestConditionsAwareDecision`). Lean: yes.

**P-4 Unconditional ⟺ singleton PD.**
- Formal: `∀ WF d. uncond(d) ⟺ |PD(d)| = 1`.
- Status: holds, argued: maps have `|PD| ≥ 2` (P-15), unions are only emitted when `|PD| ≥ 2` (`A/conditionsunion.go:144`).
- Test: `TestConditionsAwareDecision` (N-only fold, union folds). Lean: yes (needed by the fold theorems).

**P-5 FailureDecision is D or N, and D iff D is possible.**
- Formal: `FD(d) ∈ {D,N} ∧ (FD(d) = D ⟺ D ∈ PD(d))`. Same for the builder (`A/conditionsunion.go:98-103`) and the map (`A/conditionsmap.go:50-56`).
- Status: holds by construction (`A/conditions.go:224-229`). Test: property assertion in `TestConditionsAwareDecision` (`A/conditions_test.go:1082-1094`). Lean: yes (definitional).

**P-6 FailureDecision is a possible decision, except for Allow; it is never Allow.**
- Formal: `∀ WF d. FD(d) ≠ A`; `∀ WF d ≠ allow. FD(d) ∈ PD(d)`; `FD(allow) = N ∉ PD(allow)`.
- Status: holds, argued. If `D ∈ PD` trivially. Otherwise for map, `N ∈ PD` (P-15). For an unfolded union without D: `PD ⊆ {A,N}`, `|PD| ≥ 2` ⇒ `N ∈ PD`. Builder FD can be N with `PD_B = {A}` (error path, see P-38).
- Test: none as a stated property. Lean: yes.

**P-7 Conditional variants carry no reason or error; accessors on the wrong variant are empty.**
- Formal: `¬uncond d ⇒ Reason d = "" ∧ Error d = nil`; `¬IsConditionsMap d ⇒ ConditionsMap(d) = zero`; `¬IsUnion d ⇒ UnionedDecisions(d) = ∅`.
- Status: holds by construction (`A/conditionsmap.go:176-184`, `A/conditionsunion.go:176-184`, `A/conditions.go:143-145,246-254`).
- Test: iterator part `TestConditionsAwareDecisionUnionedDecisions`. Lean: no.

**P-8 FromParts is total and unconditional; unknown decisions map to Deny + error.**
- Formal: `∀x r e. uncond(FromParts(x,r,e))`; `x ∉ {D,A,N} ⇒ FromParts = deny(r, agg(e, unknown))`.
- Status: holds, tested (`A/conditions.go:102-118`; `TestConditionsAwareDecision` rows "42"). Lean: no.

**P-9 Splitters never yield Allow for a conditional decision.**
- Formal: `uncond d ⇒ OrError(d) = OrFailClosed(d) = (dec d, r, e)`; `¬uncond d ⇒ OrError(d) = (FD d, _, err≠nil) ∧ OrFailClosed(d) = (FD d, r≠"", nil)`.
- Status: holds, tested (`A/conditions.go:162-198`; `TestConditionsAwareDecisionUnconditionalParts`). `UnconditionalPartsOrFailClosed` has no production caller (shipped.md §3.1). Lean: no (follows from P-6).

**P-10 Lifting law: `CAA = FromParts ∘ Authorize` for conditions-unaware authorizers.**
- Formal: `∀ z ∈ {RBAC, Node, ABAC, alwaysAllow, alwaysDeny, privilegedGroup, AuthorizerFunc}. ∀a. z.CAA(a) = FromParts(z.Authorize(a))`.
- Status: holds by construction for those (`A/interfaces.go:139-141`; `plugin/pkg/auth/authorizer/rbac/rbac.go:133-135` and the other sites listed in pr-137204.md P1). **Does NOT hold for the webhook**: with no reviewer, a status `{denied or neither, evaluationError ≠ ""}` gives `Authorize → err = nil` but `CAA → Error ≠ nil` (`webhook.go:258-272` vs `:331-345`); and CAA validates the response while Authorize does not (`:327`).
- Test: `AuthorizerFunc` only (`TestConditionsAwareDecision`); webhook divergence untested. Lean: no (axiom about leaf authorizers).

**P-11 Unaware authorizers fail closed on EvaluateConditions.**
- Formal: `z` unaware ⇒ `z.EvaluateConditions(_,_) = (D, "", ErrorConditionEvaluationNotSupported)`.
- Status: holds by construction (`A/interfaces.go:143-145`). Combined with the union clamp this becomes `FD(c)` (P-44). Test: none. Lean: no (oracle for unaware leaves).

**P-12 CAD values are immutable after construction.**
- Formal: no operation reachable outside the package changes `PD(d)`, `UnionedDecisions(d)` or the condition lists of a constructed `d`; returned sets are fresh.
- Status: holds by construction, with caveats. Inputs cloned (`A/conditionsmap.go:180-182`); builder → result cloned (`A/conditionsunion.go:180-182`); `PossibleDecisions` returns fresh sets (`A/conditions.go:204-217`, `A/conditionsunion.go:119-128`); iterators expose no slice (`A/conditionsmap.go:65-97`, `A/conditions.go:246-254`); `v1/util.go` accessors return clones (`staging/src/k8s.io/api/authorization/v1/util.go:79-97`). Caveats: clones are shallow; `Condition` immutability is a documented contract only (`A/interfaces.go:280`), so a pointer-typed Condition can be mutated by its author; error values are shared.
- Test: `TestConditionsAwareDecisionConditionsMap_ClonesInputSlices`, `TestConditionsAwareDecisionUnion_AddAfterToDecisionDoesNotMutate` (`A/conditionsunion_test.go`). Lean: no (value semantics are free in Lean).

## B. ConditionsMap construction

**P-13 A constructed map is well-formed.**
- Formal: `mkMap(D,N,A) = map m ⇒ WFMap(m)` (§1.2).
- Status: holds, tested (`A/conditionsmap.go:150-184`). Test: `TestConditionsAwareDecision` rows `A/conditions_test.go:189-404` (cross-list duplicate rows cover deny↔allow only).
- Lean: yes (as the definition of the `map` constructor's invariant).

**P-14 The constructor never yields Allow; its fallbacks are fail-closed by effect.**
- Formal: `mkMap(D,N,A) ∉ allow(·)`. If not a map: `total = 0 ⇒ noOp(err≠nil)`; `D=[] ∧ A=[] ∧ 1≤total≤128 ⇒ noOp(nil)` **without validation**; otherwise invalid ⇒ `D ≠ [] ? deny(err) : noOp(err)`.
- Status: holds, tested, except the N-only branch: an N-only input with invalid IDs or >10240-byte expressions returns `noOp(…, nil)` silently (`A/conditionsmap.go:160-162` precedes `:164`). Harmless semantically (N-only ≡ NoOpinion). `total > 128` check precedes the N-only check (`:154`).
- Test: `TestConditionsAwareDecision` (`:207-390`); N-only-invalid untested. Lean: yes (cheap; gives "constructor never introduces Allow").

**P-15 PD of a map; maps are never foldable.**
- Formal: `PD(map(D,N,A)) = {N} ∪ {A | A≠[]} ∪ {D | D≠[]}` and `|PD| ≥ 2`.
- Status: holds, tested (`A/conditionsmap.go:103-112` + invariant `:160`). Test: `TestConditionsAwareDecision` (`:827-893`). Lean: yes.

**P-16 Wire validation does not imply constructibility.**
- Formal: `∃v. DV(v) ∧ ¬isMap(dec(v))` for `type = ConditionsMap`.
- Status: **does NOT hold** (as a desirable implication). Counterexamples: empty lists; N-only map; 129–384 conditions (DV: 128 per list, constructor: 128 total); the same ID in two lists (DV unique per list). `staging/src/k8s.io/api/authorization/v1/zz_generated.validations.go` vs `A/conditionsmap.go:154,191`. Effect: webhook answers fail closed instead of being rejected as invalid. `IsPrefixedLabelKey` (DV) and `IsDomainPrefixedKey` accept the same strings (pr-137633.md P5; `apimachinery/pkg/api/validate/content/kube.go:107-118`).
- Test: none at the API boundary. Lean: no.

**P-17 Reserved `*.k8s.io` / `*.kubernetes.io` condition IDs/types are rejected.**
- Status: **does NOT hold**. Documented (`A/interfaces.go:283-292`) but no check in `A/conditionsmap.go:187-219` or SAR/ACR validation. Test: none. Lean: no.

## C. ConditionsMap evaluation

**P-18 Soundness of PD for maps.**
- Formal: `∀ WF m, total o. evalMap(m,o) ∈ uncond ∧ dec(evalMap(m,o)) ∈ PD(map m)`.
- Status: holds, argued: D is returned only from the `D ≠ []` branch, A only from the `A ≠ []` branch, N ∈ PD always (`A/evaluate.go:134-191`). Relied on by the clamps `union.go:163`, `webhook.go:546-559`, `conditionsenforcer.go:148`.
- Test: none. Lean: **yes (theorem 3)**.

**P-19 Totality: a total oracle yields an unconditional result.**
- Formal: `∀ total o. uncond(pmap(m,o))`; more generally `∀d. uncond(peval(d,o))`.
- Status: holds, argued (no `unev` is ever produced, so the three `mkMap` branches are dead; unions then reduce leaf by leaf and `toDecision` folds the all-unconditional prefix, P-41). `A/evaluate.go:102-113,115-120`.
- Test: indirect (every non-`disableConditionsMapEvaluate` case in `A/evaluate_internal_test.go:TestConditionsMapPartiallyEvaluate`). Lean: yes.

**P-20 A true Deny dominates every Allow — inside one map, and against later authorizers only.**
- Formal (map): `(∃c ∈ D. o(c) = T) ⇒ evalMap(m,o) = deny(_, nil)` regardless of N, A and of other D results (including earlier errors).
  Formal (chain): in `seq(l)`, if `⟦cᵢ⟧ = D` and `∀j<i. ⟦cⱼ⟧ = N` then result D. If some `j < i` has `⟦cⱼ⟧ = A`, the result is A: a later Deny does not override an earlier Allow.
- Status: holds, tested for maps (`A/evaluate.go:138-143,204-210`; `TestConditionsMapPartiallyEvaluate/deny:_at_least_one_deny_condition_matched`). Chain form holds by construction (`union.go:152-155,170-172`). "Dominates every Allow" in the absolute sense is **not** a property of the chain (by design, `kep.md:861-869`).
- Lean: yes (map form), with the chain form as a remark.

**P-21 Allow characterisation; an errored Allow never yields Allow on its own.**
- Formal: `dec(evalMap(m,o)) = A ⟺ (∀c∈D. o c = F) ∧ (∀c∈N. o c = F) ∧ (∃c∈A. o c = T)`.
  Corollary: `o(a) = E` contributes nothing to Allow; if another Allow condition is T, the result is `allow(_, nil)` and a's error is **dropped** (`A/evaluate.go:177-181`, `:207-210`).
- Status: holds, tested (`TestConditionsMapPartiallyEvaluate/allow:_*`, `…/noopinion:_single_allow_error_fail_closed`). Lean: **yes (theorem 7)**.

**P-22 Exact error-to-decision mapping per effect.**
- Formal (no T in the phase that errs; all earlier phases all-F):

  | Phase with first error | Result | = FD(m)? |
  |---|---|---|
  | Deny (`D ≠ []`, no D is T, some D is E) | `deny("…errors…", agg)` | yes (D ∈ PD) |
  | NoOpinion (all D F, no N is T, some N is E) | `noOp(…, agg)` | only if D = [] |
  | Allow (all D, N F, no A is T, some A is E) | `noOp(…, agg)` | only if D = [] |

  A Deny-phase error masks any NoOpinion/Allow result (phases are sequential). The error is carried, so a final NoOpinion at the enforcer becomes 500, not 403 (`conditionsenforcer.go:126-129`; union aggregation `union.go:176-185`).
- Status: holds, tested (`A/evaluate.go:144-146,162-164,182-184`; `TestConditionsMapPartiallyEvaluate/deny:_error_fail_closed`, `…/noopinion:_single_allow_error_fail_closed`). Diverges from the KEP (P-K1, P-K2). Lean: yes.

**P-23 Decision is invariant under permutation within an effect.**
- Formal: `∀π. dec(evalMap((πD, πN, πA), o)) = dec(evalMap((D,N,A), o))`. Reason names the first T in list order; the error list follows list order.
- Status: holds, argued (`A/evaluate.go:197-224`: membership-only tests). Test: none. Lean: later (useful to justify list-as-set modelling).

**P-24 Short-circuit and evaluation order.**
- Formal: within a phase no condition after the first T is evaluated; no condition of a later phase is evaluated once a phase returns; the fallback `f` is called for c iff `ev₀(c) = U ∧ f ≠ nil`.
- Status: holds, tested (`A/evaluate.go:125-131,204-210`; panic-fallback subcases of `TestConditionsMapPartiallyEvaluate`). `ConditionsMap.Evaluate` with nil `evaluateConditionFn` panics when some `ev₀ = U` (`:105`); it has no production caller. Lean: no (operational).

## D. Partial evaluation

Throughout, `p` is a partial oracle and `o` a total oracle. **Consistency** `p ⊑ o` :⇔ `∀c. p(c) = U ∨ p(c) = o(c)`
(errors compared up to identity of the E tag).

**P-25 Monotone refinement: partial evaluation never grows PD.**
- Formal: `∀ WF d, ∀p. PD(peval(d,p)) ⊆ PD(d)` — no consistency or no-error premise needed.
- Status: holds, argued. Map: D only from the D branch, A only from the A branch, refined maps are sub-lists, N always possible (`A/evaluate.go:134-191`). Union: by induction; `add` only inserts refined children (PD ⊆ by IH) or untouched tail children; `cua(d) ⇒ cua(peval(d,p))` (an unconditional leaf is returned unchanged, `:278-280`, and the early return at `:266` keeps a cua child), so N is removed from the result whenever it was removed from d. Re-`add` cannot record name errors because names come from a WF union.
- Code relying on it: `union.go:163` (clamp against the *original* sub-decision after the webhook refined it), `conditionsenforcer.go:148`.
- Test: none direct (`A/evaluate_test.go:TestPartiallyEvaluateConditionsAwareDecision` checks shapes, not PD inclusion). Lean: **yes (theorem 5)**.

**P-26 FailureDecision can only drop, from Deny to NoOpinion.**
- Formal: `FD(peval(d,p)) ≤ FD(d)` in `N < D`. Strict drop iff every D-condition / D-leaf of d is eliminated (all evaluated F).
- Status: holds, argued (corollary of P-25 and P-5); documented at `webhook.go:424-428`.
- Is the drop safe? Relative to the reference semantics, yes under `p ⊑ o`: the eliminated Deny conditions are F under o, so `⟦d⟧ₒ` cannot be D through them, and any failure answer `FD(d') ∈ PD(d') ⊆ PD(d)`. It is **not** monotone relative to the webhook-only implementation under failures: webhook-only + ACR outage ⇒ `FD(d) = D` (chain stops); with builtins ⇒ `FD(d') = N` and a later authorizer may Allow. That is correct only if the builtin's F agrees with the authorizer's own evaluation (Axiom O3, P-76). Also: ACR failures always use `FD(d')`, ignoring `failurePolicy` (`webhook.go:529,533,537,542`).
- Test: none with builtins (pr-143024.md P7). Lean: yes (corollary).

**P-27 Confluence: partial-then-full equals full — with an exact precondition.**
- Formal (theorem): `∀ WF d, p ⊑ o. (∀c. p(c) ∉ E) ⇒ dec(⟦peval(d,p)⟧ₒ) = dec(⟦d⟧ₒ)`, and moreover the error component is equal and only the reason text may differ (fold formatting, P-39; different "first T").
  Weakest premise at a map leaf: no Allow phase is reached in which `p` returns E for some Allow condition and U for another Allow condition `a'` with `o(a') = T`.
- **Counterexample without the premise** (verified against `A/evaluate.go:173-187`): `m = ([], [], [a1, a2])`, `p(a1) = o(a1) = E`, `p(a2) = U`, `o(a2) = T`. Full: `phase(A, o)` meets `a1` (E, collected), then `a2` (T) ⇒ `allow`. Partial: `phase(A, p)` returns `errs = [a1]`, `unev = [a2]`; errors win over U (`:182`) ⇒ `noOp(err)`; full of that is N. So `⟦peval⟧ = N ≠ A = ⟦m⟧`. The direction is conservative for that leaf, but in a chain a later authorizer then decides (could be D). Error-component counterexample in the Deny phase: `D = [d1, d2]`, `p(d1) = E`, `p(d2) = U`, `o(d2) = T` ⇒ partial `deny(err)` vs full `deny(nil)`, which the enforcer turns into **500 vs 403** (`conditionsenforcer.go:126-141`). Same shape in the NoOpinion phase.
- Status on HEAD: the theorem **holds, argued** for the only production caller, because the webhook maps every builtin E to U (`webhook.go:968-970`) and decoded conditions have `ev₀ ≡ U` (`encoding.go:154-163`). It **does NOT hold** for `PartiallyEvaluateConditionsAwareDecision` as a library function (it accepts E).
- Additional premise used: Axiom O2 for the ACR webhook (it evaluates the refined decision with the same o).
- Test: none for the property; `TestEvaluateConditions_Builtins/in-process evaluation error` checks E→U. Lean: **yes (theorem 6)**, including the counterexample as a negative theorem.

**P-28 Partial evaluation with a total oracle is full evaluation.**
- Formal: `∀ total o. uncond(peval(d,o)) ∧ dec(peval(d,o)) = ⟦d⟧ₒ`.
- Status: holds, argued (P-19 plus the `seq` shape of the union loop at `A/evaluate.go:248-277`). Test: none as a property. Lean: yes (lemma for P-27).

**P-29 Laziness: nothing after the first still-conditional leaf is evaluated.**
- Formal: in `peval(union l, p)`, if `peval(cᵢ, p)` is conditional then `p` is never applied to conditions of `c_{i+1..k}`.
- Status: holds, tested (`A/evaluate.go:252-255,271-273`; `TestPartiallyEvaluateConditionsAwareDecision/first_conditionsmap_cannot_be_simplified_fully`). Lean: no (operational; the confluence theorem makes it semantically irrelevant).

**P-30 Order and names are preserved; truncation only after a cua child.**
- Formal: the name sequence of `peval(union l, p)` (if it stays a union) is a prefix of names(l), cut only right after a child c' with `cua(c')`.
- Status: holds, argued (`A/evaluate.go:253,263,266-268`). Test: none (snapshots drop names). Lean: later.

**P-31 Idempotence.**
- Formal: `peval(peval(d,p),p) ≅ peval(d,p)` (same variant, structure and PD; reasons may differ only through re-folding, which cannot happen as a folded result is unconditional and returned unchanged).
- Status: holds, argued (a refined map contains only U conditions in its first non-empty phase, so `pmap` returns it unchanged via `mkMap` of the same lists; union tail is untouched). Test: none. Lean: later.

**P-32 The webhook never feeds builtin errors into partial evaluation and never sends the original decision.**
- Formal: `p_b(c) ∈ {T, F, U}`; if `peval(d, p_b)` is unconditional, no ACR is sent; otherwise the ACR carries `enc(peval(d, p_b))` and its answer is clamped to `PD(peval(d, p_b))`.
- Status: holds, tested (`webhook.go:443-449,461,546-559,968-970`; `TestEvaluateConditions_Builtins` "fully evaluated", "partially evaluated", "in-process evaluation error"). Clamp with refined ≠ original untested (pr-143024.md Te1). Lean: no (instance of P-25/P-27).

## E. Union construction and folding

**P-33 `add` is a no-op after a child containing an unconditional Allow/Deny.**
- Formal: `B.flag ⇒ add(B, n, d) = B` (no change to inner, errs, PD), including **no name validation**.
- Status: holds, tested (`A/conditionsunion.go:59-61`; `A/conditionsunion_test.go:TestConditionsAwareDecisionUnionAdd`). Lean: yes (part of theorem 4).

**P-34 Name validation fails the whole union closed.**
- Formal: `B.errs ≠ [] ⇒ toDecision(B) = FromParts(FD_B, "failed closed", agg)`; errs records empty, duplicate, non-DNS-1123 names among added children.
- Status: holds, tested (`A/conditionsunion.go:63-72,138-141`; `TestConditionsAwareDecisionUnionAdd` rows `:66,:82`). Note `FD_B` may be N even when the offending child is `allow` (`PD_B = {A}`), so an Allow becomes NoOpinion + error (see P-42). Lean: yes.

**P-35 NoOpinion is possible iff no unconditional Allow/Deny is contained (discharges the TODO).**
- Formal: `∀ WF d. N ∈ PD(d) ⟺ ¬cua(d)`.
- Status: holds, argued by structural induction: leaves directly; map: `N ∈ PD`, `cua = false`; union: by the PD clause N is removed iff `∃i. cua(cᵢ)`, and otherwise N is present from the `{N}` seed. This is exactly the fact the comment at `A/conditionsunion.go:165` asks to "(formally) verify", and it is relied on by the early exits `union.go:118-120` and `A/evaluate.go:266-268`.
- Test: none as a property. Lean: **yes (theorem 2)**.

**P-36 Shape of an emitted union.**
- Formal: `union l` WF ⇒ `|l| ≥ 1`, `|PD| ≥ 2`, `∀i<k. ¬cua(cᵢ)`, the tree contains at least one map leaf, and `cua(union l) ⇒ cua(c_k)`.
- Status: holds, argued (P-4: a tree of only unconditional leaves under P-33 has singleton PD and is folded; `A/conditionsunion.go:144`). API doc relies on it (`staging/src/k8s.io/api/authorization/v1/types.go:580-581`). Test: `TestConditionsAwareDecision` (`:571,:587`). Lean: yes.

**P-37 Soundness of PD for every decision.**
- Formal: `∀ WF d, total o. ⟦d⟧ₒ ∈ PD(d)`.
- Status: holds, argued by induction on d using P-18 for maps; union: `seq` returns either some `⟦cᵢ⟧ ∈ {A,D}` ⊆ `PD(cᵢ)`, or N with all children N; in the latter case no child has `cua` (else by P-35 + IH that child is not N), so N ∈ PD(union).
- Test: none. Lean: **yes (theorem 3)**.

**P-38 Folding happens only on a singleton PD (or on error) and preserves the outcome.**
- Formal: let `H` be the full history of `add` calls (including the no-op ones). If `B.errs = []` then `∀ total o. ⟦toDecision(B)⟧ₒ = seq(H)`. In particular, the fold branch fires only when `PD_B = {X}` and then `seq(H) = X` for every o; the no-op `add`s after a cua child are unreachable by `seq`.
- Status: holds, argued (P-37 applied to the unfolded union plus "a cua child never yields N", P-35). Code: `A/conditionsunion.go:135-185`. The other "fold" — `mkMap` with N-only lists → `noOp` — preserves the outcome trivially.
- Test: decision values in `TestConditionsAwareDecision` (`:486-790`); no semantic-equivalence test (pr-137513.md P-U9). Lean: **yes (theorem 4)**.

**P-39 Fold reason/error aggregation.**
- Formal: fold to X ⇒ reason = `join(", ", ["n₁: … : nⱼ: {r}"])` over X-leaves, depth-first; errors = `agg(["path: e"])` over X-leaves. For X = N this means every leaf (all are N, by P-35 and P-36); for X ∈ {A,D} it is in practice the one deciding leaf (the last), but the code collects all X-leaves generically.
- Status: holds, tested (`A/conditionsunion.go:144-171,187-208`; `TestConditionsAwareDecision` union-fold rows). Abstracted away in the Lean model. Lean: no.

**P-40 No bound on union width or nesting depth.**
- Formal: `¬∃K. ∀ WF d. width(d) ≤ K ∨ depth(d) ≤ K`, including decoded webhook answers.
- Status: **does NOT hold** as a bound (`encoding.go:143-148` recursion; `staging/src/k8s.io/api/authorization/v1/types.go:584-593`). Width is bounded in kube-apiserver's own union by the chain length; nested unions from a webhook are not. Test: none. Lean: no.

## F. Union authorizer composition (`S/pkg/authorization/union/union.go`)

**P-41 With only unconditional leaves, `CAA` agrees with legacy `Authorize` on the decision — not on reason or error.**
- Formal: let `zᵢ.CAA = FromParts ∘ zᵢ.Authorize` (P-10) and all names DNS-1123 and distinct. Then `dec(CAA(chain,a)) = dec(Authorize(chain,a))`.
- Proof sketch: `add` stops after the first A/D (P-33, `union.go:118-120`), so `PD_B = {X}` with X the first non-N (or {N}); `toDecision` folds to X (P-38).
- Where they differ (verified):

  | Case | `Authorize` (`union.go:83-99`) | `CAA` fold (`A/conditionsunion.go:144-171`) |
  |---|---|---|
  | Allow/Deny by zᵢ | `(X, rᵢ, eᵢ)` verbatim, earlier N errors dropped | `X("nᵢ: {rᵢ}", agg("nᵢ: eᵢ"))`, earlier N reasons/errors dropped |
  | all N | `join("\n", "nᵢ: rᵢ")`, `agg(eᵢ)` | `join(", ", "nᵢ: {rᵢ}")`, `agg("nᵢ: eᵢ")` |
  | empty chain | `(N, "", nil)` | `noOp("", nil)` (equal) |
  | non-DNS-1123 name | unaffected | fails closed (P-42) |

  Consequence: a request classified conditional and one not classified get different 403 reason strings for the same RBAC decision (`authorization.go:163-167`).
- Status: decision part holds, argued; formats verified. Test: decision rows `A/conditions_test.go:486,571,587`; reasons of `Authorize` only via `test/integration/controlplane/synthetic_controlplane_test.go`. Lean: **yes (theorem 8)**, decision component only.

**P-42 `union.New` accepts names that make every conditions-aware request fail.**
- Formal: `union.New` succeeds iff names are non-empty and distinct (`union.go:56-73`); `add` additionally needs DNS-1123 (`A/conditionsunion.go:70`). So `∃` chain accepted by `New` such that `∀a. CAA(chain,a)` is a fail-closed decision with error; for a first authorizer that Allows, `PD_B = {A}` ⇒ result `noOp("failed closed", err)` ⇒ 500 at the filter.
- Status: **does NOT hold** (the desirable "New-valid ⇒ CAA well-behaved"). kube-apiserver is safe: config names are DNS-1123-validated (`S/pkg/apis/apiserver/validation/validation.go:632-637`) and built-in names are DNS-valid literals (`pkg/kubeapiserver/authorizer/reload.go:119`, `S/pkg/server/options/authorization.go:182,193,213`). Third-party users of `union.New` are exposed.
- Test: none. Lean: no.

**P-43 `CAA` is lazy.**
- Formal: `CAA` calls `zᵢ.CAA` exactly for `i = 0..k`, k = first index with `cua(dᵢ)`, else the last.
- Status: holds, tested (`union.go:107-122`; `union_test.go:TestUnionConditionsAwareAuthorizeShortCircuit`, `TestUnionConditionsAwareAuthorizeEmptyChain`). Lean: no.

**P-44 `EvaluateConditions` is clamped into PD and never fails open.**
- Formal: `∀ WF union u, ∀ sub-authorizers (arbitrary, possibly adversarial). dec(EvaluateConditions(u,x)) ∈ PD(u)`; every error path returns `FD` of u or of a child, never A.
- Status: holds, argued. Each child result is clamped to `PD(c)` with fallback `FD(c) ∈ PD(c)` (c conditional ⇒ c ≠ allow, P-6) (`union.go:161-165`); missing authorizer ⇒ `FD(c)` (`:190-192`); returning N requires all children N, impossible if some child is cua (P-35). Non-union input ⇒ `FD(u)`, which is N for `u = allow` (outside PD; the enforcer never passes allow, `conditionsenforcer.go:97`).
- Test: partial (`union_test.go:TestUnionEvaluateConditions` incl. the impossible-decision case). Lean: **yes** (strengthens P-37 to adversarial children; small).

**P-45 `EvaluateConditions` stops at the first Allow/Deny.**
- Formal: children after the first `{A,D}` result are not passed to their authorizer.
- Status: holds by construction (`union.go:152-155,170-172`). Test: `TestUnionEvaluateConditionsUnconditionalShortCircuit`. Lean: no.

**P-46 Routing is single-level by name.**
- Formal: for child `(n, c)`, the evaluator is `nameToAuthorizer[n]` of *this* union instance; nested unions are delegated whole.
- Status: holds, tested (`union.go:188-194`; `TestUnionEvaluateConditionsRoutesByAuthorizerName`, nested DAG in `TestUnionEvaluateConditions`). Identity with the authoring instance fails across reload (P-72).

**P-47 NoOpinion errors propagate to the final answer.**
- Formal: if `EvaluateConditions` returns N and some N child carried an error, the returned error is non-nil (`union.go:176-185`) ⇒ enforcer 500 (`conditionsenforcer.go:126-129`).
- Status: holds by construction. With P-22 this makes an Allow-effect evaluation error a 500 for the end user when nothing else allows. KEP says such errors are "ignored" (P-K2). Test: none for the HTTP code. Lean: no.

## G. Webhook protocol (`S/plugin/pkg/authorizer/webhook/webhook.go`, `S/pkg/apis/authorization/v1/encoding.go`)

**P-48 Advertising conditions requires a reviewer, which requires the gate.**
- Formal: `spec.authorizationOptions ≠ nil ⟺ reviewer ≠ nil ⟹ gate on at construction`.
- Status: holds by construction (`webhook.go:152-157,287-292`). In kube-apiserver the reviewer exists iff gate on ∧ `webhook.conditionsReview` configured (`pkg/kubeapiserver/authorizer/reload.go:188-200`), and validation forbids the stanza when the gate is off (`S/pkg/apis/apiserver/validation/validation.go:759-761`). Stage 2 (pr-140916.md ¬P6) reports that generic apiservers pass an ACR client unconditionally (`S/pkg/server/options/authorization.go:206`), so they advertise conditions while kube-apiserver serves no ACR resource; not re-verified here beyond the call site.
- Test: leaf only (`webhook_conditional_test.go:TestConditionsAwareAuthorize` reviewer/no-reviewer). Lean: no.

**P-49 An unrequested conditional answer never becomes Allow.**
- Formal (legacy path): `status.conditionalDecision ≠ nil ⇒ Authorize ∈ {(D, _, nil) if denied, (FD(dec cd), _, err≠nil) otherwise}`; in particular `allowed = true ∧ cd ≠ nil ⇒ ¬A`.
  Formal (CAA path without reviewer): `cd ≠ nil` fails `CombinedValidateSubjectAccessReviewCreate` (`S/pkg/apis/authorization/validation/validation.go:98-103`) ⇒ `failPol(err) ∈ {deny, noOp}`.
- Status: holds, tested (`webhook.go:258-272,327-329`; `TestAuthorize_FoldDown`; `TestConditionsAwareAuthorize/"no reviewer, unrequested…"`). `allowed=true ∧ cd≠nil` on the legacy path untested. Lean: no.

**P-50 CAA returns a conditional decision only when conditions were requested.**
- Formal: `¬uncond(webhook.CAA(a)) ⇒ reviewer ≠ nil`.
- Status: holds by construction (follows from P-49 second clause and `webhook.go:340-341`). Test: `TestConditionsAwareAuthorize`. Lean: no.

**P-51 Malformed responses on the CAA path follow failurePolicy, not the response's deny intent.**
- Formal: response fails validation ⇒ result `failPol(err)`, even when `status.denied = true` (e.g. denied plus an invalid `conditionalDecision`) ⇒ N under `failurePolicy: NoOpinion`.
- Status: holds by construction (`webhook.go:327-329,349-354`); contrasts with the legacy path where explicit deny wins (`:262-263`). Test: none for the deny-intent case. Lean: no.

**P-52 `webhookEvaluateConditions` returns a possible decision or the failure decision.**
- Formal: result ∈ `PD(d')` (clamped) or `= (FD d', "failed closed", err≠nil)`; never A unless `A ∈ PD(d')` and the webhook said A.
- Status: holds, tested (`webhook.go:529-562`; `TestEvaluateConditions` guard cases). Lean: no (instance of the clamp pattern).

**P-53 ACR answers are correlated by UID.**
- Formal: a webhook-supplied decision is used only if `response.uid` equals the UID generated for this call.
- Status: holds by construction (`webhook.go:483,541-543`). Test: **none effective** (the fake echoes the UID; pr-137633.md P6). Lean: no.

**P-54 Objects sent in an ACR carry apiVersion/kind.**
- Formal: non-nil, non-typed-nil `object`/`oldObject` with empty Version or Kind ⇒ `FD(d')` + error; typed nils are skipped.
- Status: holds, tested (`webhook.go:467-481`; `TestEvaluateConditions` PartialObjectMetadata case). Lean: no.

**P-55 Cache separation.**
- Formal: cache key = `json(spec)` including `authorizationOptions`, so legacy and conditions-aware calls never share entries; conditional statuses are cached for `authorizedTTL` iff `handlesConditional`; decoding a cached status allocates fresh values.
- Status: holds, tested (`webhook.go:359-362,413-419`; `TestConditionalResponseCaching`). Concurrent-read immutability untested. Lean: no.

**P-56 Encode-decode round trip for every WF CAD.**
- Formal: `∀ WF d. dec(enc(d), fc) ≅ d`, where ≅ is equality of: variant, PD, Reason, `Error()?.Error()`, condition `(id, expr, type, desc)` lists in order, union names in order, recursively.
- Status: holds, argued: unconditional — direct; map — `mkMap` re-validates the same lists (WF ⇒ accepted, P-13); union — re-`add` of valid distinct names in the same order (no cua before the last child, P-36), then `toDecision` sees the same PD (≥2) and does not fold. Losses: every condition becomes a `GenericCondition` with `ev₀ ≡ U` (precompiled evaluation is lost, by design, `A/interfaces.go:300-305`); a non-nil error whose `Error()` is `""` decodes to nil; error types/wrapping are lost.
- Test: `encoding_test.go:TestSerializeDeserializeRoundTrip` covers unconditional decisions only. Lean: later (needs a model of v1 and the projection ≅; the map/union cases reduce to P-13/P-36).

**P-57 v1 values that are not round-trippable (`enc(dec(v)) ≠ v`).**
- Exhaustive classes (from `encoding.go:126-163` and §1.2/§1.4): `type=ConditionsMap` with nil map, all-empty lists, N-only lists, >128 total, cross-list duplicate IDs, any invalid id/type/size; `type=Union` with empty list, a foldable list (e.g. all unconditional, or `[Map{allow}, Allow]` ⇒ `allow`), children after a cua child (dropped), empty/duplicate/non-DNS-1123 names; unknown `type`; unconditional type with nil member pointer (re-encoded as a non-nil empty member); any member set besides the one named by `type` (ignored); nil vs empty condition slices (re-encoded as empty). Nested decodes fold independently, so a deep tree can collapse at any level.
- Status: holds, argued (each class traced). DV rejects some of them at the API boundary (pr-137633.md P6), the decoder handles the rest by folding or failing closed. Test: `TestToAuthorizerConditionsAwareDecision` (some classes). Lean: no.

**P-58 The decoder is total and fails closed.**
- Formal: `∀v. dec(v, fc)` returns without panicking; unknown type ⇒ `fc(err)` (failurePolicy-based in the webhook, may be N); invalid maps ⇒ constructor fail-closed (`deny` iff deny conditions were present), independent of failurePolicy.
- Status: holds, tested (`encoding.go:149-150`; `TestToAuthorizerConditionsAwareDecision/unknown Type`). Lean: no.

**P-59 ACR responses are unconditional.**
- Formal: a validated ACR has `request.decision.type ∈ {ConditionsMap, Union}` and `response.decision.type ∈ {A, D, N}`; validator panics become `InternalError`.
- Status: holds, tested (`S/pkg/apis/authorization/validation/validation.go:267-302,320-342`; `TestValidateAuthorizationConditionsReview`). Lean: no.

**P-60 v1beta1 SAR webhooks are never asked for conditions.**
- Formal: v1beta1 spec drops `authorizationOptions` (`webhook.go:896-909`) ⇒ the webhook can only answer unconditionally (or is folded per P-49).
- Status: holds, tested (`TestConditionsAwareAuthorize_V1beta1Downgrade`). Lean: no.

## H. SubjectAccessReview encoding (`pkg/registry/authorization/…`)

**P-61 Unrequested variants are never emitted to a SAR client.**
- Formal: `status.conditionalDecision ≠ nil ⇒ gate on ∧ handledDecisionTypes ⊇ {A, D, N, ConditionsMap, Union}`. A client with a partial set (e.g. `{A,D,N,ConditionsMap}`) gets the legacy `Authorize` path; a set lacking any of A/D/N is rejected by validation, so the 400 branch is unreachable.
- Status: holds by construction (`pkg/registry/authorization/util/helpers.go:251-262`; `staging/src/k8s.io/api/authorization/v1/util.go:39-64`; `pkg/registry/authorization/subjectaccessreview/rest.go:94-118`, same in SSAR `:105-…`, LSAR `:103-…`). Test: `rest_test.go:TestCreateIgnoresPostedStatus`, `util_test.go:TestSupports`, DV tests. Lean: no.

**P-62 SAR status encodes conditional iff the decision is conditional.**
- Formal: `ConditionalDecision ≠ nil ⟺ ¬uncond(d)`, except on internal conversion failure, which yields `Allowed=false, Denied=(FD(d)=D)`.
- Status: holds, tested except the conversion-failure branch (`helpers.go:265-292`; `helpers_test.go:TestConditionsAwareDecisionToSARStatus`). Lean: no.

**P-63 Posted status never influences the answer.**
- Formal: `Create(sar)` clears `status` before validation and authorization; gate off also clears `spec.authorizationOptions`.
- Status: holds, tested (`subjectaccessreview/rest.go:73,78-80`; SSAR `:74,79-81`; LSAR `:75,80-82`; `TestCreateIgnoresPostedStatus` ×3). Side effect visible gate-off: validating admission on SAR create now sees an empty status (pr-137633.md). Lean: no.

## I. Filter + enforcer end to end

**P-64 The filter lets a request proceed iff it can still become allowed.**
- Formal: `next` is called iff `allow d ∨ A ∈ PD(d)`; otherwise 500 if `err(d) ≠ nil`, else 403.
- Status: holds, tested (`S/pkg/endpoints/filters/authorization.go:190-220`; `authorization_test.go:TestWithAuthorization`). A conditional d with `PD = {D, N}` is answered 403 without evaluation (correct: Allow impossible). Lean: no (trivial given PD).

**P-65 Exactly one (authorizer, decision) tuple in the context.**
- Formal: gate on ∧ authorizer ≠ nil ⇒ every request passing either filter carries exactly one tuple; a second attach fails (500). The legacy filter attaches `(AuthorizerFunc(Authorize), allow)` only on Allow (`authorization.go:71,101-110`), so `AuthorizerFunc.EvaluateConditions` is unreachable from the enforcer (`conditionsenforcer.go:97`).
- Status: holds, tested (`S/pkg/endpoints/request/context.go:92-100`; `context_invariant_test.go:TestConditionsEnforcerContextInvariant`). Lean: no.

**P-66 Enforcer acceptance implies an Allow.**
- Formal: gate on ∧ `Validate = nil` ⇒ `allow d ∨ (r = A ∧ A ∈ PD(d))` where `r = z.EvaluateConditions(d, x)`. Missing tuple ⇒ error. `Handles(op)` is constant (all ops incl. CONNECT). Return guard: `r ∉ PD(d) ⇒ (D, err)` (Deny even if D ∉ PD; harmless because terminal, result 500).
- Status: holds, tested (`conditionsenforcer.go:74-76,84-141,145-153`; `conditionsenforcer_test.go:TestConditionsEnforcerEndToEnd`, `TestConditionsEnforcerInitialization`). Lean: no.

**P-67 The enforcer evaluates against the post-mutation object in the request's external version — but not exactly once.**
- Formal (version): `x = NewVersionedAttributes(attrs, attrs.GetKind(), o)`, so `x.GetObject()`/`GetOldObject()` are in `attrs.GetKind()` (the request kind; for subresources the subresource kind), after all mutating admission. Holds, tested (`conditionsenforcer.go:106`; `S/pkg/admission/conversion.go` `GetOldObject` via #142493; integration `crd_conversion_test.go`, `hpa_conversion_test.go`).
- Formal (once): "per request, `EvaluateConditions` is called exactly once". **Does NOT hold.** Counterexamples: every `GuaranteedUpdate` conflict retry re-runs validation admission; the too-large retry calls `requestFunc` twice (`S/pkg/endpoints/handlers/update.go:227-237`); `deletecollection` runs it per item. Each call may see a different post-mutation object; there is no memoisation (`conditionsenforcer.go:112`). What holds: at most once per `Validate` invocation, and each invocation evaluates the object that invocation would persist.
- Test: none for multiplicity. Lean: no.

**P-68 A request classified conditional cannot complete without the enforcer.**
- Formal: `classifier(a) = true ∧ ¬allow d ⇒` the enforcer's `Validate` runs before any state change.
- Status: **does NOT hold.** (1) Aggregated APIs: the classifier has no "served locally" check (`pkg/controlplane/apiserver/config.go:299-321`, TODO `:314-317`); the aggregator reuses it, a conditional allow passes the filter and the proxy forwards without kube-apiserver admission (pr-141959.md Security #1; `kube-aggregator/pkg/apiserver/handler_proxy.go`). (2) Unsafe corrupt-object delete: with `ignoreStoreReadErrorWithClusterBreakingPotential`, the handler only checks an unconditional `unsafe-delete-ignore-read-errors` permission (`S/pkg/endpoints/handlers/delete.go:157`) and then uses the corrupt-object deleter, which skips `deleteValidation` (`delete.go:162-169`; `corrupt_obj_deleter.go` per pr-141959.md). Not counterexamples: create-on-update uses an unconditional `Authorize` for the create permission but still runs admission (`update.go:268`).
- Test: none for either bypass. Lean: no (needs a request-pipeline model; record as the main end-to-end axiom that is currently false).

**P-69 Unclassified requests never carry a conditional decision.**
- Formal: `¬classifier(a) ⇒ d = FromParts(z.Authorize(a))` ⇒ `uncond d`; a webhook asked via `Authorize` folds any conditional answer (P-49).
- Status: holds by construction (`authorization.go:163-167`). Effect: unrequested conditional ⇒ 500 at the filter (shipped.md §3.1). Lean: no.

**P-70 HTTP code of a final non-Allow.**
- Formal: filter and enforcer both map `(r ≠ A, e ≠ nil) ↦ 500`, `(r ≠ A, e = nil) ↦ 403`; Allow ignores e.
- Status: holds, tested (`authorization.go:190-220`, `conditionsenforcer.go:116-141`; `TestWithAuthorization`, `TestConditionsEnforcerEndToEnd`). Interacts with P-22/P-27/P-47: carried evaluation errors turn denials into 500. Lean: no.

**P-71 Legacy and conditions-aware filters agree on unconditional decisions.**
- Formal: same `(dec, err)` ⇒ same status code, audit (decision, reason) and metric label.
- Status: holds, tested (`authorization.go:94-125` vs `:190-221`; `TestWithAuthorization`, `TestRecordAuthorizationMetricsMetrics`). Caveat: the *input* decision differs by path — classified requests go through `CAA` whose reason format differs (P-41). Lean: no.

**P-72 The evaluating authorizer is the authoring authorizer.**
- Formal: `z_eval = z_author` (same configuration) for every request.
- Status: **does NOT hold.** The context stores the reloadable wrapper (`authorization.go:170`), whose `CAA` and `EvaluateConditions` each load `current` independently (`pkg/kubeapiserver/authorizer/reload.go:93-99`). A reload between authorization and admission evaluates the decision against the new chain: by name (P-46), possibly a different webhook/endpoint or a missing name (⇒ `FD(c)`). Clamps still keep the result in `PD(d)` (P-44, P-66), so it cannot exceed the authored possibilities.
- Test: none. Lean: later (model reload as a non-deterministic swap; the clamp theorem then gives "result ∈ PD(d)" as the only guarantee).

**P-73 Audit decision equals the final outcome.**
- Status: **does NOT hold** under multi-evaluation: annotations are first-writer-wins (`conditionsenforcer.go:117-121`, TODO) while P-67 allows several evaluations. Test: none. Lean: no.

## J. In-process CEL evaluator (PR #143024, unmerged)

**P-74 Result mapping.**
- Formal: `p_cel(c) = U` for nil, non-CEL type, empty expression; `E` for compile or runtime error (incl. cost exceeded); else `T ⟺ result == true`.
- Status: holds, tested (`S/pkg/admission/plugin/cel/authorization_conditions.go:148-177`; `authorization_conditions_test.go:TestAuthorizationConditionsEvaluator_EvaluateCondition`). Lean: no (oracle).

**P-75 The boolean test is total.**
- Formal: a successful evaluation returns a CEL bool, because compilation enforces `ReturnTypes = [bool]` (`authorization_conditions.go:183-188`; compiler `S/pkg/admission/plugin/cel/compile.go`).
- Status: holds, argued. Test: none for `dyn`-typed expressions. Lean: no.

**P-76 Axiom O3 — the builtin oracle agrees with the authoring authorizer where it answers.**
- Formal: `∀c. p_cel(c) ∈ {T,F} ⇒ p_cel(c) = o_author(c)`.
- Status: **unknown / not established.** Skew that produces an error is neutralised (E ↦ U, `webhook.go:968-970`), but skew that changes a boolean (different CEL library semantics, different compatibility version `authorization_conditions.go:44-47`, different namespace snapshot from the informer vs. what the webhook sees) is undetectable. Confluence (P-27) and the safety of the FD drop (P-26) rest on it. Test: none. Lean: axiom.

**P-77 Compound authorization from CEL is unconditional and request-scoped.**
- Formal: CEL `authorizer` checks go through a caching `UnconditionalAuthorizer` wrapped around the context authorizer, so they never yield a conditional decision and are cached for one `EvaluatorForData` call; the variable is declared iff that authorizer is non-nil.
- Status: holds, tested (`authorization_conditions.go:98-118`; `webhook.go:955-957`; `TestAuthorizationConditionsEvaluator_CachesAuthorizerChecks`, `…/authorizer variable is undeclared without an authorizer`, `TestEvaluateConditions_BuiltinsWithoutContextAuthorizer`). Lean: no.

**P-78 Cost is bounded per condition, not per request.**
- Status: **does NOT hold** as a per-request bound: budget per condition (`authorization_conditions.go:168`, TODO at `:52`); worst case `128 × budget` per map times union width (P-40), and again per retry (P-67). Lean: no.

**P-79 Builder failure falls back to the webhook.**
- Formal: `EvaluatorForData` error (nil data, data not `*VersionedAttributes`, namespace lookup, activation) ⇒ `peval` skipped, full decision sent to ACR.
- Status: holds, tested except activation failure (`authorization_conditions.go:80-110`; `webhook.go:958-962`; `TestAuthorizationConditionsEvaluatorBuilder_EvaluatorForData`). Lean: no.

## K. Feature gate

**P-80 Gate off ⇒ no conditional decision is produced, advertised or evaluated in production.**
- Formal: gate off ⇒ (a) legacy filter installed (`S/pkg/server/config.go:1077-1087`); (b) enforcer `Handles = false`, `Validate` no-op (`conditionsenforcer.go:74-82`); (c) webhook reviewer nil ⇒ no `authorizationOptions` (`webhook.go:152-157`); (d) builtin builder nil (`reload.go:188-211`); (e) SAR options cleared ⇒ `Authorize` only (`subjectaccessreview/rest.go:78-80`, `helpers.go:252-254`); (f) `conditionsReview` config rejected (`S/pkg/apis/apiserver/validation/validation.go:759-761`); (g) DV `ifDisabled` forbids the new SAR fields (`staging/src/k8s.io/api/authorization/v1/zz_generated.validations.go:1114-1124`); (h) the matchConditions CEL type declares `request.authorizationOptions` only when the gate is on (pr-137633.md B-P11, `S/pkg/authorization/cel/compile.go:218`).
- Status: holds, argued (each switch verified or cited); no composition test. Test: `TestCreateIgnoresPostedStatus`, `TestConditionsEnforcerInitialization`, `TestValidateConditionsReviewConfiguration`. Lean: no.

**P-81 Gate off ⇒ no new code path is reachable.**
- Status: **does NOT hold (benign).** `WebhookAuthorizer.Authorize` has no gate check: a webhook returning `status.conditionalDecision` (unrequested) reaches the decode and fold-down branch even with the gate off (`webhook.go:262-267`). Behaviour change vs. 1.37 (where the unknown field was dropped): `allowed=true ∧ conditionalDecision` now yields `FD(…) + error` (⇒ 500) instead of Allow. Fail-safe, but a gate-off behaviour change. Also gate-off visible: SAR posted status cleared (P-63).
- Test: `TestAuthorize_FoldDown` runs with the gate on only (`webhook_conditional_test.go:372`). Lean: no.

**P-82 Gate on without the enforcer plugin ⇒ no conditional authorization.**
- Formal: gate on ∧ (classifier = nil ∨ plugin disabled) ⇒ legacy filter, warning logged.
- Status: holds, tested (`S/pkg/server/config.go:1077-1091`; integration `TestConditionalAuthorizationEnforcerDisabled`). Lean: no.

## L. Interface contract

**P-83 Holders of an `UnconditionalAuthorizer` can only call `Authorize`.**
- Status: holds by construction (interface split `A/interfaces.go:84-125`; no production type assertion to `Authorizer`, per pr-138801.md P3; admission plugins use `WantsUnconditionalAuthorizer`, `S/pkg/admission/initializer/initializer.go:94-99`). Lean: no.

**P-84 `Authorize` never returns Allow for a request the authorizer would only conditionally allow.**
- Status: holds for in-tree authorizers (P-10, P-49), **not enforced** for out-of-tree ones; undocumented at `A/interfaces.go:84-88`. All 29 unconditional call sites rely on it (shipped.md §3.2). Lean: axiom.

**P-85 Wrappers are transparent; metrics double-count.**
- Status: `instrumentedAuthorizer` returns the delegate's results unchanged (holds by construction, `S/pkg/authorization/metrics/metrics.go:80-132`); `decisions_total` counts one conditional request twice (`conditional` at authorization, `allowed`/`denied` at evaluation) — **does NOT hold** as "one increment per request" (pr-137204.md P7). Lean: no.

---

# PART 3 — KEP vs code

## 3.1 Properties the KEP states that the code does not satisfy

| ID | KEP statement | HEAD behaviour | Severity / kind |
|---|---|---|---|
| P-K1 | Deny-effect error: "return an error. The FailureMode of the ConditionalAuthorizer controls whether to treat the error as decision Deny or NoOpinion" (`kep.md:815-817`) | Always `Deny` + errors, independent of failurePolicy (`A/evaluate.go:144-146`); ACR failures also ignore failurePolicy (`webhook.go:529-562`, P-26) | Important / KEP |
| P-K2 | "Any effect=Allow condition that evaluates to an error is ignored" (`kep.md:831-832`) | `NoOpinion` **with** the aggregated error (`A/evaluate.go:182-184`), propagated by the union (`union.go:176-185`) ⇒ 500 instead of 403 (P-22, P-47) | Important / code or KEP |
| P-K3 | "An authorizer only ever evaluates its own conditions" (`kep.md:1973-1976`) | Holds per name, but not per configuration across reload (P-72) | Important / code |
| P-K4 | Conditional responses only when "the API object is served by the same API server"; aggregated servers must use kube-apiserver as first authorizer (`kep.md:897-913`) | Classifier does not check locality ⇒ aggregated writes skip enforcement (P-68) | Important / code |
| P-K5 | "WithAuthorization fails closed" on conditional answers for unsupported requests (`kep.md:890-892`) | Fails closed, but as 500 (error) not 403 (P-69, shipped.md §3.1) | Nit / KEP |
| P-K6 | Connect handlers (`get pods/exec`) are conditions-capable (`kep.md:899-904`) | Classifier covers admission verbs only; CONNECT via GET is TODO (`config.go:314-317`) | Nit / KEP |
| P-K7 | `ConditionsMode` field and "None" semantics (`kep.md:1913-1915`) | Replaced by `handledDecisionTypes` superset test (P-61) | Nit / KEP (text stale) |
| P-K8 | Reserved `*.k8s.io` domains for IDs/types | Not enforced (P-17) | Nit / code |
| P-K9 | "Computing a concrete decision … the same decision that the authorizer would have immediately returned, if it had direct access to the ConditionData" (`kep.md:854-857`) | Only an assumption about authorizers (Axiom O2); the in-process path adds Axiom O3, which is unverifiable (P-76) | Question / KEP |
| P-K10 | Authorizer requirements: only conditional when unconditional is impossible; prune with request attributes; fold to Deny when deny conditions exist (`kep.md:1916-1945`) | Not checkable or enforced by the apiserver; the code tolerates violations (N-only maps fold, P-14; nothing rejects a never-true Allow condition) | Question / KEP |
| P-K11 | Implicit: conditions evaluated once in admission | Re-evaluated on retries and per deletecollection item (P-67) | Nit / KEP |

## 3.2 Properties the code establishes that the KEP does not state

- The PD/FD algebra, including `N ∈ PD ⟺ ¬cua` (P-3–P-6, P-35) and soundness (P-37).
- Folding of singleton-PD unions and of N-only maps (P-38, P-14); `add` is a no-op after a cua child (P-33).
- Three independent clamps of evaluator output into PD (union `union.go:161-165`, webhook `webhook.go:546-559`, enforcer `conditionsenforcer.go:148-150`) — the system is safe against arbitrary sub-authorizer evaluation answers (P-44).
- Construction limits: 128 conditions **in total**, ID uniqueness **across** effects, byte limits, domain-prefixed ID/type, DNS-1123 authorizer names (P-13, P-34).
- In-process pre-evaluation with E→U, sending the refined decision, clamped against the refined PD; the documented Deny→NoOpinion FD drop (P-25, P-26, P-32).
- ACR UID correlation and apiVersion/kind requirement (P-53, P-54).
- Cache-key separation of legacy and conditions-aware webhook calls (P-55).
- Single context tuple, enforcer refuses a missing tuple (P-65, P-66).
- `ConditionsData` in the request's external version (P-67).
- v1beta1 downgrade strips options (P-60); SAR posted status ignored (P-63).
- Gate-off clearing of SAR options (P-80) and the reviewer only existing with the gate on (P-48).

---

# PART 4 — Recommended Lean scoping

## 4.1 Closed core

Model in Lean exactly §1.1–1.7 and §1.8's `EvaluateConditions` loop:

- `Dec`, `R4`, `Cond` (an opaque type with `id : Cond → String`), `CAD` as the inductive of §1.3.
- `mkMap`, `add`, `toDecision`, `PD`, `FD`, `cua`, `pmap`, `peval`, `⟦·⟧`, `seq`.
- A `WF : CAD → Prop` predicate, or better a subtype produced only by the smart constructors.

This core is self-contained: none of these functions calls out except through the oracle. Model `PD` as `Finset Dec` or as a
3-bit record (decidable, makes `decide` usable).

## 4.2 Axioms and oracles

| Item | Treatment |
|---|---|
| Condition evaluation | Oracle `o : Cond → R3` (total) and `p : Cond → R4` (partial); consistency `p ⊑ o` as a hypothesis, not an axiom |
| O1 purity | Implicit (oracles are functions) |
| O2 remote evaluator conformance | Hypothesis: `ACR(d') = ⟦d'⟧ₒ`; and an adversarial variant (`ACR` arbitrary) for clamp theorems |
| O3 builtin agrees with author | Hypothesis `p_cel ⊑ o_author` (P-76) |
| `valid`, `domPrefixed`, DNS-1123 | Opaque decidable predicates |
| Reasons, errors | Drop, or `List String`; prove decision-component theorems first |
| Webhook transport, caching, HTTP, admission, reload, CEL internals | Out of scope for the first iteration |

## 4.3 Theorems, in priority order

1. **T1 — PD basics.** `∀ WF d. PD d ≠ ∅`, `uncond d ↔ |PD d| = 1`, `FD d ≠ A`, `d ≠ allow → FD d ∈ PD d`, maps never singleton. (P-3, P-4, P-6, P-15)
2. **T2 — NoOpinion lemma.** `∀ WF d. N ∈ PD d ↔ ¬ cua d`. Discharges the TODO at `A/conditionsunion.go:165`; needed by T3/T4. (P-35)
3. **T3 — Soundness.** `∀ WF d o. ⟦d⟧ₒ ∈ PD d`, and its adversarial form: `union.EvaluateConditions` with the clamp returns an element of `PD u` for arbitrary child answers. (P-18, P-37, P-44)
4. **T4 — Fold correctness.** For every `add` history `H` without name errors, `⟦toDecision(fold add H)⟧ₒ = seq H`; corollary: the fold branch preserves the outcome and the post-cua no-ops are semantically invisible. (P-33, P-38)
5. **T5 — Monotone refinement.** `∀ WF d p. PD(peval d p) ⊆ PD d` and `WF(peval d p)`; corollary `FD(peval d p) ≤ FD d`. No premise on p. (P-25, P-26)
6. **T6 — Confluence.** `p ⊑ o → (∀c. p c ∉ E) → ⟦peval d p⟧ₒ = ⟦d⟧ₒ`; plus the explicit counterexample of P-27 as a theorem `¬ ∀ p ⊑ o, …` without the no-error premise. Corollary with O2: the webhook's "builtins first, then ACR" equals "ACR only". (P-27, P-28)
7. **T7 — Map characterisation.** `dec(evalMap m o) = A ↔ (∀c∈D. o c = F) ∧ (∀c∈N. o c = F) ∧ ∃c∈A. o c = T`; `∃c∈D. o c = T → dec = D`; and the error table of P-22. (P-20, P-21, P-22)
8. **T8 — Legacy equivalence.** For chains of unconditional leaves with valid names, `dec(CAA chain) = dec(legacyAuthorize chain)`. (P-41)

Later: P-31 idempotence, P-23 permutation invariance, P-56 round trip (needs a v1 model), P-72 reload as non-deterministic
swap (only "result ∈ PD(d)" survives).

---

# Appendix — Stage 2 P-statements → this catalogue

| Source | Mapping |
|---|---|
| pr-137204 P1–P12 | P1,P2→P-10; P3→P-11; P4→P-8; P5→P-1; P6,P7→P-85; P8→P-72; P9→P-44/P-66; P10→P-65; P11→P-80; P12→P-44/P-52 |
| pr-137513 A (P-D1…P-U10) | D1→P-1; D2→P-2; D3→P-3; D4→P-4; D5→P-5; D6→P-6; D7,D8→P-7; D9→P-9; M1→P-13; M2→P-15; M3→P-14; M4,M5→P-12; M6→P-18; U1→P-34; U2,U3,U5→P-36; U4→P-35; U6→P-39; U7→P-33; U8→P-12; U9→P-38; U10→P-41 |
| pr-137513 B P1–P21 | P1→P-25; P2→P-20; P3→P-22; P4,P5→P-21; P6→P-19; P7→P-24; P8→P-23; P9→P-27 (verified; error-component claim corrected: the reason may differ, and without the premise the error differs in the Deny/NoOpinion phases); P10→P-29; P11→P-30; P12→P-35; P13→P-43; P14→P-45; P15,P16→P-44; P17,P18→P-41; P19→P-42; P20→P-46; P21→P-72 |
| pr-137633 A P1–P22 | P1→P-58; P2,P3→P-56; P4–P7→P-16/P-57; P8,P9→P-49/P-62; P10→P-50; P11,P12→P-60; P13→P-80; P14→P-63; P15–P17→P-61/P-12; P18,P19→P-59; P20 (DV option always defined) not catalogued (validation plumbing); P21→P-48; P22→P-40 |
| pr-137633 B P1–P15 | P1→P-49; P2→P-5; P3→P-50; P4→P-48; P5→P-52; P6→P-53; P7→P-54; P8–P10→P-55; P11→P-80(h); P12→P-48; P13→P-72; P14→P-68; P15→P-51 |
| pr-138801 P1–P10 | P1–P3→P-83; P4→P-10; P5→P-69; P6→P-49; P7→P-55; P8→P-84; P9,P10→P-83 |
| pr-140714 P1–P9 | P1–P8 not catalogued (validation-move refactor equivalence, outside the decision model); P9→P-10/P-51 |
| pr-140715 P1–P13 | P1–P3→P-9; P4→P-5; P5,P6→P-13/P-14; P7→P-34; P8→P-33; P9→P-42; P10→P-41/P-62 (wire-visible names); P11,P12→P-16; P13→P-17 |
| pr-140916 P1–P7 | P1–P3→P-83; P4→P-65; P5→P-80; P6, ¬P6→P-48; P7→P-49 |
| pr-141959 P1–P16 | P1,P5,P9→P-65; P2→P-64; P3→P-68; P4,P6,P13→P-66; P7→P-70; P8→P-67; P10→P-80; P11→P-62; P12→P-82; P14→P-71; P15→P-73; P16→P-72 |
| pr-142493 P1–P10 | P1–P7→P-67 (version/old-object plumbing, not catalogued individually); P8→P-54; P9,P10 not catalogued (gate-off VersionedAttributes callers) |
| pr-143024 P1–P17 | P1→P-25; P2→P-32; P3,P4→P-32; P5→P-52; P6→P-66; P7→P-26; P8→P-79; P9,P10,P12→P-77; P11→P-77; P13→P-74; P14→P-75; P15→P-78; P16→P-48/P-80; P17→P-80 |
