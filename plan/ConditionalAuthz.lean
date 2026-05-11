/-!
# Formal Model of Kubernetes Conditional Authorization (KEP-5681)

This file proves that Kubernetes' two-phase conditional authorization mechanism
(authorization phase → conditions enforcement in admission) produces the same
final authorization decision as a single-phase model where authorizers have
access to all request data upfront.

## Implementation references

The model mirrors these implementation components:
- **Union authorizer** (`pkg/authorization/union/union.go`):
  `ConditionsAwareAuthorize` iterates authorizers, collecting all decisions.
  Short-circuits when `decision.ContainsAllowOrDeny()` (Allow or Deny).
  Wraps results in `ConditionsAwareDecisionUnion(decisions...)`.
- **WithAuthorization filter** (`pkg/endpoints/filters/authorization.go`):
  Checks `CanBecomeAllowed()` on the union decision. If true, proceeds with
  conditions stored in context. If false, rejects with 403.
- **AuthorizationConditionsEnforcer** (`pkg/admission/plugin/authorizer/conditionsenforcer/`):
  Evaluates the union decision tree by walking sub-decisions in order, calling
  each authorizer's `EvaluateConditions` for conditional sub-decisions.

## Key model features (v2)

- **Union decision type**: the authorization phase collects all authorizer
  decisions into a union (flat list), mirroring `ConditionsAwareDecisionUnion`.
- **No `ax_no_noop` restriction**: conditionals CAN evaluate to `NoOpinion`,
  and evaluation continues to the next authorizer in the union. This is the
  critical feature that Union enables.
- **`canBecomeAllowed` soundness**: modelled and proven. The WithAuthorization
  filter rejects when `canBecomeAllowed = false`, which is sound because no
  authorizer in the union can produce an Allow.

## Main results

- `evaluateUnion_eq_idealChain`: evaluating the union always equals the ideal
  chain. This is the core semantic lemma.
- `cba_sound`: when `canBecomeAllowed` is false, evaluation never yields Allow.
- `authorization_allows_iff`: `isAllowed(idealChain) = isAllowed(pipeline)`.
  The two-phase model allows exactly the same requests as the single-phase model.
- `authorization_eq_when_cba`: full decision equality when `canBecomeAllowed`
  is true (not just `isAllowed`).
-/

namespace ConditionalAuthz

-- ============================================================================
-- Part 1: Core Decision Types
-- ============================================================================

/-- An unconditional authorization decision.
    Maps to `authorizer.Decision` (the int enum) in the Go implementation. -/
inductive UnconditionalDecision where
  | Allow
  | Deny
  | NoOpinion
  deriving Repr, DecidableEq, BEq

/-- A leaf decision that a single (non-union) authorizer returns.
    Maps to a non-Union `authorizer.ConditionsAwareDecision`. -/
inductive LeafDecision (CM : Type) where
  | Allow
  | Deny
  | NoOpinion
  | Conditional (cm : CM)
  deriving Repr

/-- The full decision type including the Union variant.
    Maps to `authorizer.ConditionsAwareDecision` with all five variants.
    The Union variant forms a tree where leaves are Allow/Deny/NoOpinion/Conditional
    and internal nodes are Union. Defined here for completeness; the proof
    operates on the equivalent flat-list representation (`List UnionEntry`). -/
inductive Decision (CM : Type) where
  | Allow
  | Deny
  | NoOpinion
  | Conditional (cm : CM)
  | Union (children : List (Decision CM))
  deriving Repr

/-- Whether a request was allowed. Both Deny and NoOpinion reject the request;
    only Allow lets it through. -/
def isAllowed : UnconditionalDecision → Bool
  | .Allow => true
  | _      => false

-- ============================================================================
-- Part 2: Authorizer Abstraction
-- ============================================================================

/-- An authorizer with a proven-correct two-phase split.

    Each authorizer bundles:
    - `fullAuthorize`: the ideal single-phase function (all data at once)
    - `authorize`: phase 1, returns a leaf decision (possibly Conditional)
    - `evaluateConditions`: phase 2, resolves conditions with admission data
    - `canBecomeAllowed`: whether a ConditionsMap has any Allow path

    Axioms:
    - `ax_allow/deny/noOpinion/conditional`: the two-phase split is faithful
    - `ax_cba_sound`: canBecomeAllowed = false implies no Allow possible -/
structure Authorizer (Attrs Data CM : Type) where
  /-- Ideal: authorize with complete data. -/
  fullAuthorize : Attrs → Data → UnconditionalDecision
  /-- Phase 1 (authorization): decide with only request metadata. -/
  authorize : Attrs → LeafDecision CM
  /-- Phase 2 (admission): evaluate a ConditionsMap against admission data. -/
  evaluateConditions : CM → Data → UnconditionalDecision
  /-- Whether a ConditionsMap can possibly evaluate to Allow.
      Mirrors `ConditionsMap.CanBecomeAllowed()` which checks for
      the presence of at least one `effect=Allow` condition. -/
  canBecomeAllowed : CM → Bool

  /-- If phase 1 returns Allow, the ideal also returns Allow. -/
  ax_allow : ∀ (attrs : Attrs) (data : Data),
    authorize attrs = .Allow →
    fullAuthorize attrs data = .Allow
  /-- If phase 1 returns Deny, the ideal also returns Deny. -/
  ax_deny : ∀ (attrs : Attrs) (data : Data),
    authorize attrs = .Deny →
    fullAuthorize attrs data = .Deny
  /-- If phase 1 returns NoOpinion, the ideal also returns NoOpinion. -/
  ax_noOpinion : ∀ (attrs : Attrs) (data : Data),
    authorize attrs = .NoOpinion →
    fullAuthorize attrs data = .NoOpinion
  /-- If phase 1 returns Conditional(cm), evaluating cm equals the ideal. -/
  ax_conditional : ∀ (attrs : Attrs) (data : Data) (cm : CM),
    authorize attrs = .Conditional cm →
    fullAuthorize attrs data = evaluateConditions cm data
  /-- Soundness of canBecomeAllowed: if false, evaluation never returns Allow.
      This holds because if there are no `effect=Allow` conditions,
      `ConditionsMap.Evaluate` returns either Deny, NoOpinion, or NoOpinion
      (the "no conditions matched" default). -/
  ax_cba_sound : ∀ (cm : CM) (data : Data),
    canBecomeAllowed cm = false →
    evaluateConditions cm data ≠ .Allow

-- ============================================================================
-- Part 3: Ideal Chain Evaluation
-- ============================================================================

/-- The ideal authorization chain: run each authorizer in order with all data,
    short-circuit on Allow or Deny, continue on NoOpinion.
    Mirrors the semantics of `union.Authorize()`. -/
def idealChain {Attrs Data CM : Type}
    (chain : List (Authorizer Attrs Data CM))
    (attrs : Attrs) (data : Data) : UnconditionalDecision :=
  match chain with
  | [] => .NoOpinion
  | a :: rest =>
    match a.fullAuthorize attrs data with
    | .Allow     => .Allow
    | .Deny      => .Deny
    | .NoOpinion => idealChain rest attrs data

-- ============================================================================
-- Part 4: Implementation Model
-- ============================================================================

-- 4a. Union entries and authorization phase
-- Reference: staging/src/k8s.io/apiserver/pkg/authorization/union/union.go:73-96

/-- An entry in the union decision list: pairs an authorizer with its leaf decision.
    In the Go implementation, `decisions[i]` is correlated with `authzHandler[i]`
    by index. This structure makes the pairing explicit. -/
structure UnionEntry (Attrs Data CM : Type) where
  auth : Authorizer Attrs Data CM
  decision : LeafDecision CM

/-- The authorization phase: iterate through the authorizer chain, calling
    each authorizer's phase-1 function and collecting results.

    Short-circuits on Allow or Deny (when `ContainsAllowOrDeny()` returns true
    for a leaf decision). Continues past NoOpinion and Conditional.

    Mirrors `unionAuthzHandler.ConditionsAwareAuthorize` (union.go:73-96). -/
def authzPhase {Attrs Data CM : Type}
    (chain : List (Authorizer Attrs Data CM))
    (attrs : Attrs) : List (UnionEntry Attrs Data CM) :=
  match chain with
  | [] => []
  | a :: rest =>
    let d := a.authorize attrs
    let entry : UnionEntry Attrs Data CM := ⟨a, d⟩
    match d with
    | .Allow | .Deny => [entry]  -- ContainsAllowOrDeny() = true → short-circuit
    | .NoOpinion | .Conditional _ => entry :: authzPhase rest attrs

-- 4b. canBecomeAllowed on the union
-- Reference: authorizer.conditionsAwareDecisionUnionSlice.CanBecomeAllowed

/-- Can the union of decisions possibly evaluate to Allow?
    Mirrors `conditionsAwareDecisionUnionSlice.CanBecomeAllowed()`.
    Walks the list in order:
    - Allow → true (trivially can become allowed)
    - Deny → false (blocks everything after it in the chain)
    - NoOpinion → continue (no opinion, check rest)
    - Conditional cm → true if the ConditionsMap can become allowed, else continue -/
def unionCanBecomeAllowed {Attrs Data CM : Type}
    (entries : List (UnionEntry Attrs Data CM)) : Bool :=
  match entries with
  | [] => false
  | ⟨a, d⟩ :: rest =>
    match d with
    | .Allow          => true
    | .Deny           => false
    | .NoOpinion      => unionCanBecomeAllowed rest
    | .Conditional cm => a.canBecomeAllowed cm || unionCanBecomeAllowed rest

-- 4c. Evaluation of the union
-- Reference: unionAuthzHandler.EvaluateConditions (union.go:99-152)

/-- Evaluate the union of decisions by walking entries in order.
    For each entry:
    - Allow → return Allow (short-circuit)
    - Deny → return Deny (short-circuit)
    - NoOpinion → continue to next
    - Conditional cm → evaluate via the authorizer's `evaluateConditions`:
      - If Allow or Deny → return it (short-circuit)
      - If NoOpinion → continue to next (THIS is what Union enables!)

    Mirrors `unionAuthzHandler.EvaluateConditions` (union.go:99-152). -/
def evaluateUnion {Attrs Data CM : Type}
    (entries : List (UnionEntry Attrs Data CM))
    (data : Data) : UnconditionalDecision :=
  match entries with
  | [] => .NoOpinion
  | ⟨a, d⟩ :: rest =>
    match d with
    | .Allow     => .Allow
    | .Deny      => .Deny
    | .NoOpinion => evaluateUnion rest data
    | .Conditional cm =>
      match a.evaluateConditions cm data with
      | .Allow     => .Allow
      | .Deny      => .Deny
      | .NoOpinion => evaluateUnion rest data

-- 4d. WithAuthorization filter
-- Reference: staging/src/k8s.io/apiserver/pkg/endpoints/filters/authorization.go:70-151

/-- Result of the WithAuthorization filter. -/
inductive FilterVerdict (Attrs Data CM : Type) where
  | Proceed (entries : List (UnionEntry Attrs Data CM))
  | Reject

/-- The WithAuthorization HTTP filter.
    Checks `CanBecomeAllowed()` on the union decision.
    - If true → store decision in context, proceed to admission
    - If false → reject with 403 Forbidden

    Also handles the unconditional Allow case (which is subsumed by
    canBecomeAllowed returning true for an Allow entry). -/
def withAuthorizationFilter {Attrs Data CM : Type}
    (entries : List (UnionEntry Attrs Data CM))
    : FilterVerdict Attrs Data CM :=
  if unionCanBecomeAllowed entries then .Proceed entries
  else .Reject

-- 4e. AuthorizationConditionsEnforcer admission plugin
-- Reference: conditionsenforcer.go:87-147

/-- The AuthorizationConditionsEnforcer validating admission plugin.
    - If the filter rejected → Deny (403 Forbidden)
    - If the filter proceeded → evaluate the union decision tree -/
def conditionsEnforcer {Attrs Data CM : Type}
    (verdict : FilterVerdict Attrs Data CM)
    (data : Data) : UnconditionalDecision :=
  match verdict with
  | .Reject          => .Deny
  | .Proceed entries => evaluateUnion entries data

-- 4f. Pipeline composition

/-- The full implementation pipeline:
    1. Authorization phase → union entries
    2. WithAuthorization filter → proceed or reject
    3. AuthorizationConditionsEnforcer → final decision -/
def pipeline {Attrs Data CM : Type}
    (chain : List (Authorizer Attrs Data CM))
    (attrs : Attrs) (data : Data) : UnconditionalDecision :=
  conditionsEnforcer (withAuthorizationFilter (authzPhase chain attrs)) data

-- ============================================================================
-- Part 5: Core Semantic Lemma
-- ============================================================================

/-- **Core lemma**: Evaluating the union of authzPhase results always equals
    the ideal chain evaluation. This holds unconditionally — no restrictions
    on what conditionals evaluate to.

    The proof is by structural induction on the authorizer chain. For each
    authorizer, it case-splits on the phase-1 result:
    - Allow/Deny: both sides short-circuit with the same result (by axioms)
    - NoOpinion: both sides skip and recurse (by axiom + IH)
    - Conditional cm: both sides match on `evaluateConditions cm data`:
      - Allow/Deny: both short-circuit with the same result
      - **NoOpinion: both sides recurse on the remaining chain (by IH)**
        This is the critical case that required the `ax_no_noop` restriction
        in v1 — Union resolves it by enabling chain resumption. -/
theorem evaluateUnion_eq_idealChain {Attrs Data CM : Type}
    (chain : List (Authorizer Attrs Data CM))
    (attrs : Attrs) (data : Data)
    : evaluateUnion (authzPhase chain attrs) data = idealChain chain attrs data := by
  induction chain with
  | nil => rfl
  | cons a rest ih =>
    cases hauth : a.authorize attrs with
    | Allow =>
      simp [authzPhase, hauth, evaluateUnion, idealChain, a.ax_allow attrs data hauth]
    | Deny =>
      simp [authzPhase, hauth, evaluateUnion, idealChain, a.ax_deny attrs data hauth]
    | NoOpinion =>
      simp only [authzPhase, hauth, evaluateUnion, idealChain, a.ax_noOpinion attrs data hauth]
      exact ih
    | Conditional cm =>
      simp only [authzPhase, hauth, evaluateUnion, idealChain, a.ax_conditional attrs data cm hauth]
      -- Both sides now match on a.evaluateConditions cm data
      cases heval : a.evaluateConditions cm data with
      | Allow     => simp
      | Deny      => simp
      | NoOpinion =>
        -- Key v2 case: Conditional → NoOpinion → continue the chain.
        -- Both evaluateUnion and idealChain recurse on the remaining chain.
        exact ih

-- ============================================================================
-- Part 6: canBecomeAllowed Soundness
-- ============================================================================

/-- **Soundness**: when `unionCanBecomeAllowed` returns false for a list of
    union entries, `evaluateUnion` cannot return Allow.

    Proof by induction on the entries:
    - Empty: evaluateUnion returns NoOpinion ≠ Allow
    - Allow entry: canBecomeAllowed would be true — contradiction
    - Deny entry: evaluateUnion returns Deny ≠ Allow
    - NoOpinion entry: canBecomeAllowed passes through, so does evaluateUnion;
      apply IH on the rest
    - Conditional cm entry: canBecomeAllowed cm = false (otherwise cba would
      be true) AND canBecomeAllowed rest = false. By `ax_cba_sound`,
      evaluateConditions ≠ Allow, so if it's Deny we're done; if NoOpinion,
      apply IH on the rest. -/
theorem cba_sound {Attrs Data CM : Type}
    (entries : List (UnionEntry Attrs Data CM))
    (data : Data)
    (hcba : unionCanBecomeAllowed entries = false)
    : evaluateUnion entries data ≠ .Allow := by
  induction entries with
  | nil =>
    simp [evaluateUnion]
  | cons entry rest ih =>
    -- Destructure the entry
    obtain ⟨a, d⟩ := entry
    cases hd : d with
    | Allow =>
      -- unionCanBecomeAllowed would return true → contradiction
      simp [unionCanBecomeAllowed, hd] at hcba
    | Deny =>
      -- evaluateUnion returns Deny
      simp [evaluateUnion]
    | NoOpinion =>
      -- canBecomeAllowed passes through to rest; evaluateUnion also passes through
      simp [unionCanBecomeAllowed, hd] at hcba
      simp only [evaluateUnion]
      exact ih hcba
    | Conditional cm =>
      -- From hcba: a.canBecomeAllowed cm = false AND unionCanBecomeAllowed rest = false
      simp [unionCanBecomeAllowed, hd, Bool.or_eq_false_iff] at hcba
      obtain ⟨hcba_cm, hcba_rest⟩ := hcba
      -- evaluateUnion matches on a.evaluateConditions cm data
      simp only [evaluateUnion]
      cases heval : a.evaluateConditions cm data with
      | Allow =>
        -- Contradiction: canBecomeAllowed cm = false but evaluateConditions = Allow
        exact absurd heval (a.ax_cba_sound cm data hcba_cm)
      | Deny =>
        simp
      | NoOpinion =>
        exact ih hcba_rest

-- ============================================================================
-- Part 7: Main Theorems
-- ============================================================================

/-- Helper: `isAllowed` of the pipeline equals `isAllowed` of evaluateUnion.
    When canBecomeAllowed is true, the pipeline evaluates the union directly.
    When false, both are not Allow (pipeline returns Deny; evaluateUnion ≠ Allow
    by cba_sound). -/
private theorem pipeline_isAllowed_eq {Attrs Data CM : Type}
    (chain : List (Authorizer Attrs Data CM))
    (attrs : Attrs) (data : Data)
    : isAllowed (pipeline chain attrs data)
    = isAllowed (evaluateUnion (authzPhase chain attrs) data) := by
  -- Case split on the Bool value of canBecomeAllowed.
  -- This resolves the `if ... = true then Proceed else Reject` and
  -- the subsequent `match` on FilterVerdict inside the expanded pipeline.
  cases hcba : unionCanBecomeAllowed (authzPhase chain attrs) with
  | true =>
    -- canBecomeAllowed = true: pipeline evaluates the union. Both sides equal.
    simp [pipeline, conditionsEnforcer, withAuthorizationFilter, hcba]
  | false =>
    -- canBecomeAllowed = false: pipeline returns Deny, isAllowed = false.
    -- evaluateUnion also ≠ Allow by cba_sound, so isAllowed = false.
    simp [pipeline, conditionsEnforcer, withAuthorizationFilter, hcba, isAllowed]
    have h := cba_sound (authzPhase chain attrs) data hcba
    cases heval : evaluateUnion (authzPhase chain attrs) data with
    | Allow     => exact absurd heval h
    | Deny      => rfl
    | NoOpinion => rfl

/-- **Main theorem**: The ideal single-phase model allows a request if and only
    if the implementation's two-phase pipeline allows it.

    This is the security-critical property: the conditional authorization
    mechanism neither grants unauthorized access nor denies authorized access.

    The proof combines two lemmas:
    - `evaluateUnion_eq_idealChain`: evaluateUnion = idealChain (core semantics)
    - `pipeline_isAllowed_eq`: isAllowed(pipeline) = isAllowed(evaluateUnion)
      (canBecomeAllowed soundness) -/
theorem authorization_allows_iff {Attrs Data CM : Type}
    (chain : List (Authorizer Attrs Data CM))
    (attrs : Attrs) (data : Data)
    : isAllowed (idealChain chain attrs data) = isAllowed (pipeline chain attrs data) := by
  rw [pipeline_isAllowed_eq, evaluateUnion_eq_idealChain]

/-- **Stronger theorem**: When the pipeline proceeds (canBecomeAllowed = true),
    the ideal chain and the pipeline produce the exact same decision — not just
    the same isAllowed result, but the same Allow/Deny/NoOpinion value.

    This is stronger than `authorization_allows_iff` but only applies when
    the request isn't rejected by the WithAuthorization filter. -/
theorem authorization_eq_when_cba {Attrs Data CM : Type}
    (chain : List (Authorizer Attrs Data CM))
    (attrs : Attrs) (data : Data)
    (hcba : unionCanBecomeAllowed (authzPhase chain attrs) = true)
    : idealChain chain attrs data = pipeline chain attrs data := by
  simp [pipeline, conditionsEnforcer, withAuthorizationFilter, hcba]
  exact (evaluateUnion_eq_idealChain chain attrs data).symm

-- ============================================================================
-- Part 8: Concrete ConditionsMap Model
-- ============================================================================

section ConcreteConditionsMap

/-- The effect of a condition evaluating to true.
    Maps to `authorizer.ConditionEffect`. -/
inductive ConditionEffect where
  | Allow
  | Deny
  | NoOpinion
  deriving Repr, DecidableEq, BEq

/-- A single condition entry.
    Maps to `authorizer.Condition` (the interface). -/
structure ConditionEntry (Data : Type) where
  id : String
  effect : ConditionEffect
  evaluate : Data → Bool

/-- A concrete conditions map, mirroring `authorizer.ConditionsMap`.
    In the implementation, conditions are pre-sorted by effect into
    `denyConditions/noOpinionConditions/allowConditions`. -/
structure ConcConditionsMap (Data : Type) where
  conditions : List (ConditionEntry Data)

/-- Does this conditions map have at least one Allow condition?
    Mirrors `ConditionsMap.CanBecomeAllowed()`. -/
def ConcConditionsMap.canBecomeAllowed (cm : ConcConditionsMap Data) : Bool :=
  cm.conditions.any (fun c => c.effect == .Allow)

/-- Evaluate a concrete conditions map against admission data.
    Mirrors `ConditionsMap.Evaluate()` (conditions.go:700-870).
    Priority: Deny > NoOpinion > Allow > NoOpinion (default). -/
def ConcConditionsMap.evaluate (cm : ConcConditionsMap Data) (data : Data)
    : UnconditionalDecision :=
  if cm.conditions.any (fun c => c.effect == .Deny && c.evaluate data) then
    .Deny
  else if cm.conditions.any (fun c => c.effect == .NoOpinion && c.evaluate data) then
    .NoOpinion
  else if cm.conditions.any (fun c => c.effect == .Allow && c.evaluate data) then
    .Allow
  else
    .NoOpinion

/-- If there are no Allow conditions, evaluation never returns Allow.
    This justifies the `ax_cba_sound` axiom for concrete conditions maps. -/
theorem ConcConditionsMap.cba_sound {Data : Type}
    (cm : ConcConditionsMap Data) (data : Data)
    (h : cm.canBecomeAllowed = false)
    : cm.evaluate data ≠ .Allow := by
  simp [ConcConditionsMap.canBecomeAllowed] at h
  -- h : ∀ x ∈ cm.conditions, (x.effect == .Allow) = false
  -- This means no condition has effect Allow.
  -- evaluate checks Deny, NoOpinion, Allow branches in order.
  -- The Allow branch requires ∃ c with effect=Allow ∧ c.evaluate data = true,
  -- but h rules this out. So evaluate returns Deny, NoOpinion, or NoOpinion (default).
  unfold ConcConditionsMap.evaluate
  -- Case split on each branch of the if-then-else
  split
  · -- Deny branch: result is .Deny ≠ .Allow
    simp
  · split
    · -- NoOpinion branch: result is .NoOpinion ≠ .Allow
      simp
    · split
      · -- Allow branch: impossible because h rules out any Allow conditions
        rename_i h_no_deny h_no_noop h_allow
        simp [List.any_eq_true] at h_allow
        obtain ⟨c, hc_mem, hc_eff, _⟩ := h_allow
        have := h c hc_mem
        simp [hc_eff] at this
      · -- Default: result is .NoOpinion ≠ .Allow
        simp

end ConcreteConditionsMap

-- ============================================================================
-- Part 9: Decision tree correspondence (reference)
-- ============================================================================

section DecisionTreeCorrespondence

/-- Convert a list of union entries to the `Decision` tree type.
    The flat list `[e₁, e₂, ..., eₙ]` maps to
    `Decision.Union [toLeaf e₁, toLeaf e₂, ..., toLeaf eₙ]`. -/
def entriesToDecision {Attrs Data CM : Type}
    (entries : List (UnionEntry Attrs Data CM)) : Decision CM :=
  .Union (entries.map fun e =>
    match e.decision with
    | .Allow          => .Allow
    | .Deny           => .Deny
    | .NoOpinion      => .NoOpinion
    | .Conditional cm => .Conditional cm)

/-- `canBecomeAllowed` on the `Decision` tree type.
    Recursive on the tree structure.
    Mirrors `ConditionsAwareDecision.CanBecomeAllowed()`. -/
def Decision.canBecomeAllowed' {CM : Type} (cba : CM → Bool) : Decision CM → Bool
  | .Allow          => true
  | .Deny           => false
  | .NoOpinion      => false
  | .Conditional cm => cba cm
  | .Union children => go children
where
  go : List (Decision CM) → Bool
    | []      => false
    | d :: rest =>
      match d with
      | .Deny    => false
      | .Allow   => true
      | .Conditional cm => cba cm || go rest
      | .Union ds => Decision.canBecomeAllowed' cba (.Union ds) || go rest
      | .NoOpinion => go rest

end DecisionTreeCorrespondence

end ConditionalAuthz
