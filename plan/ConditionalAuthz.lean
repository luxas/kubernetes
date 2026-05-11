/-!
# Formal Model of Kubernetes Conditional Authorization (KEP-5681)

This file proves that Kubernetes' two-phase conditional authorization mechanism
(authorization phase → conditions enforcement in admission) produces the same
final authorization decision as a single-phase model where authorizers have
access to all request data upfront.

## Implementation references

The model mirrors these implementation components:
- **Union authorizer** (`pkg/authorization/union/union.go`):
  `ConditionsAwareAuthorize` iterates authorizers, short-circuits on Allow/Deny
  or Conditional(CanBecomeAllowed).
- **WithAuthorization filter** (`pkg/endpoints/filters/authorization.go`):
  Lets through unconditional Allow or conditional decisions that can become
  allowed; rejects everything else with 403.
- **AuthorizationConditionsEnforcer** (`pkg/admission/plugin/authorizer/conditionsenforcer/`):
  Evaluates conditional decisions against admission data; passes through
  unconditional allows.

## Simplifications (v1)

- No `Union` decision variant (will be added in a future iteration).
- Temporary axiom: conditional decisions never evaluate to `NoOpinion`.
  Without `Union`, the implementation cannot resume the authorizer chain after
  a conditional evaluates to `NoOpinion`. This axiom is relaxed when `Union`
  is added.

## Main result

`theorem authorization_equivalence`: For any list of authorizers and any
request data, `idealChain = pipeline` — the single-phase evaluation equals
the composed two-phase implementation.
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

/-- A decision that may be conditional on data not yet available.
    Maps to `authorizer.ConditionsAwareDecision` in the Go implementation,
    without the `Union` variant (to be added later).
    `CM` is the type of condition maps (abstract in the main theorem). -/
inductive Decision (CM : Type) where
  | Allow
  | Deny
  | NoOpinion
  | Conditional (cm : CM)
  deriving Repr

/-- Embed an unconditional decision into the richer Decision type. -/
def UnconditionalDecision.toDecision (d : UnconditionalDecision) : Decision CM :=
  match d with
  | .Allow     => .Allow
  | .Deny      => .Deny
  | .NoOpinion => .NoOpinion

/-- Can this decision possibly evaluate to Allow?
    Mirrors `ConditionsAwareDecision.CanBecomeAllowed()`.
    Without Union, this is simply: Allow or Conditional. -/
def Decision.canBecomeAllowed : Decision CM → Bool
  | .Allow          => true
  | .Conditional _  => true
  | .Deny           => false
  | .NoOpinion      => false

-- ============================================================================
-- Part 2: Authorizer Abstraction
-- ============================================================================

/-- An authorizer with a proven-correct two-phase split.

    Each authorizer bundles three functions:
    - `fullAuthorize`: the ideal single-phase function (all data at once)
    - `authorize`: phase 1, returns a possibly-conditional decision
    - `evaluateConditions`: phase 2, resolves conditions with admission data

    Five axioms link these functions:
    - `ax_allow/deny/noOpinion`: unconditional phase-1 results match the ideal
    - `ax_conditional`: conditional phase-1 + phase-2 evaluation = ideal
    - `ax_no_noop`: (temporary) conditionals never evaluate to NoOpinion -/
structure Authorizer (Attrs Data CM : Type) where
  /-- Ideal: authorize with complete data. -/
  fullAuthorize : Attrs → Data → UnconditionalDecision
  /-- Phase 1 (authorization): decide with only request metadata. -/
  authorize : Attrs → Decision CM
  /-- Phase 2 (admission): evaluate conditions against admission data. -/
  evaluateConditions : CM → Data → UnconditionalDecision

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
  /-- If phase 1 returns Conditional(cm), evaluating cm with data equals the ideal. -/
  ax_conditional : ∀ (attrs : Attrs) (data : Data) (cm : CM),
    authorize attrs = .Conditional cm →
    fullAuthorize attrs data = evaluateConditions cm data
  /-- TEMPORARY (relaxed when Union is added):
      A conditional decision never evaluates to NoOpinion.
      This is needed because without Union, the implementation cannot
      resume the authorizer chain after Conditional → NoOpinion. -/
  ax_no_noop : ∀ (attrs : Attrs) (data : Data) (cm : CM),
    authorize attrs = .Conditional cm →
    evaluateConditions cm data ≠ .NoOpinion

-- ============================================================================
-- Part 3: Ideal Chain Evaluation
-- ============================================================================

/-- The ideal authorization chain: run each authorizer in order with all data,
    short-circuit on Allow or Deny, continue on NoOpinion.

    This directly mirrors `union.Authorize()` (the old, unconditional method),
    which is the "gold standard" semantics. -/
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
-- Part 4: Implementation Model — Three Components
-- ============================================================================

-- 4a. Authorization Phase (union authorizer's ConditionsAwareAuthorize)
-- Reference: staging/src/k8s.io/apiserver/pkg/authorization/union/union.go:73-96

/-- Result of the authorization phase.
    In the real implementation, the decision and the authorizer that produced
    a conditional are stored in the request context via
    `request.WithConditionallyAuthorizedDecision(ctx, a, decision)`. -/
structure AuthzPhaseResult (Attrs Data CM : Type) where
  /-- The authorization decision from the chain. -/
  decision : Decision CM
  /-- The authorizer that produced a Conditional decision (if any).
      Used later by the conditions enforcer to call EvaluateConditions. -/
  conditionalAuthorizer : Option (Authorizer Attrs Data CM)

/-- The authorization phase: iterate through the authorizer chain, calling
    each authorizer's phase-1 function.

    Short-circuits on:
    - Allow (unconditional)
    - Deny (unconditional)
    - Conditional (can become allowed — always true without Union)

    Continues on:
    - NoOpinion

    Mirrors `unionAuthzHandler.ConditionsAwareAuthorize` which iterates
    authorizers and breaks when `decision.ContainsAllowOrDeny()` (simplified
    here to also break on Conditional, since without Union every Conditional
    is a leaf that ContainsAllowOrDeny would catch). -/
def authzPhase {Attrs Data CM : Type}
    (chain : List (Authorizer Attrs Data CM))
    (attrs : Attrs) : AuthzPhaseResult Attrs Data CM :=
  match chain with
  | [] => ⟨.NoOpinion, none⟩
  | a :: rest =>
    match a.authorize attrs with
    | .Allow          => ⟨.Allow, none⟩
    | .Deny           => ⟨.Deny, none⟩
    | .Conditional cm => ⟨.Conditional cm, some a⟩
    | .NoOpinion      => authzPhase rest attrs

-- 4b. WithAuthorization HTTP Filter
-- Reference: staging/src/k8s.io/apiserver/pkg/endpoints/filters/authorization.go:70-151

/-- Result of the WithAuthorization filter: either the request proceeds
    (with optional conditions to enforce later) or is rejected. -/
inductive FilterVerdict (Attrs Data CM : Type) where
  /-- Request proceeds to the handler chain (and eventually admission).
      If conditions are present, they must be enforced before the request
      reaches the storage layer. -/
  | Proceed (conditions : Option (CM × Authorizer Attrs Data CM))
  /-- Request is rejected (403 Forbidden or 500 Internal Server Error). -/
  | Reject (d : UnconditionalDecision)

/-- The WithAuthorization HTTP filter.

    Implementation flow (authorization.go:75-151):
    1. Call `a.ConditionsAwareAuthorize(ctx, attributes)` or `a.Authorize(ctx, attributes)`
    2. If unconditionallyAuthorized (Allow):
       → set audit annotations, proceed to handler
    3. If conditional and `CanBecomeAllowed()`:
       → store (authorizer, decision) in context, proceed to handler
    4. If error:
       → return 500
    5. Otherwise:
       → return 403 Forbidden -/
def withAuthorizationFilter {Attrs Data CM : Type}
    (result : AuthzPhaseResult Attrs Data CM)
    : FilterVerdict Attrs Data CM :=
  match result.decision with
  | .Allow          => .Proceed none
  | .Conditional cm =>
    match result.conditionalAuthorizer with
    | some a => .Proceed (some (cm, a))
    | none   => .Reject .Deny  -- invariant violation: conditional without source
  | .Deny           => .Reject .Deny
  | .NoOpinion      => .Reject .NoOpinion

-- 4c. AuthorizationConditionsEnforcer Admission Plugin
-- Reference: staging/src/k8s.io/apiserver/pkg/admission/plugin/authorizer/conditionsenforcer/conditionsenforcer.go:87-147

/-- The AuthorizationConditionsEnforcer validating admission plugin.

    Implementation flow (conditionsenforcer.go:87-147):
    1. Get `(authorizer, decision)` from context
       (`request.ConditionallyAuthorizedDecisionFrom(ctx)`)
    2. If not present → unconditionally authorized, `return nil` (pass through)
    3. Convert objects to request version
    4. Call `authorizer.EvaluateConditions(ctx, decision, data)`
    5. If result is Allow → pass through
    6. If error → return 500
    7. Otherwise → return 403 Forbidden -/
def conditionsEnforcer {Attrs Data CM : Type}
    (verdict : FilterVerdict Attrs Data CM)
    (data : Data) : UnconditionalDecision :=
  match verdict with
  | .Reject d              => d
  | .Proceed none          => .Allow  -- unconditionally authorized, nothing to enforce
  | .Proceed (some (cm, a)) => a.evaluateConditions cm data

-- 4d. Pipeline Composition

/-- The full implementation pipeline, composing the three stages:
    1. Authorization phase (union authorizer → `AuthzPhaseResult`)
    2. WithAuthorization filter (`AuthzPhaseResult → FilterVerdict`)
    3. AuthorizationConditionsEnforcer (`FilterVerdict → UnconditionalDecision`) -/
def pipeline {Attrs Data CM : Type}
    (chain : List (Authorizer Attrs Data CM))
    (attrs : Attrs) (data : Data) : UnconditionalDecision :=
  conditionsEnforcer (withAuthorizationFilter (authzPhase chain attrs)) data

-- ============================================================================
-- Part 5: Simplified Implementation (for proof convenience)
-- ============================================================================

/-- Simplified implementation that collapses the three stages into one
    recursive function. The proof first shows `pipeline = implChain`,
    then shows `idealChain = implChain`. -/
def implChain {Attrs Data CM : Type}
    (chain : List (Authorizer Attrs Data CM))
    (attrs : Attrs) (data : Data) : UnconditionalDecision :=
  match chain with
  | [] => .NoOpinion
  | a :: rest =>
    match a.authorize attrs with
    | .Allow          => .Allow
    | .Deny           => .Deny
    | .NoOpinion      => implChain rest attrs data
    | .Conditional cm => a.evaluateConditions cm data

-- ============================================================================
-- Part 6: Proofs
-- ============================================================================

/-- Lemma: the composed pipeline equals the simplified implChain.
    This factors out the structural argument from the semantic argument. -/
theorem pipeline_eq_implChain {Attrs Data CM : Type}
    (chain : List (Authorizer Attrs Data CM))
    (attrs : Attrs) (data : Data)
    : pipeline chain attrs data = implChain chain attrs data := by
  induction chain with
  | nil =>
    -- Both return .NoOpinion for empty chain
    rfl
  | cons a rest ih =>
    -- Unfold pipeline and implChain one step
    simp only [pipeline, authzPhase, implChain]
    -- Case split on what phase 1 returns for this authorizer
    cases hauth : a.authorize attrs with
    | Allow =>
      -- pipeline: authzPhase returns ⟨Allow, none⟩ → filter Proceed none → enforcer Allow
      -- implChain: Allow
      simp [withAuthorizationFilter, conditionsEnforcer]
    | Deny =>
      -- pipeline: authzPhase returns ⟨Deny, none⟩ → filter Reject Deny → enforcer Deny
      -- implChain: Deny
      simp [withAuthorizationFilter, conditionsEnforcer]
    | NoOpinion =>
      -- pipeline: authzPhase recurses → pipeline on rest
      -- implChain: recurses on rest
      -- After unfolding, both sides reduce to their recursive calls.
      -- `ih` speaks about `pipeline rest`, which is definitionally equal to the
      -- unfolded `conditionsEnforcer (withAuthorizationFilter (authzPhase rest attrs)) data`.
      exact ih
    | Conditional cm =>
      -- pipeline: authzPhase returns ⟨Conditional cm, some a⟩
      --   → filter Proceed (some (cm, a)) → enforcer evaluateConditions cm data
      -- implChain: evaluateConditions cm data
      simp [withAuthorizationFilter, conditionsEnforcer]

/-- **Main theorem**: The ideal single-phase chain evaluation equals the
    implementation's two-phase pipeline.

    For any list of authorizers and any request data, running all authorizers
    with complete data (short-circuiting on Allow/Deny) produces the same
    result as the implementation's split into:
    1. Authorization phase (only Attributes → possibly Conditional)
    2. WithAuthorization filter (pass/reject)
    3. AuthorizationConditionsEnforcer (evaluate conditions with admission data)

    The proof proceeds by structural induction on the authorizer chain.
    For each authorizer, it case-splits on `authorize attrs` and uses the
    correctness axioms to align `fullAuthorize` with the implementation. -/
theorem authorization_equivalence {Attrs Data CM : Type}
    (chain : List (Authorizer Attrs Data CM))
    (attrs : Attrs) (data : Data)
    : idealChain chain attrs data = pipeline chain attrs data := by
  -- Step 1: Replace pipeline with the structurally equivalent implChain
  rw [pipeline_eq_implChain]
  -- Step 2: Prove idealChain = implChain by induction
  induction chain with
  | nil =>
    -- Base case: both return .NoOpinion
    rfl
  | cons a rest ih =>
    -- Inductive case: show the step for authorizer `a` followed by `rest`.
    -- We case-split on what `a.authorize attrs` returns (phase 1 decision),
    -- then use the correctness axioms to rewrite `a.fullAuthorize` in idealChain
    -- to match implChain. `simp` is used to force iota-reduction of match
    -- expressions on known constructors after rewriting.
    cases hauth : a.authorize attrs with
    | Allow =>
      -- Phase 1 returned Allow.
      -- By ax_allow: a.fullAuthorize attrs data = .Allow
      -- So idealChain returns .Allow, and implChain returns .Allow.
      simp [idealChain, implChain, a.ax_allow attrs data hauth, hauth]
    | Deny =>
      -- Phase 1 returned Deny.
      -- By ax_deny: a.fullAuthorize attrs data = .Deny
      simp [idealChain, implChain, a.ax_deny attrs data hauth, hauth]
    | NoOpinion =>
      -- Phase 1 returned NoOpinion.
      -- By ax_noOpinion: a.fullAuthorize attrs data = .NoOpinion
      -- Both sides recurse on `rest`; apply the induction hypothesis.
      simp only [idealChain, implChain, hauth, a.ax_noOpinion attrs data hauth]
      exact ih
    | Conditional cm =>
      -- Phase 1 returned Conditional(cm).
      -- By ax_conditional: a.fullAuthorize attrs data = a.evaluateConditions cm data
      simp only [idealChain, implChain, hauth, a.ax_conditional attrs data cm hauth]
      -- Now the goal is (after reduction):
      --   (match a.evaluateConditions cm data with
      --    | Allow => Allow | Deny => Deny | NoOpinion => idealChain rest attrs data)
      --   = a.evaluateConditions cm data
      --
      -- Case split on the evaluation result:
      cases heval : a.evaluateConditions cm data with
      | Allow =>
        -- match .Allow with ... = .Allow, and RHS = .Allow
        simp
      | Deny =>
        -- match .Deny with ... = .Deny, and RHS = .Deny
        simp
      | NoOpinion =>
        -- This case is impossible by ax_no_noop
        exact absurd heval (a.ax_no_noop attrs data cm hauth)

-- ============================================================================
-- Part 7: Concrete ConditionsMap Model (reference)
-- ============================================================================

-- This section defines concrete condition types mirroring the implementation.
-- It is NOT used by the main theorem (which is abstract over CM) but provides
-- the groundwork for a future refinement proof.

section ConcreteConditionsMap

/-- The effect of a condition evaluating to true.
    Maps to `authorizer.ConditionEffect` and `ConditionEffectAllow/Deny/NoOpinion`. -/
inductive ConditionEffect where
  | Allow
  | Deny
  | NoOpinion
  deriving Repr, DecidableEq, BEq

/-- A single condition entry in a ConditionsMap.
    Maps to `authorizer.Condition` (the interface). Simplified: the condition
    is modelled as a boolean function of the admission data. -/
structure ConditionEntry (Data : Type) where
  /-- Unique identifier (label key format in the implementation). -/
  id : String
  /-- How evaluating to `true` should be treated. -/
  effect : ConditionEffect
  /-- The condition itself: a pure function from admission data to Bool.
      In the real implementation, this is `Condition.Evaluate()`. -/
  evaluate : Data → Bool

/-- A concrete conditions map, mirroring `authorizer.ConditionsMap`.
    Conditions are stored in a flat list; the implementation pre-sorts them
    by effect into `denyConditions/noOpinionConditions/allowConditions`. -/
structure ConcConditionsMap (Data : Type) where
  conditions : List (ConditionEntry Data)

/-- Does this conditions map have at least one Allow condition?
    Mirrors `ConditionsMap.CanBecomeAllowed()`. -/
def ConcConditionsMap.canBecomeAllowed (cm : ConcConditionsMap Data) : Bool :=
  cm.conditions.any (fun c => c.effect == .Allow)

/-- Evaluate a concrete conditions map against admission data.
    Mirrors `ConditionsMap.Evaluate()` from conditions.go:700-870.

    Priority order (higher precedence first):
    1. If any Deny condition evaluates to true → Deny
    2. If any NoOpinion condition evaluates to true → NoOpinion
    3. If any Allow condition evaluates to true → Allow
    4. Otherwise → NoOpinion (no conditions matched) -/
def ConcConditionsMap.evaluate (cm : ConcConditionsMap Data) (data : Data)
    : UnconditionalDecision :=
  -- Phase 1: Check Deny conditions
  if cm.conditions.any (fun c => c.effect == .Deny && c.evaluate data) then
    .Deny
  -- Phase 2: Check NoOpinion conditions
  else if cm.conditions.any (fun c => c.effect == .NoOpinion && c.evaluate data) then
    .NoOpinion
  -- Phase 3: Check Allow conditions
  else if cm.conditions.any (fun c => c.effect == .Allow && c.evaluate data) then
    .Allow
  -- Phase 4: No conditions matched
  else
    .NoOpinion

/-- Maximum number of conditions per map (implementation constant). -/
def maxConditionsPerMap : Nat := 128

end ConcreteConditionsMap

-- ============================================================================
-- Part 8: Future Extension Stubs
-- ============================================================================

section FutureExtensions

/-- Decision type extended with the Union variant, for the full model.
    The Union variant forms an ordered tree where leaves are
    Allow/Deny/NoOpinion/ConditionsMap and internal nodes are Union.
    Maps to `ConditionsAwareDecisionTypeUnion`. -/
inductive DecisionWithUnion (CM : Type) where
  | Allow
  | Deny
  | NoOpinion
  | Conditional (cm : CM)
  | Union (decisions : List (DecisionWithUnion CM))

/-- With Union, `CanBecomeAllowed` is recursive:
    - Allow → true
    - Deny → false (short-circuits the chain)
    - NoOpinion → false
    - Conditional cm → true (if cm has Allow conditions)
    - Union ds → any sub-decision can become allowed,
      AND no preceding Deny blocks it. -/
def DecisionWithUnion.canBecomeAllowed : DecisionWithUnion CM → Bool
  | .Allow          => true
  | .Deny           => false
  | .NoOpinion      => false
  | .Conditional _  => true
  | .Union ds       => go ds
where
  go : List (DecisionWithUnion CM) → Bool
    | []      => false
    | d :: rest =>
      match d with
      | .Deny => false  -- Deny blocks everything after it
      | .Allow => true
      | .Conditional _ => true
      | .Union ds' => go ds' || go rest
      | .NoOpinion => go rest

/-- STUB: With Union, the `ax_no_noop` axiom can be relaxed.
    Instead, the Union decision tree captures the remaining authorizer chain,
    so if a Conditional evaluates to NoOpinion, evaluation continues to the
    next sub-decision in the Union.

    The relaxed equivalence theorem would state:
    `idealChain chain attrs data = pipelineWithUnion chain attrs data`
    where `pipelineWithUnion` uses `DecisionWithUnion` and recursively
    evaluates Union decisions via the union authorizer's `EvaluateConditions`. -/
theorem authorization_equivalence_with_union
    {Attrs Data CM : Type}
    (_chain : List (Authorizer Attrs Data CM))
    (_attrs : Attrs) (_data : Data)
    : True := by  -- placeholder type; real statement uses DecisionWithUnion
  trivial
  -- sorry  -- To be implemented when Union support is added

/-- STUB: Prove that the concrete `ConcConditionsMap.evaluate` correctly
    implements the priority semantics (Deny > NoOpinion > Allow). -/
theorem conditionsMap_evaluate_priority
    {Data : Type}
    (cm : ConcConditionsMap Data) (data : Data)
    -- If there's a true Deny condition, the result is Deny
    (hDeny : cm.conditions.any (fun c => c.effect == .Deny && c.evaluate data) = true)
    : cm.evaluate data = .Deny := by
  simp [ConcConditionsMap.evaluate, hDeny]

end FutureExtensions

end ConditionalAuthz
