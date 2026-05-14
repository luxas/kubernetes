
namespace ConditionalAuthzFromScratch

-- ============================================================================
-- Types
-- ============================================================================

inductive Decision where
  | Deny | Allow | NoOpinion
  deriving Repr, DecidableEq, BEq

structure ConditionsMap where
  hasDenyCondition : Bool
  hasAllowCondition : Bool
  evaluate : Decision

  ax_at_least_one_allow_or_deny: hasDenyCondition = true ∨ hasAllowCondition = true
  ax_no_allow_cond_implies_never_allow : ¬hasAllowCondition → evaluate ≠ .Allow
  ax_no_deny_cond_implies_never_deny : ¬hasDenyCondition → evaluate ≠ .Deny
  deriving Repr, DecidableEq

def ConditionsMap.FailClosedDecision (c : ConditionsMap) : Decision :=
  if c.hasDenyCondition then .Deny else .NoOpinion

def ConditionsMap.CanBecomeAllowed (c : ConditionsMap) : Bool :=
  c.hasAllowCondition

def ConditionsMap.Ideal (c : ConditionsMap) : Decision :=
  c.evaluate

/-- A conditions-aware decision: either a leaf decision, or a union (chain) of decisions.
    Mirrors Go's `ConditionsAwareDecision`. -/
inductive ConditionsAwareDecision where
  | Allow
  | Deny
  | NoOpinion
  | ConditionsMap (cm: ConditionsMap)
  | Union (decisions : List ConditionsAwareDecision)
  deriving Repr

/-- Returns the decision to fail closed with when processing fails.
    If the decision contains any Deny (leaf or condition), we must fail closed with Deny —
    otherwise NoOpinion. -/
def ConditionsAwareDecision.FailClosedDecision : ConditionsAwareDecision → Decision
  | .Allow     => .NoOpinion
  | .NoOpinion => .NoOpinion
  | .Deny      => .Deny
  | .ConditionsMap c => c.FailClosedDecision
  | .Union authorizers => foldFailClosed authorizers
where
  foldFailClosed : List ConditionsAwareDecision → Decision
    | []      => .NoOpinion
    | d :: ds =>
      match d.FailClosedDecision with
      | .Deny => .Deny
      | _     => foldFailClosed ds

/-- Returns true if the decision tree contains at least one Allow or Deny leaf. -/
def ConditionsAwareDecision.ContainsAllowOrDeny : ConditionsAwareDecision → Bool
  | .Allow     => true
  | .Deny      => true
  | .NoOpinion => false
  | .ConditionsMap _ => false
  | .Union ds => anyContainsAllowOrDeny ds
where
  anyContainsAllowOrDeny : List ConditionsAwareDecision → Bool
    | []      => false
    | d :: ds => d.ContainsAllowOrDeny || anyContainsAllowOrDeny ds

/-- Returns true if there exists some ConditionsData for which the decision could evaluate to Allow. -/
def ConditionsAwareDecision.CanBecomeAllowed : ConditionsAwareDecision → Bool
  | .Allow     => true
  | .Deny      => false
  | .NoOpinion => false
  | .ConditionsMap c => c.CanBecomeAllowed
  | .Union ds => anyCanBecomeAllowed ds
where
  anyCanBecomeAllowed : List ConditionsAwareDecision → Bool
    | []      => false
    | d :: ds => d.CanBecomeAllowed || anyCanBecomeAllowed ds

def unionIdealAuthorize(decisions : List ConditionsAwareDecision) : Decision :=
  match decisions with
  | [] => .NoOpinion
  | d :: rest =>
    match d with
    | .Allow     => .Allow
    | .Deny      => .Deny
    | .NoOpinion => unionIdealAuthorize rest
    | .ConditionsMap cm => cm.Ideal
    | .Union subDecisions => unionIdealAuthorize subDecisions

/-- Returns the idealized unconditional decision from a Decision tree. -/
def ConditionsAwareDecision.Ideal : ConditionsAwareDecision → Decision
  | .Allow     => .Allow
  | .Deny      => .Deny
  | .NoOpinion => .NoOpinion
  | .ConditionsMap cm => cm.Ideal
  | .Union decisions => unionIdealAuthorize decisions

-- The axioms of the authorizer. The conditionsAwareAuthorize "controls" what authorize and evaluateConditions should return
def AuthorizerContract (conditionsAwareAuthorize : ConditionsAwareDecision)
    (authorize evaluateConditions : Decision) : Prop :=
  match conditionsAwareAuthorize with
  | .Allow     => authorize = .Allow ∧ evaluateConditions = .Deny
  | .Deny      => authorize = .Deny ∧ evaluateConditions = .Deny
  | .NoOpinion => authorize = .NoOpinion ∧ evaluateConditions = .Deny
  | .ConditionsMap _ | .Union _ =>
      evaluateConditions = conditionsAwareAuthorize.Ideal ∧
      match conditionsAwareAuthorize.FailClosedDecision with -- TODO: Theorem that says FailClosedDecision can never be false
      | .Deny => authorize = .Deny
      | _ => authorize = .NoOpinion

/-- An individual authorizer, with pre-bound attrs and data.
    See the module docstring for a description of each field. -/
structure Authorizer where
  authorize      : Decision
  conditionsAwareAuthorize : ConditionsAwareDecision
  evaluateConditions     : Decision

  -- Axioms where an exhaustive match
  ax_authorizer : AuthorizerContract conditionsAwareAuthorize authorize evaluateConditions
