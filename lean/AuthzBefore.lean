/-
  AuthzBefore.lean — Pre-KEP Kubernetes Authorization Model

  Models the authorization decision pipeline as it exists before KEP-5681,
  after the Phase 0 refactoring (Decision as a value type, 2-value return).

  This captures the core semantics of:
  - The Decision type (Allow, Deny, NoOpinion) with reason
  - The Authorizer interface: Attributes → (Decision, Option Error)
  - The union/chain authorizer: first Allow or Deny wins
  - The WithAuthorization HTTP filter
-/

namespace Kubernetes.AuthzBefore

-- ============================================================================
-- Core Types
-- ============================================================================

/-- The three possible authorization decisions. -/
inductive DecisionKind where
  | allow
  | deny
  | noOpinion
  deriving Repr, DecidableEq, BEq

/-- A Decision bundles a DecisionKind with a human-readable reason. -/
structure Decision where
  kind : DecisionKind
  reason : String := ""
  deriving Repr

/-- Smart constructors matching the Go API. -/
def Decision.allow (reason : String := "") : Decision := ⟨.allow, reason⟩
def Decision.deny (reason : String := "") : Decision := ⟨.deny, reason⟩
def Decision.noOpinion (reason : String := "") : Decision := ⟨.noOpinion, reason⟩

/-- Predicates matching the Go methods. -/
def Decision.isAllowed (d : Decision) : Bool := d.kind == .allow
def Decision.isDenied (d : Decision) : Bool := d.kind == .deny
def Decision.isNoOpinion (d : Decision) : Bool := d.kind == .noOpinion

/-- A decision is concrete if it is Allow or Deny (i.e., not NoOpinion).
    In the pre-KEP model, all decisions are "concrete" in the sense that
    there are no conditional decisions, but this definition matches the
    chain short-circuit condition. -/
def Decision.isDefinitive (d : Decision) : Bool :=
  d.isAllowed || d.isDenied

-- ============================================================================
-- Attributes (request context)
-- ============================================================================

/-- Abstract request attributes. We leave this opaque since the authorization
    decision logic does not inspect the attribute structure — individual
    authorizer implementations do. -/
structure Attributes where
  /-- The user making the request -/
  user : String
  /-- The verb (get, list, create, update, delete, etc.) -/
  verb : String
  /-- The API group -/
  apiGroup : String
  /-- The resource type -/
  resource : String
  /-- The namespace (empty for cluster-scoped) -/
  namespace : String
  /-- The specific resource name -/
  name : String
  /-- Whether this is a resource request (vs. non-resource URL) -/
  isResourceRequest : Bool
  /-- The non-resource URL path (for non-resource requests) -/
  path : String
  deriving Repr

-- ============================================================================
-- Authorizer
-- ============================================================================

/-- An error from an authorizer. -/
structure AuthzError where
  message : String
  deriving Repr

/-- The result of calling an authorizer: a Decision plus an optional error.
    This models the Go signature: `Authorize(ctx, a) (Decision, error)` -/
structure AuthzResult where
  decision : Decision
  error : Option AuthzError := none
  deriving Repr

/-- An Authorizer is a function from Attributes to an AuthzResult.
    This models the Go interface:
      type Authorizer interface {
          Authorize(ctx context.Context, a Attributes) (Decision, error)
      }
    We omit the context parameter as it carries no authorization-relevant state
    in the pre-KEP model. -/
def Authorizer := Attributes → AuthzResult

-- ============================================================================
-- Union (Chain) Authorizer
-- ============================================================================

/-- Run a chain of authorizers. The first Allow or Deny short-circuits.
    NoOpinion authorizers are skipped, with their reasons and errors
    aggregated.

    This directly models the Go implementation in union/union.go:
      for _, currAuthzHandler := range authzHandler {
          decision, err := currAuthzHandler.Authorize(ctx, a)
          if err != nil { errlist = append(errlist, err) }
          if decision.IsAllowed() || decision.IsDenied() {
              return decision, err
          }
          if reason := decision.Reason(); len(reason) != 0 {
              reasonlist = append(reasonlist, reason)
          }
      }
      return DecisionNoOpinion(join(reasonlist)), aggregate(errlist)
-/
def chainAuthorize
    (authorizers : List Authorizer) (attrs : Attributes) : AuthzResult :=
  go authorizers [] []
where
  go : List Authorizer → List String → List AuthzError → AuthzResult
  | [], reasons, errors =>
    { decision := Decision.noOpinion (String.intercalate "\n" reasons)
      error := if errors.isEmpty then none
               else some ⟨String.intercalate "; " (errors.map (·.message))⟩ }
  | authz :: rest, reasons, errors =>
    let result := authz attrs
    let errors' := match result.error with
      | some e => errors ++ [e]
      | none => errors
    if result.decision.isDefinitive then
      -- Short-circuit: return this decision with its own error
      result
    else
      -- NoOpinion: accumulate reason and continue
      let reasons' := if result.decision.reason.isEmpty then reasons
                      else reasons ++ [result.decision.reason]
      go rest reasons' errors'

/-- Construct a union authorizer from a list of authorizers. -/
def unionAuthorizer (authorizers : List Authorizer) : Authorizer :=
  fun attrs => chainAuthorize authorizers attrs

-- ============================================================================
-- WithAuthorization HTTP Filter
-- ============================================================================

/-- The outcome of the WithAuthorization filter. -/
inductive FilterOutcome where
  /-- Request is allowed to proceed. -/
  | proceed (decision : Decision)
  /-- Request is forbidden (403). -/
  | forbidden (reason : String)
  deriving Repr

/-- The WithAuthorization HTTP filter. If the authorizer allows the request,
    it proceeds. Otherwise, a 403 Forbidden is returned.

    Models the Go implementation in filters/authorization.go:
      authorized, err := a.Authorize(ctx, attributes)
      if authorized.IsAllowed() {
          // proceed
      } else {
          // 403 Forbidden
      }
-/
def withAuthorization (authz : Authorizer) (attrs : Attributes) : FilterOutcome :=
  let result := authz attrs
  if result.decision.isAllowed then
    .proceed result.decision
  else
    .forbidden result.decision.reason

-- ============================================================================
-- Common Authorizer Implementations
-- ============================================================================

/-- An authorizer that always allows. Models alwaysAllowAuthorizer. -/
def alwaysAllow : Authorizer :=
  fun _ => { decision := Decision.allow "always allow" }

/-- An authorizer that always denies. Models alwaysDenyAuthorizer. -/
def alwaysDeny : Authorizer :=
  fun _ => { decision := Decision.deny "always deny" }

/-- An authorizer that always returns NoOpinion. -/
def alwaysNoOpinion : Authorizer :=
  fun _ => { decision := Decision.noOpinion "" }

-- ============================================================================
-- Basic Properties (as Prop-valued definitions, proved in Properties.lean)
-- ============================================================================

/-- A decision is in the set {allow, deny, noOpinion}. -/
theorem decision_trichotomy (d : Decision) :
    d.kind = .allow ∨ d.kind = .deny ∨ d.kind = .noOpinion := by
  cases d.kind <;> simp

/-- An empty chain always returns NoOpinion. -/
theorem empty_chain_noOpinion (attrs : Attributes) :
    (chainAuthorize [] attrs).decision.kind = .noOpinion := by
  simp [chainAuthorize, chainAuthorize.go]

/-- A singleton allow chain returns Allow. -/
theorem singleton_allow_chain (attrs : Attributes) :
    (chainAuthorize [alwaysAllow] attrs).decision.kind = .allow := by
  simp [chainAuthorize, chainAuthorize.go, alwaysAllow,
        Decision.isDefinitive, Decision.isAllowed, Decision.isDenied]

/-- A singleton deny chain returns Deny. -/
theorem singleton_deny_chain (attrs : Attributes) :
    (chainAuthorize [alwaysDeny] attrs).decision.kind = .deny := by
  simp [chainAuthorize, chainAuthorize.go, alwaysDeny,
        Decision.isDefinitive, Decision.isAllowed, Decision.isDenied]

/-- Prepending a NoOpinion authorizer to a chain does not change
    the decision kind. -/
theorem noOpinion_prefix_preserves_kind (authzs : List Authorizer) (attrs : Attributes)
    (h : ∀ a, (alwaysNoOpinion a).decision.kind = .noOpinion) :
    (chainAuthorize (alwaysNoOpinion :: authzs) attrs).decision.kind =
    (chainAuthorize authzs attrs).decision.kind := by
  simp [chainAuthorize, chainAuthorize.go, alwaysNoOpinion,
        Decision.isDefinitive, Decision.isAllowed, Decision.isDenied]

end Kubernetes.AuthzBefore
