import TranspiledAuthz
import Lean.Data.Json

/-!
# FFI exports for the transpiled authorization model.

Exposes the core transpiled functions via `@[export]` so they can be called
from Go (or any language) through Lean's C FFI. Uses JSON as the serialization
format for inputs and outputs.

- `lean_authz_evaluate(ByteArray) → String`: Given a JSON-encoded list of
  handler descriptions, computes UnionAuthorize, Pipeline, UnionEvaluateConditions,
  and SliceCBA, returning all results as a JSON string.
-/

open TranspiledAuthz Lean

-- ============================================================================
-- JSON-serializable types
-- ============================================================================

structure HandlerJson where
  authorize              : String
  conditionsAwareAuthorize : String
  cmCanBecomeAllowed     : Bool
  evaluateConditions     : String
  deriving FromJson, ToJson

structure AuthzInput where
  handlers : Option (List HandlerJson) := none
  deriving FromJson, ToJson

structure AuthzOutput where
  unionAuthorize        : String
  pipeline              : String
  evaluateEntries       : String
  sliceCBA              : Bool
  deriving FromJson, ToJson

structure ErrorOutput where
  error : String
  deriving ToJson

-- ============================================================================
-- Conversion helpers
-- ============================================================================

def parseDecision (s : String) : Decision :=
  match s with
  | "Allow"     => .Allow
  | "Deny"      => .Deny
  | _           => .NoOpinion

def parseLeafDecision (s : String) : LeafDecision :=
  match s with
  | "Allow"          => .Allow
  | "Deny"           => .Deny
  | "NoOpinion"      => .NoOpinion
  | "ConditionsMap"  => .ConditionsMap
  | _                => .NoOpinion

def decisionToString : Decision → String
  | .Allow     => "Allow"
  | .Deny      => "Deny"
  | .NoOpinion => "NoOpinion"

/-- Validate and construct a Handler from JSON, or return an error if the
    per-authorizer coherence axioms would not hold. This makes the axioms
    true by construction — no `sorry` or `unsafe` needed. -/
def toHandler (h : HandlerJson) : Except String Handler :=
  let auth := parseDecision h.authorize
  let ca := parseLeafDecision h.conditionsAwareAuthorize
  let cba := h.cmCanBecomeAllowed
  let eval := parseDecision h.evaluateConditions
  -- Validate coherence: the two-phase split must agree with the single-phase result.
  match ca with
  | .Allow =>
    if auth != .Allow then .error s!"incoherent: conditionsAwareAuthorize=Allow but authorize={h.authorize}"
    else .ok { authorize := .Allow, conditionsAwareAuthorize := .Allow,
               cmCanBecomeAllowed := cba, evaluateConditions := eval,
               ax_allow := fun _ => rfl, ax_deny := fun h => absurd h (by decide),
               ax_noOpinion := fun h => absurd h (by decide),
               ax_conditional := fun h => absurd h (by decide),
               ax_cba_sound := fun h => absurd h (by decide) }
  | .Deny =>
    if auth != .Deny then .error s!"incoherent: conditionsAwareAuthorize=Deny but authorize={h.authorize}"
    else .ok { authorize := .Deny, conditionsAwareAuthorize := .Deny,
               cmCanBecomeAllowed := cba, evaluateConditions := eval,
               ax_allow := fun h => absurd h (by decide), ax_deny := fun _ => rfl,
               ax_noOpinion := fun h => absurd h (by decide),
               ax_conditional := fun h => absurd h (by decide),
               ax_cba_sound := fun h => absurd h (by decide) }
  | .NoOpinion =>
    if auth != .NoOpinion then .error s!"incoherent: conditionsAwareAuthorize=NoOpinion but authorize={h.authorize}"
    else .ok { authorize := .NoOpinion, conditionsAwareAuthorize := .NoOpinion,
               cmCanBecomeAllowed := cba, evaluateConditions := eval,
               ax_allow := fun h => absurd h (by decide), ax_deny := fun h => absurd h (by decide),
               ax_noOpinion := fun _ => rfl,
               ax_conditional := fun h => absurd h (by decide),
               ax_cba_sound := fun h => absurd h (by decide) }
  | .ConditionsMap =>
    -- Match on (authorize, evaluateConditions) concretely to make axioms hold by rfl.
    -- Reject incoherent combinations (auth ≠ eval, or cba=false with eval=Allow).
    let mk (d : Decision) (cba_ok : cba = false → d ≠ .Allow) : Except String Handler :=
      .ok { authorize := d, conditionsAwareAuthorize := .ConditionsMap,
            cmCanBecomeAllowed := cba, evaluateConditions := d,
            ax_allow := fun h => absurd h (by decide),
            ax_deny := fun h => absurd h (by decide),
            ax_noOpinion := fun h => absurd h (by decide),
            ax_conditional := fun _ => rfl,
            ax_cba_sound := fun _ => cba_ok }
    match parseDecision h.authorize, parseDecision h.evaluateConditions with
    | .Allow, .Allow =>
      if hcba : cba = false
      then .error "incoherent: cmCanBecomeAllowed=false but evaluateConditions=Allow"
      else mk .Allow (fun h => absurd h hcba)
    | .Deny, .Deny => mk .Deny (fun _ h => absurd h (by decide))
    | .NoOpinion, .NoOpinion => mk .NoOpinion (fun _ h => absurd h (by decide))
    | _, _ => .error s!"incoherent: authorize={h.authorize} ≠ evaluateConditions={h.evaluateConditions}"

-- ============================================================================
-- Core FFI function
-- ============================================================================

@[export lean_authz_evaluate]
def leanAuthzEvaluate (input : @& ByteArray) : String :=
  let inputStr := String.fromUTF8! input
  match Json.parse inputStr >>= fromJson? (α := AuthzInput) with
  | .error e => toString (toJson (ErrorOutput.mk s!"parse error: {e}"))
  | .ok inp =>
    match (inp.handlers.getD []).mapM toHandler with
    | .error e => toString (toJson (ErrorOutput.mk e))
    | .ok handlers =>
      let entries := UnionConditionsAwareAuthorize handlers
      let result : AuthzOutput := {
        unionAuthorize := decisionToString (UnionAuthorize handlers)
        pipeline := decisionToString (PipelineDecision handlers)
        evaluateEntries := decisionToString (UnionEvaluateConditions entries)
        sliceCBA := UnionSliceCanBecomeAllowed entries
      }
      toString (toJson result)
