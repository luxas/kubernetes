# Plan: Model the union authorizer as an `Authorizer` instance

## Context

We have an `Authorizer` structure with an `ax_authorizer : AuthorizerContract ...` field. We have transliterated `unionAuthorize`, `unionConditionsAwareAuthorize`, and `unionEvaluateConditions` as standalone functions. The question: can we construct an `Authorizer` from a `List Authorizer`, proving `ax_authorizer` during construction?

## Approach

Define `def mkUnionAuthorizer (handlers : List Authorizer) : Authorizer` that bundles:

```
authorize             := unionAuthorize handlers
conditionsAwareAuthorize := Decision.Union (handlers.map (·.conditionsAwareAuthorize))
evaluateConditions    := unionEvaluateConditions (unionConditionsAwareAuthorize handlers)
ax_authorizer         := <proof>
```

The `AuthorizerContract` for the `Union` case requires two things:

1. **`evaluateConditions = conditionsAwareAuthorize.Ideal`**
   - `conditionsAwareAuthorize.Ideal = unionIdealAuthorize (handlers.map ...)` by definition
   - `unionEvaluateConditions entries = unionIdeal handlers` by `evaluate_eq_ideal`
   - Need to connect these: show `unionIdealAuthorize (handlers.map (·.conditionsAwareAuthorize))` equals `unionIdeal handlers` (which uses `idealAuthorize = conditionsAwareAuthorize.Ideal`)

2. **`authorize` matches `FailClosedDecision`**:
   - If `FailClosedDecision(Union decisions) = Deny` → `unionAuthorize handlers = Deny`
   - If `FailClosedDecision(Union decisions) ≠ Deny` → `unionAuthorize handlers = NoOpinion`
   - Need a new theorem: `unionAuthorize` returns at most what `FailClosedDecision` allows

## Key theorems needed

### Already proven
- `evaluate_eq_ideal`: `unionEvaluateConditions entries = unionIdeal handlers`
- `failClosed_not_deny_implies_ideal_not_deny`: FailClosed ≠ Deny → Ideal ≠ Deny
- `metadata_allow_implies_ideal_allow`: unionAuthorize = Allow → unionIdeal = Allow

### New theorems needed

1. **`unionIdealAuthorize_eq_unionIdeal`**: Connect `unionIdealAuthorize (handlers.map (·.conditionsAwareAuthorize))` to `unionIdeal handlers`. These iterate the same chain but one uses `conditionsAwareAuthorize.Ideal` per element and the other uses `idealAuthorize` (which equals `conditionsAwareAuthorize.Ideal` by definition). Should be straightforward by induction.

2. **`unionAuthorize_failClosed`**: Show `unionAuthorize handlers` agrees with `FailClosedDecision` of the union decision:
   - When any handler has `authorize = Deny`, `unionAuthorize` returns `Deny`
   - By the contract, `authorize = Deny` iff `FailClosedDecision = Deny` (for the conditional case)
   - For unconditional cases, `authorize = Deny` iff `conditionsAwareAuthorize = Deny` iff `FailClosedDecision = Deny`

   More precisely: `FailClosedDecision(Union decisions) = Deny → unionAuthorize = Deny`, and `FailClosedDecision(Union decisions) ≠ Deny → unionAuthorize = NoOpinion` (since the metadata path can only return NoOpinion when no handler returns Allow or Deny, and Allow is impossible because that would mean some handler allowed which means FailClosed would also indicate a non-NoOpinion via different reasoning).

   Actually this is subtle. `unionAuthorize` can return Allow (if some handler's `authorize = Allow`). The contract for the Union case says:
   - If `FailClosedDecision = Deny` → `authorize = Deny`
   - Otherwise → `authorize = NoOpinion`

   But `unionAuthorize` CAN return Allow! This means the contract as stated cannot hold for the union if any sub-authorizer unconditionally allows. However, looking at `AuthorizerContract`:

   ```
   | .Union _ =>
       evaluateConditions = conditionsAwareAuthorize.Ideal ∧
       match conditionsAwareAuthorize.FailClosedDecision with
       | .Deny => authorize = .Deny
       | _ => authorize = .NoOpinion
   ```

   This says `authorize` must be either Deny or NoOpinion for a Union — never Allow. But `unionAuthorize` returns Allow when a sub-handler allows! This is a real mismatch.

   The resolution: when a sub-handler returns `Allow` from `conditionsAwareAuthorize`, the union's `conditionsAwareAuthorize` short-circuits and returns `Allow` directly (not `Union`). So the union decision is `Allow`, not `Union [...]`. The `Union` variant only appears when NO sub-handler returned Allow or Deny — only NoOpinion and Conditional.

   In that case, `unionAuthorize` can only return NoOpinion or Deny (never Allow), because:
   - Sub-handlers with `conditionsAwareAuthorize = NoOpinion` have `authorize = NoOpinion` (by contract)
   - Sub-handlers with `conditionsAwareAuthorize = ConditionsMap/Union` have `authorize = Deny` or `NoOpinion` (by contract — FailClosed is Deny or NoOpinion)

   So the union's `authorize` = `unionAuthorize handlers` is correctly Deny or NoOpinion, matching the contract.

## Implementation plan

### File: `plan/ConditionalAuthzFromScratch.lean`

1. Add helper: `unionConditionsAwareDecision` that returns the `ConditionsAwareDecision` the union produces (mirroring `ConditionsAwareDecisionUnion(decisions...)`)
2. Add theorem connecting `unionIdealAuthorize` on the mapped decisions to `unionIdeal`
3. Add theorem that when all sub-decisions are NoOpinion/Conditional (no Allow/Deny), `unionAuthorize` returns only Deny or NoOpinion
4. Add theorem connecting `unionAuthorize`'s result to `FailClosedDecision` of the union decision
5. Define `mkUnionAuthorizer : List Authorizer → Authorizer` with the proven `ax_authorizer`

## Verification

`lean plan/ConditionalAuthzFromScratch.lean` — should compile with no errors and no sorry.
