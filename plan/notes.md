# Lean notes

- Should go stronger and show that not just isAllow equals, but the exact returned decision is equal
- The withauthorization handling wrt HTTP codes should be equal to the admission controller's handling
- It should hold that `!isUnconditional(authorizer.ConditionsAwareAuthorize(...)) => authorizer.ConditionsAwareAuthorize(...) == authorizer.Authorize(...)`
  - One kind of "axiom"/property we want authorizers to satisfy is that `Authorize` always folds down soundly, that is, if it wanted to return a conditional with `effect=Deny`, it must return `decision=Deny`.
  - Another property of authorizers should be that if `authorizer.Authorize(...) == Allow => authorizer.ConditionsAwareAuthorize(...) == Allow`
- The transpiled Lean code should have also the `Union` type.
- The transpiled code should be such that the CanBecomeAllowed is directly derived from the ConditionsMap structure, not kept abstract
- We should make framework to fuzz authorizers against the properties that are desired.
- The Pipeline should be strengthened, and we should keep WithAuthorization and ConditionsEnforcement separate. Distinguish between 
- Error handling should be taken into account
- Make sure there is no user-facing behavioral change between the two, which includes the gotcha of 500 (authorize with error) vs 403.
- Actually guard against authorizers misbehaving (returning Allow or Deny when there were no such effects in the conditions) in our framework instead of this assumption


-- TODO: This should use the ContainsAllowOrDeny, and also use the DecisionUnion constructor