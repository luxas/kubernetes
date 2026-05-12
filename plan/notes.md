# Lean notes

- Should go stronger and show that not just isAllow equals, but the exact returned decision is equal
- The withauthorization handling wrt HTTP codes should be equal to the admission controller's handling
- It should hold that `!isUnconditional(authorizer.ConditionsAwareAuthorize(...)) => authorizer.ConditionsAwareAuthorize(...) == authorizer.Authorize(...)`
  - One kind of "axiom"/property we want authorizers to satisfy is that `Authorize` always folds down soundly, that is, if it wanted to return a conditional with `effect=Deny`, it must return `decision=Deny`.
  - Another property of authorizers should be that if `authorizer.Authorize(...) == Allow => authorizer.ConditionsAwareAuthorize(...) == Allow`
