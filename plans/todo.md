# TODO

- Compound authorization for patch -> create ok (plus patch + authorizer + ns test)
- Aggregated API server integration test partially done (need to verify test)
- Webhook authorizer to support multiple conditionsets partially done (tests missing)
- Better knowledge when a request is conditionally authorized partially done (connect missing)
- Make ACR endpoint configurable in AuthorizationConfig partially done (needs unit tests)
- Real endpoint for AuthorizationConditionsReview partially done (needs unit tests)
- CEL builtin evaluator ok (more unit tests)
- More unit tests for various parts
- Implement compound authz for connect?
- (Maybe) support for optimized CEL conditions
- (Maybe) lazy evaluation
- (Maybe) showcase impersonation support
- (Maybe) Evaluate conditions to conditions
  - we should add a "target" field for the conditionset, and a targets collector
    for the decision.
  - then the withauthorization filter can check that only the "admission" target
    exists, but the impersonation filter would allow "admission" or
    "impersonation" targets.
  - the impersonation filter would require that the output after eval of
    impersonation targets must only be "admission" targets

- we should just encode directly the conditionset on the SAR status.
- should we store evaluation errors with the decision as well? should we
  altogether build in the error into the decision, that might actually be the
  cleanest!
- it's optional for builtin evaluators to evaluate things.
  - however, a builtin evaluator could already have figured out that an earlier
    sub-part is `NoOpinion`, and thus could it return a partially-pruned
    decision. This could be implemented later, however, but one should make sure
    that already the builtin evaluator has the possibility of saying "I did not
    evaluate this; I might have simplified it"

- Could do a lattice-like subset check of evaluation: Allow/Deny/NoOpinion are
  uncomparable in this logic, neither can be evaluated into the other.
  - This would make sure evaluator errors are caught and invalidated.
  - "foo || bar" > "foo" > "foo && baz"
  - Evaluation of a ConditionSet can only remove conditions, never add, "new IDs
    is subset of old IDs".
  - A condition, its effect and its description can never change
- Do we need a DeepCopy method for Decisions?
