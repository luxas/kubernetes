# Worklist

## Important

- Add back `SetAuthorizer`, add a test that shows an existing conditions-unaware `SetAuthorizer`-based impl does not start panicing or fail validation.

## Small

- From a `6d78dfd60cfeddcd3e47a92306571eab155ea7ce`:
  - immutability/concurrency-safety test for `ConditionsAwareDecision`
  - symmetric Allow-with-non-nil-error case is not covered in `TestConditionsAwareDecision`
- From c 
  - Fix `TODO(luxas): Add a test for getting a conditional decision from ConditionsAwareAuthorize, and evaluating a condition, once introduced`
    - The "conditional" label emitted by metrics.go:110–115 (the case where a conditional decision is returned by the wrapped authorizer) is not exercised — the dummy authorizer only produces unconditional decisions. Since the ConditionsMap and Union variants don't exist in the tree at this commit, this branch is currently unreachable, but the code path is there and will silently emit a metric label without a test to guard it. Add a row when 9d7f6593151 lands.

- From d:
  - Use `UnconditionalParts` in `dummyConditionalAuthorizer.Authorize`
  - Some refined `IsAllowed` -> `IsAllow`

- From i:
  - Verify that we have coverage for: "GenericCondition.Evaluate fallback — not defined yet in this commit (the Evaluate method lands in i-666dea045e8)."

## Micro

- From a `6d78dfd60cfeddcd3e47a92306571eab155ea7ce`:
  - The triple-shape rows (`[]authorizer.ConditionsAwareDecision`) are a nice pattern — but the inner subtest loop `t.Run(fmt.Sprint(i), ...)` uses the array index for the subtest name (`conditions_test.go:161`). Prefer a stable label like `"direct-constructor"`, `"from-parts"`, `"authorizer-func"` so failing subtests are self-identifying.
  - `unexpectedErr` and `otherErr` are constructed with `fmt.Errorf` (`conditions_test.go:35–36`). Package-level `var` block would be idiomatic. Micro-nit.
  - The `sampleAttrs := authorizer.AttributesRecord{}` fixture (`:38`) is passed to `ConditionsAwareAuthorize` but the closures ignore attributes. Consider a documenting comment.
  - The zero-value test uses `named1, named2, named3` in a variadic `return` (`conditions_test.go:56`) — clever but obscure; `return authorizer.DecisionDeny, "", nil` would be clearer.

- From c:
  - Missing test for EvaluateConditions fail-closed path. All the added implementations (abac, node, rbac, unionAuthzHandler, PolicyList) have new EvaluateConditions methods returning the sentinel error — but the tests table doesn't include even one assertion that calling EvaluateConditions on these types returns ErrorConditionEvaluationNotSupported. If a future refactor accidentally returns DecisionAllow, tests would not catch it.

- From h:
 - If someone constructs a ConditionsMap value directly via zero-value struct literal, the invariant is violated. Since ConditionsMap has only private fields, external code can't construct one — but if reflection or unsafe.Pointer sneaks by, this is a latent trap. Consider a constructor-only pattern with a sealed struct{} field.

