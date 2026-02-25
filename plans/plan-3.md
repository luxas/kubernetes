# Add a no-op Conditions Evaluation implementation to existing authorizers

The `authorizer.Authorizer` interface was augmented with the
`ConditionSetEvaluator` functions. Update all existing authorizer
implementations to return the commonly-defined
`authorizer.ErrorConditionEvaluationNotSupported`. Only new authorizers will
later add support for this function.