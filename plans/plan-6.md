# Integration testing for Conditional Authorization

Implement an integration test for Kubernetes (similar to `test/integration/apiserver/cel/authorizerselector/selectorenabled/main_test.go`, with both positive and negative testing) that:

- enables the Conditional Authorization feature and the `AuthorizationConditionsEnforcer` admission plugin
- configures the API server to use a webhook authorizer using HTTPS, configured through API server flags `authorization-webhook-config-file`, `authorization-mode=Webhook,RBAC`, `authorization-webhook-version=v1`
- runs a webhook server that serves both the `SubjectAccessReview` and `AuthorizationConditionsReview` on its `/authorize` HTTPS endpoint. The webhook inspects the payload by parsing to TypeMeta first, to know which type to decode into.
- sets up the integration test to various users, as determined by test cases
- sends various payloads, as specified by test cases (which can invoke a function with the configured client), and asserts whether the request is allowed or denied, as per the rule of the webhook authorizer (also part of the test case)