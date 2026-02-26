# Integration testing for Conditional Authorization

Implement an integration test for Kubernetes (similar to `test/integration/apiserver/cel/authorizerselector/selectorenabled/main_test.go`, with both positive and negative testing) that:

- enables the Conditional Authorization feature and the `AuthorizationConditionsEnforcer` admission plugin
- configures the API server to use a webhook authorizer using HTTPS, configured through API server flags `authorization-webhook-config-file`, `authorization-mode=Webhook,RBAC`, `authorization-webhook-version=v1`
- runs a webhook server that serves both the `SubjectAccessReview` and `AuthorizationConditionsReview` on its `/authorize` HTTPS endpoint. The webhook inspects the payload by parsing to TypeMeta first, to know which type to decode into.
- sets up the integration test to various users, as determined by test cases
- sends various payloads, as specified by test cases (which can invoke a function with the configured client), and asserts whether the request is allowed or denied, as per the rule of the webhook authorizer (also part of the test case)


## Second pass 

 Plan: Add CEL-based condition integration tests for conditional authorization                                                                                                                                                                   
                                                                                                                                                                                                                                                 
 Context                                                                                                                                                                                                                                         
                                                                                                                                                                                                                                                 
 The existing integration test at test/integration/apiserver/conditionalauthorization/conditionalauthorization_test.go tests the conditional authorization flow end-to-end but uses hardcoded webhook ACR responses (always allow/deny). We need 
  to add tests where CEL expressions are the condition language, flow through the API server (SAR response → conditional decision → ACR request), and are evaluated by the webhook against the actual request objects.

 Changes

 Single file modified: test/integration/apiserver/conditionalauthorization/conditionalauthorization_test.go

 1. Add CEL evaluator helpers

 Add two helper functions at the bottom of the test file:

 - celEvaluateConditions(t, acr) (allowed, denied bool) — Parses conditions from acr.Request.Decision.Conditions, deserializes Object/OldObject from WriteRequest.Object.Raw into map[string]any, builds a request map from
 WriteRequest.Operation/Namespace/Name, creates a cel-go env with object, oldObject, request variables (all cel.DynType), and evaluates conditions following Deny > NoOpinion > Allow precedence per EvaluateConditionSet semantics.
 - evalCEL(t, env, expr, vars) bool — Compiles and evaluates a single CEL expression.

 New import: "github.com/google/cel-go/cel"

 2. Add 8 new test cases

 All use the same pattern: SAR returns ConditionalDecisionChain with CEL expressions, ACR handler calls celEvaluateConditions which evaluates CEL against the actual object.

 ┌─────┬────────────────────────────────────────┬────────────────────────────────────────────────────────────────────────────┬───────────────────────┬─────────────────────────────────────┐
 │  #  │               Test name                │                               CEL expression                               │        Object         │              Expected               │
 ├─────┼────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────┼───────────────────────┼─────────────────────────────────────┤
 │ 1   │ cel allow by name pattern              │ object.metadata.name.startsWith("safe-")                                   │ name=safe-configmap   │ allowed                             │
 ├─────┼────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────┼───────────────────────┼─────────────────────────────────────┤
 │ 2   │ cel deny by name pattern mismatch      │ same expression                                                            │ name=unsafe-configmap │ denied (no Allow match → NoOpinion) │
 ├─────┼────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────┼───────────────────────┼─────────────────────────────────────┤
 │ 3   │ cel deny by label overrides allow      │ Allow: true + Deny: labels.restricted == "true"                            │ restricted=true label │ denied (Deny > Allow)               │
 ├─────┼────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────┼───────────────────────┼─────────────────────────────────────┤
 │ 4   │ cel allow by data content              │ object.data.approved == "yes"                                              │ data.approved=yes     │ allowed                             │
 ├─────┼────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────┼───────────────────────┼─────────────────────────────────────┤
 │ 5   │ cel deny by data content missing       │ same expression                                                            │ data.approved=no      │ denied                              │
 ├─────┼────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────┼───────────────────────┼─────────────────────────────────────┤
 │ 6   │ cel operation-aware deny update        │ Allow: request.operation == "CREATE" + Deny: request.operation == "UPDATE" │ CREATE then UPDATE    │ update denied                       │
 ├─────┼────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────┼───────────────────────┼─────────────────────────────────────┤
 │ 7   │ cel deny overrides allow and noopinion │ all effects true                                                           │ any                   │ denied (Deny > NoOpinion > Allow)   │
 ├─────┼────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────┼───────────────────────┼─────────────────────────────────────┤
 │ 8   │ cel noopinion overrides allow          │ Allow: true + NoOpinion: labels.review == "pending"                        │ review=pending label  │ denied (NoOpinion > Allow)          │
 └─────┴────────────────────────────────────────┴────────────────────────────────────────────────────────────────────────────┴───────────────────────┴─────────────────────────────────────┘

 All CEL test cases set expectAllowedWhenDisabled: boolPtr(false) since the users have no RBAC rules.

 Key references

 - authorizer.EvaluateConditionSet in staging/.../authorizer/conditional.go — Deny > NoOpinion > Allow precedence
 - WebhookAuthorizer.EvaluateConditions in staging/.../webhook/webhook.go:322-385 — How ACR is built with Object/OldObject from WriteRequest
 - AuthorizationConditionsWriteRequest in staging/.../authorization/v1alpha1/types.go — ACR request with Object.Raw, Operation
 - cel-go vendored at vendor/github.com/google/cel-go/cel/

 Verification

 1. Run go test -v -count=1 -timeout=300s ./test/integration/apiserver/conditionalauthorization/...
 2. All 20 test cases should pass (6 existing + 8 new CEL × 2 enabled/disabled modes = 14 new subtests, but the test structure runs all cases per mode, so 28 subtests total across 2 top-level tests)
 3. Run hack/test-changed.sh to verify no regressions

## Aggregated APIs

next, implement an integration test that registers an aggregated API server for
the main kube-apiserver. Use the existing test framework in
test/integration/examples/apiserver_test.go. The aggregated API server should
perform a webhook to kube-apiserver, and kube-apiserver should be configured to
(again) webhook to the conditional authorizer used in our existing test
fixtures. Assert that when a client issues create request for an aggregated API
resource, the conditional rules defined in the conditional webhook authorizer
are respected and enforced. The aggregated API server should enable conditional
authorization support too.

 Plan: Aggregated API Server Integration Test for Conditional Authorization                                                                                                                                                        

 Context

 The existing conditional authorization tests verify the flow for core API resources (ConfigMaps) directly on kube-apiserver. We need to test the end-to-end flow through an aggregated API server: Client → kube-apiserver
 (aggregator) → sample-apiserver (wardle), where conditional authorization rules are enforced by the aggregated server's admission chain. This requires production code changes to enable conditional auth in the delegating
 authorization path, since the aggregated server must be able to receive conditional decisions via SAR and evaluate them via ACR.

 Request flow

 Client --create Flunder--> kube-apiserver aggregator --proxy--> wardle (sample-apiserver)
                                                                   |
                                                       wardle authorizes via SAR
                                                                   |
                                                       SAR --> kube-apiserver SAR handler
                                                                   |
                                                       kube-apiserver authorizer chain
                                                                   |
                                                       webhook --> conditional webhook server
                                                                   |
                                                       conditional decision flows back
                                                                   |
                                                       wardle stores conditional decision
                                                                   |
                                                       AuthorizationConditionsEnforcer runs
                                                                   |
                                                       ACR --> conditional webhook server
                                                                   |
                                                       CEL evaluated, allow/deny returned

 Production Code Changes (4 files)

 1. staging/src/k8s.io/apiserver/plugin/pkg/authorizer/webhook/webhook.go

 Add conditionsWebhookConfig *rest.Config parameter to NewFromInterface (line 91).

 Currently NewFromInterface passes nil for the ACR client (// TODO: fixme). Change to:
 func NewFromInterface(
     subjectAccessReview authorizationv1client.AuthorizationV1Interface,
     authorizedTTL, unauthorizedTTL time.Duration,
     retryBackoff wait.Backoff,
     decisionOnError authorizer.Decision,
     metrics metrics.AuthorizerMetrics,
     compiler authorizationcel.Compiler,
     conditionsWebhookConfig *rest.Config, // NEW
 ) (*WebhookAuthorizer, error) {
     var acrClient *authorizationConditionsClient
     if conditionsWebhookConfig != nil {
         var err error
         acrClient, err = buildAuthorizationConditionsClient(conditionsWebhookConfig, retryBackoff)
         if err != nil {
             return nil, err
         }
     }
     return newWithBackoff(
         &subjectAccessReviewV1Client{subjectAccessReview.RESTClient()},
         authorizedTTL, unauthorizedTTL, retryBackoff, decisionOnError,
         nil, metrics, compiler, "", acrClient,
     )
 }

 2. staging/src/k8s.io/apiserver/pkg/authorization/authorizerfactory/delegating.go

 Add ConditionsWebhookConfig *rest.Config field to DelegatingAuthorizerConfig (line 32).

 type DelegatingAuthorizerConfig struct {
     // ... existing fields ...
     ConditionsWebhookConfig *rest.Config // NEW: webhook config for ACR evaluation
 }

 In New() (line 60), pass the config to NewFromInterface:
 return webhook.NewFromInterface(
     c.SubjectAccessReviewClient,
     c.AllowCacheTTL, c.DenyCacheTTL,
     *c.WebhookRetryBackoff,
     authorizer.DecisionNoOpinion(""),
     NewDelegatingAuthorizerMetrics(),
     compiler,
     c.ConditionsWebhookConfig, // NEW
 )

 3. staging/src/k8s.io/apiserver/pkg/server/options/authorization.go

 Add ConditionsWebhookConfigFile string field to DelegatingAuthorizationOptions (line 43).

 Add flag in AddFlags (line 136):
 fs.StringVar(&s.ConditionsWebhookConfigFile,
     "authorization-conditions-webhook-config-file", s.ConditionsWebhookConfigFile,
     "kubeconfig file pointing at the webhook for evaluating authorization conditions.")

 In ApplyTo (line 162), set the classifier and load the conditions config:
 func (s *DelegatingAuthorizationOptions) ApplyTo(c *server.AuthorizationInfo) error {
     // ... existing code ...
     // Set default classifier for conditional authorization
     if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.ConditionalAuthorization) {
         c.ConditionalAuthorizationRequestClassifier = defaultWriteVerbClassifier
     }
     c.Authorizer, err = s.toAuthorizer(client)
     return err
 }

 Add default classifier:
 func defaultWriteVerbClassifier(attrs authorizer.Attributes) bool {
     switch attrs.GetVerb() {
     case "create", "update", "patch", "delete", "deletecollection":
         return true
     }
     return false
 }

 In toAuthorizer (line 195), load conditions webhook config and pass through:
 cfg := authorizerfactory.DelegatingAuthorizerConfig{
     SubjectAccessReviewClient: client.AuthorizationV1(),
     AllowCacheTTL:             s.AllowCacheTTL,
     DenyCacheTTL:              s.DenyCacheTTL,
     WebhookRetryBackoff:       s.WebhookRetryBackoff,
 }
 if len(s.ConditionsWebhookConfigFile) > 0 {
     conditionsConfig, err := loadKubeconfig(s.ConditionsWebhookConfigFile)
     if err != nil {
         return nil, err
     }
     cfg.ConditionsWebhookConfig = conditionsConfig
 }

 New imports needed: genericfeatures "k8s.io/apiserver/pkg/features", utilfeature "k8s.io/apiserver/pkg/util/feature", "k8s.io/apiserver/pkg/authorization/authorizer", clientcmd (already imported).

 4. No sample-apiserver code changes needed

 - AuthorizationConditionsEnforcer is already registered via RegisterAllAdmissionPlugins (called from NewAdmissionOptions in staging/.../server/options/recommended.go)
 - It can be enabled via --enable-admission-plugins=AuthorizationConditionsEnforcer
 - Feature gate ConditionalAuthorization=true can be passed via --feature-gates
 - The classifier is set by DelegatingAuthorizationOptions.ApplyTo() (change #3 above)

 Integration Test

 New file: test/integration/apiserver/conditionalauthorization/aggregated_test.go

 Reuses from existing test file: webhookServer, webhookServerHandler, newWebhookServer, celEvaluateConditions, evalCEL, boolPtr

 Test function: TestAggregatedConditionalAuthorization

 Setup:
 1. Start conditional webhook server (reuses newWebhookServer from existing test)
 2. Write webhook kubeconfig pointing to conditional webhook (for kube-apiserver --authorization-webhook-config-file and for wardle --authorization-conditions-webhook-config-file)
 3. Start kube-apiserver with flags:
   - --feature-gates=ConditionalAuthorization=true
   - --authorization-mode=Webhook,RBAC
   - --authorization-webhook-config-file=<webhook-kubeconfig>
   - --authorization-webhook-version=v1
   - --authorization-webhook-cache-authorized-ttl=1ms
   - --authorization-webhook-cache-unauthorized-ttl=1ms
   - --enable-admission-plugins=AuthorizationConditionsEnforcer
   - EnableCertAuth: true (for front-proxy cert auth to wardle)
 4. Create namespace + service for wardle in kube-apiserver
 5. Create listener for wardle, override service resolver (pattern from apiserver_test.go:703-708)
 6. Create WardleServerOptions with component globals registry (pattern from apiserver_test.go:718-761)
 7. Write kubeconfig for wardle→kube-apiserver connection (pattern from apiserver_test.go:780)
 8. Write kubeconfig for wardle→conditional webhook connection (for ACR)
 9. Start wardle with args:
   - --authentication-kubeconfig=<wardle-to-kas>
   - --authorization-kubeconfig=<wardle-to-kas>
   - --authorization-conditions-webhook-config-file=<webhook-kubeconfig> (NEW flag)
   - --authorization-webhook-cache-authorized-ttl=1ms
   - --authorization-webhook-cache-unauthorized-ttl=1ms
   - --enable-admission-plugins=AuthorizationConditionsEnforcer
   - --feature-gates=ConditionalAuthorization=true
   - --etcd-servers=<etcd-url>, --cert-dir=<dir>, --kubeconfig=<wardle-to-kas>
 10. Wait for wardle to be running (healthz check)
 11. Register APIService for v1alpha1.wardle.example.com with wardle's CA bundle
 12. Wait for APIService to be Available
 13. Create wardle clientset via kube-apiserver (aggregated path)

 Test cases (5):

 ┌─────┬──────────────────────────────────────────────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────┬────────────────────────────────────┬──────────┐
 │  #  │                  Test name                   │                                                 Webhook behavior                                                  │               Object               │ Expected │
 ├─────┼──────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┼──────────┤
 │ 1   │ aggregated unconditional allow               │ SAR returns Allowed: true                                                                                         │ Flunder "allowed-flunder"          │ allowed  │
 ├─────┼──────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┼──────────┤
 │ 2   │ aggregated unconditional deny                │ SAR returns Denied: true                                                                                          │ Flunder "denied-flunder"           │ denied   │
 ├─────┼──────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┼──────────┤
 │ 3   │ aggregated conditional allow by name         │ SAR returns conditional with CEL object.metadata.name.startsWith("safe-"); ACR handler uses celEvaluateConditions │ Flunder "safe-flunder"             │ allowed  │
 ├─────┼──────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┼──────────┤
 │ 4   │ aggregated conditional deny by name mismatch │ Same CEL as #3                                                                                                    │ Flunder "unsafe-flunder"           │ denied   │
 ├─────┼──────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┼──────────┤
 │ 5   │ aggregated conditional deny by label         │ SAR returns Allow true + Deny labels.restricted == "true"; ACR uses celEvaluateConditions                         │ Flunder with label restricted=true │ denied   │
 └─────┴──────────────────────────────────────────────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────┴────────────────────────────────────┴──────────┘

 Each test case:
 - Configures the webhook handler's sarHandler and acrHandler
 - Creates an impersonated client for the test user (via kube-apiserver)
 - Creates a Flunder object via the aggregated path (wardle.example.com/v1alpha1)
 - Asserts allowed/forbidden

 Key imports for the new file:
 import (
     wardlev1alpha1 "k8s.io/sample-apiserver/pkg/apis/wardle/v1alpha1"
     sampleserver "k8s.io/sample-apiserver/pkg/cmd/server"
     wardlev1alpha1client "k8s.io/sample-apiserver/pkg/generated/clientset/versioned/typed/wardle/v1alpha1"
     apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
     aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
     "k8s.io/kubernetes/cmd/kube-apiserver/app"
     // ... and existing imports from conditionalauthorization_test.go
 )

 Key references

 - test/integration/examples/apiserver_test.go:698-886 — Aggregated server setup patterns
 - conditionalauthorization_test.go — Existing webhook handler, CEL evaluator helpers
 - staging/.../webhook/webhook.go:91-93 — NewFromInterface with // TODO: fixme
 - staging/.../authorizerfactory/delegating.go:32-69 — DelegatingAuthorizerConfig
 - staging/.../server/options/authorization.go:43-209 — DelegatingAuthorizationOptions
 - staging/.../filters/authorization.go:100-115 — Conditional authorization filter check
 - staging/.../union/union.go:75-122 — Union EvaluateConditions delegation
 - staging/.../server/plugins.go — RegisterAllAdmissionPlugins includes conditionsenforcer

 Verification

 1. Run make — verify compilation
 2. Run go test -v -count=1 -timeout=300s ./test/integration/apiserver/conditionalauthorization/... — all tests pass
 3. Run hack/test-changed.sh — no regressions

## authorizationconfig

instead of specifying a conditionswebhookconfigfile in options, build the conditions client from the existing kubeconfig file, but take as a parameter in AuthorizationConfiguration the kubeconfig context name for the           
  conditionsreview, and also add a field for the API version of ACR to use. update the integration tests to use the AuthorizationConfiguration config file instead, and use this option. Wire it correctly as well in the            
  webhook authorizer. In the integration test, serve the SAR webhook on /authorize and the ACR on /conditionsreview.