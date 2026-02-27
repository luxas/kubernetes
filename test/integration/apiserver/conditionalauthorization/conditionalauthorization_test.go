/*
Copyright 2025 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package conditionalauthorization

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/cel-go/cel"

	authorizationv1 "k8s.io/api/authorization/v1"
	authorizationv1alpha1 "k8s.io/api/authorization/v1alpha1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	kubeapiservertesting "k8s.io/kubernetes/cmd/kube-apiserver/app/testing"
	"k8s.io/kubernetes/test/integration/authutil"
	"k8s.io/kubernetes/test/integration/framework"
)

// TestConditionalAuthorizationEnabled tests the conditional authorization flow
// end-to-end with the feature gate enabled and the AuthorizationConditionsEnforcer
// admission plugin active. The webhook authorizer returns conditional decisions
// (with conditions) for SubjectAccessReview requests, and then evaluates those
// conditions via AuthorizationConditionsReview during admission.
func TestConditionalAuthorizationEnabled(t *testing.T) {
	runConditionalAuthorizationTests(t, true)
}

// TestConditionalAuthorizationDisabled tests that when the ConditionalAuthorization
// feature gate is disabled, conditional decisions from webhooks are treated as
// NoOpinion (falling through to RBAC).
func TestConditionalAuthorizationDisabled(t *testing.T) {
	runConditionalAuthorizationTests(t, false)
}

func runConditionalAuthorizationTests(t *testing.T, featureEnabled bool) {
	dir := t.TempDir()

	// Start a webhook server that handles both SubjectAccessReview (authorization)
	// and AuthorizationConditionsReview (conditions evaluation) on the same endpoint.
	webhookServer := newWebhookServer(t)
	defer webhookServer.server.Close()

	// Write a kubeconfig for the webhook server with two contexts:
	// - "default" context for SAR on /authorize
	// - "conditions" context for ACR on /conditionsreview
	kubeconfigPath := filepath.Join(dir, "webhook-kubeconfig.yaml")
	if err := os.WriteFile(kubeconfigPath, []byte(fmt.Sprintf(`
apiVersion: v1
kind: Config
clusters:
- name: authorize
  cluster:
    server: %q
    insecure-skip-tls-verify: true
- name: conditions
  cluster:
    server: %q
    insecure-skip-tls-verify: true
contexts:
- name: default
  context:
    cluster: authorize
    user: test
- name: conditions
  context:
    cluster: conditions
    user: test
current-context: default
users:
- name: test
`, webhookServer.server.URL+"/authorize", webhookServer.server.URL+"/conditionsreview")), 0644); err != nil {
		t.Fatal(err)
	}

	// Write an AuthorizationConfiguration file
	authzConfigPath := filepath.Join(dir, "authz-config.yaml")
	conditionsReviewSection := ""
	if featureEnabled {
		conditionsReviewSection = `
    conditionsReview:
      kubeConfigContextName: conditions
      version: v1alpha1`
	}
	if err := os.WriteFile(authzConfigPath, []byte(fmt.Sprintf(`
apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthorizationConfiguration
authorizers:
- type: Webhook
  name: conditional-webhook
  webhook:
    timeout: 10s
    subjectAccessReviewVersion: v1
    matchConditionSubjectAccessReviewVersion: v1
    failurePolicy: NoOpinion
    authorizedTTL: 1ms
    unauthorizedTTL: 1ms
    connectionInfo:
      type: KubeConfigFile
      kubeConfigFile: %q%s
- type: RBAC
  name: rbac
`, kubeconfigPath, conditionsReviewSection)), 0644); err != nil {
		t.Fatal(err)
	}

	// Start the test API server with the AuthorizationConfiguration, feature gate,
	// and the AuthorizationConditionsEnforcer admission plugin
	flags := []string{
		fmt.Sprintf("--feature-gates=ConditionalAuthorization=%v", featureEnabled),
		"--authorization-config=" + authzConfigPath,
		"--enable-admission-plugins=AuthorizationConditionsEnforcer",
	}
	server := kubeapiservertesting.StartTestServerOrDie(t, nil, flags, framework.SharedEtcd())
	t.Cleanup(server.TearDownFn)

	adminClient := clientset.NewForConfigOrDie(server.ClientConfig)

	// Create the "test-ns" namespace for tests
	_, err := adminClient.CoreV1().Namespaces().Create(context.TODO(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}

	testCases := []struct {
		name string
		// user is the username that will be impersonated
		user string
		// webhookBehavior configures the webhook for this test case.
		// It is called before makeRequest to set the desired behavior.
		webhookBehavior func(ws *webhookServerHandler)
		// makeRequest creates a client with the given user and performs an API request.
		// Returns an error if the request fails.
		makeRequest func(t *testing.T, client *clientset.Clientset) error
		// expectAllowed is true if the request should be allowed
		expectAllowed bool
		// expectAllowedWhenDisabled overrides expectAllowed when the feature is disabled.
		// If nil, uses expectAllowed.
		expectAllowedWhenDisabled *bool
	}{
		{
			name: "unconditional allow from webhook",
			user: "allow-user",
			webhookBehavior: func(ws *webhookServerHandler) {
				ws.sarHandler = func(sar *authorizationv1.SubjectAccessReview) {
					sar.Status.Allowed = true
					sar.Status.Reason = "unconditionally allowed"
				}
			},
			makeRequest: func(t *testing.T, client *clientset.Clientset) error {
				_, err := client.CoreV1().ConfigMaps("test-ns").Create(context.TODO(), &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "test-allowed"},
				}, metav1.CreateOptions{})
				return err
			},
			expectAllowed: true,
		},
		{
			name: "unconditional deny from webhook",
			user: "deny-user",
			webhookBehavior: func(ws *webhookServerHandler) {
				ws.sarHandler = func(sar *authorizationv1.SubjectAccessReview) {
					sar.Status.Allowed = false
					sar.Status.Denied = true
					sar.Status.Reason = "unconditionally denied"
				}
			},
			makeRequest: func(t *testing.T, client *clientset.Clientset) error {
				_, err := client.CoreV1().ConfigMaps("test-ns").Create(context.TODO(), &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "test-denied"},
				}, metav1.CreateOptions{})
				return err
			},
			expectAllowed: false,
		},
		{
			name: "conditional allow - condition evaluates to allow",
			user: "conditional-allow-user",
			webhookBehavior: func(ws *webhookServerHandler) {
				ws.sarHandler = func(sar *authorizationv1.SubjectAccessReview) {
					// Return a conditional decision with conditions that should evaluate to allow
					sar.Status.ConditionalDecisionChain = []authorizationv1.SubjectAccessReviewAuthorizationDecision{
						{
							ConditionsType: "webhook",
							Conditions: []authorizationv1.SubjectAccessReviewCondition{
								{
									ID:          "always-allow",
									Effect:      authorizationv1.SubjectAccessReviewConditionEffectAllow,
									Condition:   "true", // always true
									Description: "always allow condition",
								},
							},
						},
					}
				}
				ws.acrHandler = func(acr *authorizationv1alpha1.AuthorizationConditionsReview) {
					acr.Response = &authorizationv1alpha1.AuthorizationConditionsResponse{
						SubjectAccessReviewAuthorizationDecision: authorizationv1alpha1.SubjectAccessReviewAuthorizationDecision{
							Allowed: true,
						},
					}
				}
			},
			makeRequest: func(t *testing.T, client *clientset.Clientset) error {
				_, err := client.CoreV1().ConfigMaps("test-ns").Create(context.TODO(), &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "test-conditional-allow"},
				}, metav1.CreateOptions{})
				return err
			},
			expectAllowed: true,
			// When disabled, the conditional decision is treated as NoOpinion,
			// falling through to RBAC which denies (no RBAC rules for this user).
			expectAllowedWhenDisabled: boolPtr(false),
		},
		{
			name: "conditional deny - condition evaluates to deny",
			user: "conditional-deny-user",
			webhookBehavior: func(ws *webhookServerHandler) {
				ws.sarHandler = func(sar *authorizationv1.SubjectAccessReview) {
					// Return a conditional decision with a deny condition
					sar.Status.ConditionalDecisionChain = []authorizationv1.SubjectAccessReviewAuthorizationDecision{
						{
							ConditionsType: "webhook",
							Conditions: []authorizationv1.SubjectAccessReviewCondition{
								{
									ID:          "always-allow",
									Effect:      authorizationv1.SubjectAccessReviewConditionEffectAllow,
									Condition:   "true",
									Description: "base allow condition",
								},
								{
									ID:          "always-deny",
									Effect:      authorizationv1.SubjectAccessReviewConditionEffectDeny,
									Condition:   "true", // deny is true => denied
									Description: "always deny condition",
								},
							},
						},
					}
				}
				ws.acrHandler = func(acr *authorizationv1alpha1.AuthorizationConditionsReview) {
					acr.Response = &authorizationv1alpha1.AuthorizationConditionsResponse{
						SubjectAccessReviewAuthorizationDecision: authorizationv1alpha1.SubjectAccessReviewAuthorizationDecision{
							Denied: true,
						},
					}
				}
			},
			makeRequest: func(t *testing.T, client *clientset.Clientset) error {
				_, err := client.CoreV1().ConfigMaps("test-ns").Create(context.TODO(), &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "test-conditional-deny"},
				}, metav1.CreateOptions{})
				return err
			},
			expectAllowed: false,
		},
		{
			name: "conditional no-opinion falls through to RBAC allow",
			user: "conditional-noop-rbac-user",
			webhookBehavior: func(ws *webhookServerHandler) {
				ws.sarHandler = func(sar *authorizationv1.SubjectAccessReview) {
					// Return a conditional decision that will evaluate to NoOpinion
					sar.Status.ConditionalDecisionChain = []authorizationv1.SubjectAccessReviewAuthorizationDecision{
						{
							ConditionsType: "webhook",
							Conditions: []authorizationv1.SubjectAccessReviewCondition{
								{
									ID:          "no-opinion",
									Effect:      authorizationv1.SubjectAccessReviewConditionEffectNoOpinion,
									Condition:   "true", // no-opinion is true => NoOpinion
									Description: "no opinion condition",
								},
							},
						},
					}
				}
				ws.acrHandler = func(acr *authorizationv1alpha1.AuthorizationConditionsReview) {
					// NoOpinion: allowed=false, denied=false
					acr.Response = &authorizationv1alpha1.AuthorizationConditionsResponse{
						SubjectAccessReviewAuthorizationDecision: authorizationv1alpha1.SubjectAccessReviewAuthorizationDecision{
							Allowed: false,
							Denied:  false,
						},
					}
				}
			},
			makeRequest: func(t *testing.T, client *clientset.Clientset) error {
				_, err := client.CoreV1().ConfigMaps("test-ns").List(context.TODO(), metav1.ListOptions{})
				return err
			},
			// With feature enabled: conditional => NoOpinion from webhook conditions evaluation,
			// but wait — the conditions evaluator returns NoOpinion, so it falls through.
			// Actually, the conditional flow: webhook returns conditional, and then during admission
			// the conditions are evaluated. If they return NoOpinion the request is denied because
			// the authorizer "used up" its chance. So this should be denied.
			// Let's grant RBAC for this user and observe the conditional NoOpinion behavior:
			// When feature is enabled, conditional decisions bypass RBAC (they're handled during admission).
			// The original Authorize() in the chain returns Conditional (which CanBecomeAllowed),
			// so RBAC is never consulted. The conditions evaluator returns NoOpinion => denied.
			expectAllowed: false,
			// When disabled: conditional decision is NoOpinion, RBAC is consulted and allows.
			expectAllowedWhenDisabled: boolPtr(true),
		},
		{
			name: "webhook no-opinion falls through to RBAC allow",
			user: "webhook-noop-rbac-user",
			webhookBehavior: func(ws *webhookServerHandler) {
				ws.sarHandler = func(sar *authorizationv1.SubjectAccessReview) {
					// NoOpinion: neither allowed nor denied
					sar.Status.Allowed = false
					sar.Status.Denied = false
				}
			},
			makeRequest: func(t *testing.T, client *clientset.Clientset) error {
				_, err := client.CoreV1().ConfigMaps("test-ns").List(context.TODO(), metav1.ListOptions{})
				return err
			},
			expectAllowed: true,
		},

		// CEL-based conditional authorization tests.
		// These test that CEL expressions flow through the SAR → Decision → ACR
		// pipeline and the webhook can evaluate them against the actual request objects.
		{
			name: "cel allow by name pattern",
			user: "cel-name-user",
			webhookBehavior: func(ws *webhookServerHandler) {
				ws.sarHandler = func(sar *authorizationv1.SubjectAccessReview) {
					sar.Status.ConditionalDecisionChain = []authorizationv1.SubjectAccessReviewAuthorizationDecision{
						{
							ConditionsType: "webhook",
							Conditions: []authorizationv1.SubjectAccessReviewCondition{
								{
									ID:          "allow-safe-prefix",
									Effect:      authorizationv1.SubjectAccessReviewConditionEffectAllow,
									Condition:   `object.metadata.name.startsWith("safe-")`,
									Description: "only allow configmaps with safe- prefix",
								},
							},
						},
					}
				}
				ws.acrHandler = func(acr *authorizationv1alpha1.AuthorizationConditionsReview) {
					allowed, denied := celEvaluateConditions(ws.t, acr)
					acr.Response = &authorizationv1alpha1.AuthorizationConditionsResponse{
						SubjectAccessReviewAuthorizationDecision: authorizationv1alpha1.SubjectAccessReviewAuthorizationDecision{
							Allowed: allowed,
							Denied:  denied,
						},
					}
				}
			},
			makeRequest: func(t *testing.T, client *clientset.Clientset) error {
				_, err := client.CoreV1().ConfigMaps("test-ns").Create(context.TODO(), &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "safe-configmap"},
				}, metav1.CreateOptions{})
				return err
			},
			expectAllowed:             true,
			expectAllowedWhenDisabled: boolPtr(false),
		},
		{
			name: "cel deny by name pattern mismatch",
			user: "cel-name-deny-user",
			webhookBehavior: func(ws *webhookServerHandler) {
				ws.sarHandler = func(sar *authorizationv1.SubjectAccessReview) {
					sar.Status.ConditionalDecisionChain = []authorizationv1.SubjectAccessReviewAuthorizationDecision{
						{
							ConditionsType: "webhook",
							Conditions: []authorizationv1.SubjectAccessReviewCondition{
								{
									ID:          "allow-safe-prefix",
									Effect:      authorizationv1.SubjectAccessReviewConditionEffectAllow,
									Condition:   `object.metadata.name.startsWith("safe-")`,
									Description: "only allow configmaps with safe- prefix",
								},
							},
						},
					}
				}
				ws.acrHandler = func(acr *authorizationv1alpha1.AuthorizationConditionsReview) {
					allowed, denied := celEvaluateConditions(ws.t, acr)
					acr.Response = &authorizationv1alpha1.AuthorizationConditionsResponse{
						SubjectAccessReviewAuthorizationDecision: authorizationv1alpha1.SubjectAccessReviewAuthorizationDecision{
							Allowed: allowed,
							Denied:  denied,
						},
					}
				}
			},
			makeRequest: func(t *testing.T, client *clientset.Clientset) error {
				_, err := client.CoreV1().ConfigMaps("test-ns").Create(context.TODO(), &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "unsafe-configmap"},
				}, metav1.CreateOptions{})
				return err
			},
			expectAllowed: false,
		},
		{
			name: "cel deny by label overrides allow",
			user: "cel-label-deny-user",
			webhookBehavior: func(ws *webhookServerHandler) {
				ws.sarHandler = func(sar *authorizationv1.SubjectAccessReview) {
					sar.Status.ConditionalDecisionChain = []authorizationv1.SubjectAccessReviewAuthorizationDecision{
						{
							ConditionsType: "webhook",
							Conditions: []authorizationv1.SubjectAccessReviewCondition{
								{
									ID:          "allow-all",
									Effect:      authorizationv1.SubjectAccessReviewConditionEffectAllow,
									Condition:   "true",
									Description: "base allow",
								},
								{
									ID:     "deny-restricted-label",
									Effect: authorizationv1.SubjectAccessReviewConditionEffectDeny,
									Condition: `has(object.metadata.labels) && ` +
										`has(object.metadata.labels.restricted) && ` +
										`object.metadata.labels.restricted == "true"`,
									Description: "deny restricted labels",
								},
							},
						},
					}
				}
				ws.acrHandler = func(acr *authorizationv1alpha1.AuthorizationConditionsReview) {
					allowed, denied := celEvaluateConditions(ws.t, acr)
					acr.Response = &authorizationv1alpha1.AuthorizationConditionsResponse{
						SubjectAccessReviewAuthorizationDecision: authorizationv1alpha1.SubjectAccessReviewAuthorizationDecision{
							Allowed: allowed,
							Denied:  denied,
						},
					}
				}
			},
			makeRequest: func(t *testing.T, client *clientset.Clientset) error {
				_, err := client.CoreV1().ConfigMaps("test-ns").Create(context.TODO(), &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "cel-restricted-cm",
						Labels: map[string]string{"restricted": "true"},
					},
				}, metav1.CreateOptions{})
				return err
			},
			expectAllowed: false,
		},
		{
			name: "cel allow by data content",
			user: "cel-data-user",
			webhookBehavior: func(ws *webhookServerHandler) {
				ws.sarHandler = func(sar *authorizationv1.SubjectAccessReview) {
					sar.Status.ConditionalDecisionChain = []authorizationv1.SubjectAccessReviewAuthorizationDecision{
						{
							ConditionsType: "webhook",
							Conditions: []authorizationv1.SubjectAccessReviewCondition{
								{
									ID:     "allow-approved-data",
									Effect: authorizationv1.SubjectAccessReviewConditionEffectAllow,
									Condition: `has(object.data) && ` +
										`has(object.data.approved) && ` +
										`object.data.approved == "yes"`,
									Description: "only allow configmaps with approved=yes in data",
								},
							},
						},
					}
				}
				ws.acrHandler = func(acr *authorizationv1alpha1.AuthorizationConditionsReview) {
					allowed, denied := celEvaluateConditions(ws.t, acr)
					acr.Response = &authorizationv1alpha1.AuthorizationConditionsResponse{
						SubjectAccessReviewAuthorizationDecision: authorizationv1alpha1.SubjectAccessReviewAuthorizationDecision{
							Allowed: allowed,
							Denied:  denied,
						},
					}
				}
			},
			makeRequest: func(t *testing.T, client *clientset.Clientset) error {
				_, err := client.CoreV1().ConfigMaps("test-ns").Create(context.TODO(), &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "cel-approved-cm"},
					Data:       map[string]string{"approved": "yes"},
				}, metav1.CreateOptions{})
				return err
			},
			expectAllowed:             true,
			expectAllowedWhenDisabled: boolPtr(false),
		},
		{
			name: "cel deny by data content missing",
			user: "cel-data-deny-user",
			webhookBehavior: func(ws *webhookServerHandler) {
				ws.sarHandler = func(sar *authorizationv1.SubjectAccessReview) {
					sar.Status.ConditionalDecisionChain = []authorizationv1.SubjectAccessReviewAuthorizationDecision{
						{
							ConditionsType: "webhook",
							Conditions: []authorizationv1.SubjectAccessReviewCondition{
								{
									ID:     "allow-approved-data",
									Effect: authorizationv1.SubjectAccessReviewConditionEffectAllow,
									Condition: `has(object.data) && ` +
										`has(object.data.approved) && ` +
										`object.data.approved == "yes"`,
									Description: "only allow configmaps with approved=yes in data",
								},
							},
						},
					}
				}
				ws.acrHandler = func(acr *authorizationv1alpha1.AuthorizationConditionsReview) {
					allowed, denied := celEvaluateConditions(ws.t, acr)
					acr.Response = &authorizationv1alpha1.AuthorizationConditionsResponse{
						SubjectAccessReviewAuthorizationDecision: authorizationv1alpha1.SubjectAccessReviewAuthorizationDecision{
							Allowed: allowed,
							Denied:  denied,
						},
					}
				}
			},
			makeRequest: func(t *testing.T, client *clientset.Clientset) error {
				_, err := client.CoreV1().ConfigMaps("test-ns").Create(context.TODO(), &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "cel-unapproved-cm"},
					Data:       map[string]string{"approved": "no"},
				}, metav1.CreateOptions{})
				return err
			},
			expectAllowed: false,
		},
		{
			name: "cel operation-aware deny update",
			user: "cel-op-user",
			webhookBehavior: func(ws *webhookServerHandler) {
				ws.sarHandler = func(sar *authorizationv1.SubjectAccessReview) {
					sar.Status.ConditionalDecisionChain = []authorizationv1.SubjectAccessReviewAuthorizationDecision{
						{
							ConditionsType: "webhook",
							Conditions: []authorizationv1.SubjectAccessReviewCondition{
								{
									ID:          "allow-creates",
									Effect:      authorizationv1.SubjectAccessReviewConditionEffectAllow,
									Condition:   `request.operation == "CREATE"`,
									Description: "allow create operations",
								},
								{
									ID:          "deny-updates",
									Effect:      authorizationv1.SubjectAccessReviewConditionEffectDeny,
									Condition:   `request.operation == "UPDATE"`,
									Description: "deny update operations",
								},
							},
						},
					}
				}
				ws.acrHandler = func(acr *authorizationv1alpha1.AuthorizationConditionsReview) {
					allowed, denied := celEvaluateConditions(ws.t, acr)
					acr.Response = &authorizationv1alpha1.AuthorizationConditionsResponse{
						SubjectAccessReviewAuthorizationDecision: authorizationv1alpha1.SubjectAccessReviewAuthorizationDecision{
							Allowed: allowed,
							Denied:  denied,
						},
					}
				}
			},
			makeRequest: func(t *testing.T, client *clientset.Clientset) error {
				// Create should succeed (CEL allows CREATE)
				cm, err := client.CoreV1().ConfigMaps("test-ns").Create(context.TODO(), &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "cel-op-cm"},
					Data:       map[string]string{"key": "value"},
				}, metav1.CreateOptions{})
				if err != nil {
					return fmt.Errorf("create should have succeeded: %w", err)
				}
				// Update should be denied (CEL denies UPDATE)
				cm.Data["key"] = "new-value"
				_, err = client.CoreV1().ConfigMaps("test-ns").Update(context.TODO(), cm, metav1.UpdateOptions{})
				return err
			},
			expectAllowed:             false,
			expectAllowedWhenDisabled: boolPtr(false),
		},
		{
			name: "cel deny overrides allow and noopinion",
			user: "cel-priority-user",
			webhookBehavior: func(ws *webhookServerHandler) {
				ws.sarHandler = func(sar *authorizationv1.SubjectAccessReview) {
					sar.Status.ConditionalDecisionChain = []authorizationv1.SubjectAccessReviewAuthorizationDecision{
						{
							ConditionsType: "webhook",
							Conditions: []authorizationv1.SubjectAccessReviewCondition{
								{
									ID:          "allow-all",
									Effect:      authorizationv1.SubjectAccessReviewConditionEffectAllow,
									Condition:   "true",
									Description: "allow everything",
								},
								{
									ID:          "noop-all",
									Effect:      authorizationv1.SubjectAccessReviewConditionEffectNoOpinion,
									Condition:   "true",
									Description: "no opinion on everything",
								},
								{
									ID:          "deny-all",
									Effect:      authorizationv1.SubjectAccessReviewConditionEffectDeny,
									Condition:   "true",
									Description: "deny everything",
								},
							},
						},
					}
				}
				ws.acrHandler = func(acr *authorizationv1alpha1.AuthorizationConditionsReview) {
					allowed, denied := celEvaluateConditions(ws.t, acr)
					acr.Response = &authorizationv1alpha1.AuthorizationConditionsResponse{
						SubjectAccessReviewAuthorizationDecision: authorizationv1alpha1.SubjectAccessReviewAuthorizationDecision{
							Allowed: allowed,
							Denied:  denied,
						},
					}
				}
			},
			makeRequest: func(t *testing.T, client *clientset.Clientset) error {
				_, err := client.CoreV1().ConfigMaps("test-ns").Create(context.TODO(), &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "cel-priority-cm"},
				}, metav1.CreateOptions{})
				return err
			},
			expectAllowed: false,
		},
		{
			name: "cel noopinion overrides allow",
			user: "cel-noop-vs-allow-user",
			webhookBehavior: func(ws *webhookServerHandler) {
				ws.sarHandler = func(sar *authorizationv1.SubjectAccessReview) {
					sar.Status.ConditionalDecisionChain = []authorizationv1.SubjectAccessReviewAuthorizationDecision{
						{
							ConditionsType: "webhook",
							Conditions: []authorizationv1.SubjectAccessReviewCondition{
								{
									ID:          "allow-all",
									Effect:      authorizationv1.SubjectAccessReviewConditionEffectAllow,
									Condition:   "true",
									Description: "allow everything",
								},
								{
									ID:     "noop-on-pending-review",
									Effect: authorizationv1.SubjectAccessReviewConditionEffectNoOpinion,
									Condition: `has(object.metadata.labels) && ` +
										`has(object.metadata.labels.review) && ` +
										`object.metadata.labels.review == "pending"`,
									Description: "no opinion when review=pending label is present",
								},
							},
						},
					}
				}
				ws.acrHandler = func(acr *authorizationv1alpha1.AuthorizationConditionsReview) {
					allowed, denied := celEvaluateConditions(ws.t, acr)
					acr.Response = &authorizationv1alpha1.AuthorizationConditionsResponse{
						SubjectAccessReviewAuthorizationDecision: authorizationv1alpha1.SubjectAccessReviewAuthorizationDecision{
							Allowed: allowed,
							Denied:  denied,
						},
					}
				}
			},
			makeRequest: func(t *testing.T, client *clientset.Clientset) error {
				_, err := client.CoreV1().ConfigMaps("test-ns").Create(context.TODO(), &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "cel-noop-cm",
						Labels: map[string]string{"review": "pending"},
					},
				}, metav1.CreateOptions{})
				return err
			},
			expectAllowed: false,
		},

		// Update-to-create tests: When a PUT (update) request targets a non-existent
		// resource with AllowCreateOnUpdate=true, the update handler authorizes a
		// "create" verb. These tests verify that conditional authorization works
		// correctly in this flow. Leases support AllowCreateOnUpdate.
		// TODO: Verify the same behavior for patch
		{
			name: "update-to-create conditional allow by label",
			user: "update-create-allow-user",
			webhookBehavior: func(ws *webhookServerHandler) {
				ws.sarHandler = func(sar *authorizationv1.SubjectAccessReview) {
					if sar.Spec.ResourceAttributes == nil {
						return
					}
					switch sar.Spec.ResourceAttributes.Verb {
					case "update", "patch":
						// Unconditionally allow updates
						sar.Status.Allowed = true
						sar.Status.Reason = "updates always allowed"
					case "create":
						// Conditionally allow creates: only when creator=update-create-allow-user
						sar.Status.ConditionalDecisionChain = []authorizationv1.SubjectAccessReviewAuthorizationDecision{
							{
								ConditionsType: "webhook",
								Conditions: []authorizationv1.SubjectAccessReviewCondition{
									{
										ID:     "require-owner-label",
										Effect: authorizationv1.SubjectAccessReviewConditionEffectAllow,
										Condition: `has(object.metadata.labels) && ` +
											`has(object.metadata.labels.creator) && ` +
											`object.metadata.labels.creator == "update-create-allow-user"`,
										Description: "only allow creates when creator=update-create-allow-user",
									},
								},
							},
						}
					}
				}
				ws.acrHandler = func(acr *authorizationv1alpha1.AuthorizationConditionsReview) {
					allowed, denied := celEvaluateConditions(ws.t, acr)
					acr.Response = &authorizationv1alpha1.AuthorizationConditionsResponse{
						SubjectAccessReviewAuthorizationDecision: authorizationv1alpha1.SubjectAccessReviewAuthorizationDecision{
							Allowed: allowed,
							Denied:  denied,
						},
					}
				}
			},
			makeRequest: func(t *testing.T, client *clientset.Clientset) error {
				// PUT a non-existent lease with creator=update-create-allow-user.
				// Since Leases support AllowCreateOnUpdate, this becomes a create.
				// The create authorization should succeed because the condition is met.
				_, err := client.CoordinationV1().Leases("test-ns").Update(context.TODO(), &coordinationv1.Lease{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "update-create-allowed",
						Labels: map[string]string{"creator": "update-create-allow-user"},
					},
				}, metav1.UpdateOptions{})
				/*_, err := client.CoordinationV1().Leases("test-ns").Apply(context.TODO(),
				applyconfigurationscoordinationv1.
					Lease("update-create-denied", "test-ns").
					WithLabels(map[string]string{"creator": "update-create-allow-user"}),
				metav1.ApplyOptions{
					FieldManager: "foo",
				})*/
				return err
			},
			expectAllowed: true,
			// When disabled, the conditional create decision is treated as NoOpinion,
			// falls through to RBAC which denies (no RBAC rules for this user).
			expectAllowedWhenDisabled: boolPtr(false),
		},
		{
			name: "update-to-create conditional deny by label",
			user: "update-create-deny-user",
			webhookBehavior: func(ws *webhookServerHandler) {
				ws.sarHandler = func(sar *authorizationv1.SubjectAccessReview) {
					if sar.Spec.ResourceAttributes == nil {
						return
					}
					switch sar.Spec.ResourceAttributes.Verb {
					case "update", "patch":
						// Unconditionally allow updates
						sar.Status.Allowed = true
						sar.Status.Reason = "updates always allowed"
					case "create":
						// Conditionally allow creates: only when creator=update-create-deny-user
						sar.Status.ConditionalDecisionChain = []authorizationv1.SubjectAccessReviewAuthorizationDecision{
							{
								ConditionsType: "webhook",
								Conditions: []authorizationv1.SubjectAccessReviewCondition{
									{
										ID:     "require-owner-label",
										Effect: authorizationv1.SubjectAccessReviewConditionEffectAllow,
										Condition: `has(object.metadata.labels) && ` +
											`has(object.metadata.labels.creator) && ` +
											`object.metadata.labels.creator == "update-create-deny-user"`,
										Description: "only allow creates when creator=update-create-deny-user",
									},
								},
							},
						}
					}
				}
				ws.acrHandler = func(acr *authorizationv1alpha1.AuthorizationConditionsReview) {
					allowed, denied := celEvaluateConditions(ws.t, acr)
					acr.Response = &authorizationv1alpha1.AuthorizationConditionsResponse{
						SubjectAccessReviewAuthorizationDecision: authorizationv1alpha1.SubjectAccessReviewAuthorizationDecision{
							Allowed: allowed,
							Denied:  denied,
						},
					}
				}
			},
			makeRequest: func(t *testing.T, client *clientset.Clientset) error {
				// PUT a non-existent lease with classified=true.
				// The create authorization should fail because the condition is not met.
				_, err := client.CoordinationV1().Leases("test-ns").Update(context.TODO(), &coordinationv1.Lease{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "update-create-denied",
						Labels: map[string]string{"creator": "not-authorized-user"},
					},
				}, metav1.UpdateOptions{})
				/*_, err := client.CoordinationV1().Leases("test-ns").Apply(context.TODO(),
				applyconfigurationscoordinationv1.
					Lease("update-create-denied", "test-ns").
					WithLabels(map[string]string{"creator": "not-authorized-user"}),
				metav1.ApplyOptions{
					FieldManager: "foo",
				})*/
				return err
			},
			expectAllowed: false,
		},
		{
			name: "update-to-create, both update and create conditions must be satisfied",
			user: "update-create-deny-user",
			webhookBehavior: func(ws *webhookServerHandler) {
				ws.sarHandler = func(sar *authorizationv1.SubjectAccessReview) {
					if sar.Spec.ResourceAttributes == nil {
						return
					}
					switch sar.Spec.ResourceAttributes.Verb {
					case "update", "patch":
						// Conditionally allow updates: only when classified=false
						sar.Status.ConditionalDecisionChain = []authorizationv1.SubjectAccessReviewAuthorizationDecision{
							{
								ConditionsType: "webhook",
								Conditions: []authorizationv1.SubjectAccessReviewCondition{
									{
										ID:     "allow-unclassified",
										Effect: authorizationv1.SubjectAccessReviewConditionEffectAllow,
										Condition: `has(object.metadata.labels) && ` +
											`has(object.metadata.labels.classified) && ` +
											`object.metadata.labels.classified == "false"`,
										Description: "only allow creates when classified=false",
									},
								},
							},
						}
					case "create":
						// Conditionally allow creates: only when creator=update-create-deny-user
						sar.Status.ConditionalDecisionChain = []authorizationv1.SubjectAccessReviewAuthorizationDecision{
							{
								ConditionsType: "webhook",
								Conditions: []authorizationv1.SubjectAccessReviewCondition{
									{
										ID:     "require-owner-label",
										Effect: authorizationv1.SubjectAccessReviewConditionEffectAllow,
										Condition: `has(object.metadata.labels) && ` +
											`has(object.metadata.labels.creator) && ` +
											`object.metadata.labels.creator == "update-create-deny-user"`,
										Description: "only allow creates when creator=update-create-deny-user",
									},
								},
							},
						}
					}
				}
				ws.acrHandler = func(acr *authorizationv1alpha1.AuthorizationConditionsReview) {
					allowed, denied := celEvaluateConditions(ws.t, acr)
					acr.Response = &authorizationv1alpha1.AuthorizationConditionsResponse{
						SubjectAccessReviewAuthorizationDecision: authorizationv1alpha1.SubjectAccessReviewAuthorizationDecision{
							Allowed: allowed,
							Denied:  denied,
						},
					}
				}
			},
			makeRequest: func(t *testing.T, client *clientset.Clientset) error {
				// PUT a non-existent lease with classified=true.
				// The create authorization should fail because the condition is not met.
				_, err := client.CoordinationV1().Leases("test-ns").Update(context.TODO(), &coordinationv1.Lease{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "update-create-denied-by-update-condition",
						Labels: map[string]string{"creator": "update-create-deny-user"},
					},
				}, metav1.UpdateOptions{})
				/*_, err := client.CoordinationV1().Leases("test-ns").Apply(context.TODO(),
				applyconfigurationscoordinationv1.
					Lease("update-create-denied-by-update-condition", "test-ns").
					// Satisfies the create condition, but not the update one
					WithLabels(map[string]string{"creator": "update-create-deny-user"}),
				metav1.ApplyOptions{
					FieldManager: "foo",
				})*/
				return err
			},
			expectAllowed: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Configure the webhook behavior for this test case
			tc.webhookBehavior(webhookServer.handler)

			// For tests that need RBAC fallthrough, grant RBAC access
			if tc.user == "conditional-noop-rbac-user" || tc.user == "webhook-noop-rbac-user" {
				authutil.GrantUserAuthorization(t, context.TODO(), adminClient, tc.user,
					rbacv1.PolicyRule{
						Verbs:     []string{"list", "get"},
						APIGroups: []string{""},
						Resources: []string{"configmaps"},
					},
				)
			}

			// Create an impersonated client for the test user
			impersonationConfig := rest.CopyConfig(server.ClientConfig)
			impersonationConfig.Impersonate.UserName = tc.user
			userClient := clientset.NewForConfigOrDie(impersonationConfig)

			// Execute the request
			err := tc.makeRequest(t, userClient)

			expected := tc.expectAllowed
			if !featureEnabled && tc.expectAllowedWhenDisabled != nil {
				expected = *tc.expectAllowedWhenDisabled
			}

			if expected {
				if err != nil {
					t.Fatalf("expected request to be allowed, got error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected request to be denied, got success")
				}
				if !apierrors.IsForbidden(err) && !apierrors.IsUnauthorized(err) {
					t.Fatalf("expected Forbidden or Unauthorized error, got: %v", err)
				}
			}
		})
	}
}

func boolPtr(b bool) *bool {
	return &b
}

// webhookServer wraps an httptest.Server serving both SubjectAccessReview and
// AuthorizationConditionsReview on its /authorize endpoint.
type webhookServer struct {
	server  *httptest.Server
	handler *webhookServerHandler
}

type webhookServerHandler struct {
	t          *testing.T
	sarHandler func(sar *authorizationv1.SubjectAccessReview)
	acrHandler func(acr *authorizationv1alpha1.AuthorizationConditionsReview)
}

func newWebhookServer(t *testing.T) *webhookServer {
	handler := &webhookServerHandler{t: t}
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", handler.serveSAR)
	mux.HandleFunc("/conditionsreview", handler.serveACR)
	server := httptest.NewTLSServer(mux)
	return &webhookServer{
		server:  server,
		handler: handler,
	}
}

func (h *webhookServerHandler) serveSAR(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "only POST is supported", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		h.t.Errorf("failed to read request body: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer req.Body.Close()

	h.handleSAR(w, body)
}

func (h *webhookServerHandler) serveACR(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "only POST is supported", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		h.t.Errorf("failed to read request body: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer req.Body.Close()

	h.handleACR(w, body)
}

func (h *webhookServerHandler) handleSAR(w http.ResponseWriter, body []byte) {
	sar := &authorizationv1.SubjectAccessReview{}
	if err := json.Unmarshal(body, sar); err != nil {
		h.t.Errorf("failed to unmarshal SubjectAccessReview: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.t.Logf("SAR request for user=%q resource=%v verb=%v ns=%v",
		sar.Spec.User,
		safeResourceAttr(sar, func(ra *authorizationv1.ResourceAttributes) string { return ra.Resource }),
		safeResourceAttr(sar, func(ra *authorizationv1.ResourceAttributes) string { return ra.Verb }),
		safeResourceAttr(sar, func(ra *authorizationv1.ResourceAttributes) string { return ra.Namespace }),
	)

	if h.sarHandler != nil {
		h.sarHandler(sar)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(sar); err != nil {
		h.t.Errorf("failed to encode SAR response: %v", err)
	}
}

func (h *webhookServerHandler) handleACR(w http.ResponseWriter, body []byte) {
	acr := &authorizationv1alpha1.AuthorizationConditionsReview{}
	if err := json.Unmarshal(body, acr); err != nil {
		h.t.Errorf("failed to unmarshal AuthorizationConditionsReview: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.t.Logf("ACR request: decision conditions count=%d", len(acr.Request.Decision.Conditions))

	if h.acrHandler != nil {
		h.acrHandler(acr)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(acr); err != nil {
		h.t.Errorf("failed to encode ACR response: %v", err)
	}
}

func safeResourceAttr(sar *authorizationv1.SubjectAccessReview, fn func(*authorizationv1.ResourceAttributes) string) string {
	if sar.Spec.ResourceAttributes != nil {
		return fn(sar.Spec.ResourceAttributes)
	}
	return "<non-resource>"
}

// celEvaluateConditions evaluates CEL conditions from an ACR request against
// the objects in the write request. It follows the condition precedence:
// Deny > NoOpinion > Allow (matching EvaluateConditionSet semantics).
// Returns (allowed, denied).
func celEvaluateConditions(t *testing.T, acr *authorizationv1alpha1.AuthorizationConditionsReview) (bool, bool) {
	t.Helper()

	env, err := cel.NewEnv(
		cel.Variable("object", cel.DynType),
		cel.Variable("oldObject", cel.DynType),
		cel.Variable("request", cel.DynType),
	)
	if err != nil {
		t.Fatalf("failed to create CEL env: %v", err)
	}

	// Deserialize object and oldObject from RawExtension JSON
	var objectMap map[string]any
	if len(acr.Request.WriteRequest.Object.Raw) > 0 {
		if err := json.Unmarshal(acr.Request.WriteRequest.Object.Raw, &objectMap); err != nil {
			t.Fatalf("failed to unmarshal object: %v", err)
		}
	}

	var oldObjectMap map[string]any
	if len(acr.Request.WriteRequest.OldObject.Raw) > 0 {
		if err := json.Unmarshal(acr.Request.WriteRequest.OldObject.Raw, &oldObjectMap); err != nil {
			t.Fatalf("failed to unmarshal oldObject: %v", err)
		}
	}

	requestMap := map[string]any{
		"operation": string(acr.Request.WriteRequest.Operation),
		"namespace": acr.Request.WriteRequest.Namespace,
		"name":      acr.Request.WriteRequest.Name,
	}

	vars := map[string]any{
		"object":    objectMap,
		"oldObject": oldObjectMap,
		"request":   requestMap,
	}

	conditions := collectConditions(acr.Request.Decision)

	// Phase 1: Deny conditions
	for _, cond := range conditions {
		if cond.Effect != authorizationv1alpha1.SubjectAccessReviewConditionEffectDeny {
			continue
		}
		if evalCEL(t, env, cond.Condition, vars) {
			return false, true
		}
	}

	// Phase 2: NoOpinion conditions
	for _, cond := range conditions {
		if cond.Effect != authorizationv1alpha1.SubjectAccessReviewConditionEffectNoOpinion {
			continue
		}
		if evalCEL(t, env, cond.Condition, vars) {
			return false, false
		}
	}

	// Phase 3: Allow conditions
	for _, cond := range conditions {
		if cond.Effect != authorizationv1alpha1.SubjectAccessReviewConditionEffectAllow {
			continue
		}
		if evalCEL(t, env, cond.Condition, vars) {
			return true, false
		}
	}

	// Default: NoOpinion
	return false, false
}

// collectConditions recursively extracts all conditions from a decision.
// When the decision comes through an aggregated API server, the conditions may
// be nested inside ConditionalDecisionChain entries rather than at the top level.
func collectConditions(decision authorizationv1alpha1.SubjectAccessReviewAuthorizationDecision) []authorizationv1alpha1.SubjectAccessReviewCondition {
	if len(decision.Conditions) > 0 {
		return decision.Conditions
	}
	var conditions []authorizationv1alpha1.SubjectAccessReviewCondition
	for _, subDecision := range decision.ConditionalDecisionChain {
		conditions = append(conditions, collectConditions(subDecision)...)
	}
	return conditions
}

// evalCEL compiles and evaluates a single CEL expression, returning true/false.
func evalCEL(t *testing.T, env *cel.Env, expr string, vars map[string]any) bool {
	t.Helper()
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		t.Fatalf("CEL compile error for %q: %v", expr, issues.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		t.Fatalf("CEL program error for %q: %v", expr, err)
	}
	out, _, err := prg.Eval(vars)
	if err != nil {
		t.Fatalf("CEL eval error for %q: %v", expr, err)
	}
	result, ok := out.Value().(bool)
	if !ok {
		t.Fatalf("CEL expression %q did not return bool, got %T", expr, out.Value())
	}
	return result
}
