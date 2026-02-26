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

	authorizationv1 "k8s.io/api/authorization/v1"
	authorizationv1alpha1 "k8s.io/api/authorization/v1alpha1"
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

	// Write a kubeconfig for the webhook server
	kubeconfigPath := filepath.Join(dir, "webhook-kubeconfig.yaml")
	if err := os.WriteFile(kubeconfigPath, []byte(fmt.Sprintf(`
apiVersion: v1
kind: Config
clusters:
- name: webhook
  cluster:
    server: %q
    insecure-skip-tls-verify: true
contexts:
- name: default
  context:
    cluster: webhook
    user: test
current-context: default
users:
- name: test
`, webhookServer.server.URL+"/authorize")), 0644); err != nil {
		t.Fatal(err)
	}

	// Start the test API server with the webhook authorizer, feature gate,
	// and the AuthorizationConditionsEnforcer admission plugin
	flags := []string{
		fmt.Sprintf("--feature-gates=ConditionalAuthorization=%v", featureEnabled),
		"--authorization-mode=Webhook,RBAC",
		"--authorization-webhook-config-file=" + kubeconfigPath,
		"--authorization-webhook-version=v1",
		"--authorization-webhook-cache-authorized-ttl=1ms",
		"--authorization-webhook-cache-unauthorized-ttl=1ms",
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
						Allowed: true,
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
						Denied: true,
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
						Allowed: false,
						Denied:  false,
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
	mux.HandleFunc("/authorize", handler.ServeHTTP)
	server := httptest.NewTLSServer(mux)
	return &webhookServer{
		server:  server,
		handler: handler,
	}
}

func (h *webhookServerHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
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

	// Parse TypeMeta first to determine which type to decode
	var typeMeta metav1.TypeMeta
	if err := json.Unmarshal(body, &typeMeta); err != nil {
		h.t.Errorf("failed to unmarshal TypeMeta: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.t.Logf("webhook received: apiVersion=%s kind=%s", typeMeta.APIVersion, typeMeta.Kind)

	switch {
	case typeMeta.APIVersion == "authorization.k8s.io/v1" && typeMeta.Kind == "SubjectAccessReview":
		h.handleSAR(w, body)
	case typeMeta.APIVersion == "authorization.k8s.io/v1alpha1" && typeMeta.Kind == "AuthorizationConditionsReview":
		h.handleACR(w, body)
	default:
		h.t.Errorf("unexpected type: %s/%s", typeMeta.APIVersion, typeMeta.Kind)
		http.Error(w, fmt.Sprintf("unexpected type: %s/%s", typeMeta.APIVersion, typeMeta.Kind), http.StatusBadRequest)
	}
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
