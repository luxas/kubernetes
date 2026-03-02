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

package conditionsenforcer

import (
	"maps"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	genericfeatures "k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
)

var (
	podGVK = schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"}
	podGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
)

func newObjectInterfacesForTest() admission.ObjectInterfaces {
	scheme := runtime.NewScheme()
	corev1.AddToScheme(scheme)
	return admission.NewObjectInterfacesFromScheme(scheme)
}

func podCreateAttributes() admission.Attributes {
	object := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			Labels:    map[string]string{"app": "web"},
		},
		Spec: corev1.PodSpec{
			NodeName: "node1",
		},
	}
	return admission.NewAttributesRecord(object, nil, podGVK, "default", "test-pod", podGVR, "", admission.Create, &metav1.CreateOptions{}, false, nil)
}

func podUpdateAttributes() admission.Attributes {
	oldObject := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			Labels:    map[string]string{"app": "web"},
		},
		Spec: corev1.PodSpec{
			NodeName: "node1",
		},
	}
	newObject := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			Labels:    map[string]string{"app": "web", "version": "v2"},
		},
		Spec: corev1.PodSpec{
			NodeName: "node2",
		},
	}
	return admission.NewAttributesRecord(newObject, oldObject, podGVK, "default", "test-pod", podGVR, "", admission.Update, &metav1.UpdateOptions{}, false, nil)
}

func makeVersionedAttrs(t *testing.T, attrs admission.Attributes) *admission.VersionedAttributes {
	t.Helper()
	va, err := admission.NewVersionedAttributes(attrs, attrs.GetKind(), newObjectInterfacesForTest())
	if err != nil {
		t.Fatalf("failed to create versioned attributes: %v", err)
	}
	return va
}

func makeConditionalDecision(t *testing.T, conditionType authorizer.ConditionType, conditions map[string]authorizer.Condition) authorizer.Decision {
	t.Helper()
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, genericfeatures.ConditionalAuthorization, true)
	attrs := authorizer.AttributesRecord{
		ConditionsMode: authorizer.ConditionsModeHumanReadable,
	}
	d, err := authorizer.DecisionConditional(attrs, conditionType, maps.All(conditions))
	if err != nil {
		t.Fatalf("failed to create conditional decision: %v", err)
	}
	return d
}

// noWriteRequestData is a ConditionData that returns nil for WriteRequest.
type noWriteRequestData struct{}

func (d *noWriteRequestData) WriteRequest() authorizer.WriteRequestConditionData { return nil }
func (d *noWriteRequestData) ImpersonationRequest() authorizer.ImpersonationRequestConditionData {
	return nil
}

// fakeWriteRequestData implements WriteRequestConditionData but is not an *attrsShim.
type fakeWriteRequestData struct{}

func (d *fakeWriteRequestData) GetOperation() string                { return "CREATE" }
func (d *fakeWriteRequestData) GetOperationOptions() runtime.Object { return nil }
func (d *fakeWriteRequestData) GetObject() runtime.Object           { return nil }
func (d *fakeWriteRequestData) GetOldObject() runtime.Object        { return nil }

// TestCelConditionsEnforcer_NoOp tests all cases where the enforcer is a no-op
// and returns the unevaluated decision unchanged: nil WriteRequest, concrete
// decisions (Allow/Deny/NoOpinion), and non-attrsShim WriteRequest data.
func TestCelConditionsEnforcer_NoOp(t *testing.T) {
	enforcer := &celConditionsEnforcer{}
	va := makeVersionedAttrs(t, podCreateAttributes())
	writeRequestData := conditionsData{attrsShim: attrsShim{VersionedAttributes: va}}

	tests := []struct {
		name         string
		decision     authorizer.Decision
		data         authorizer.ConditionData
		wantDecision string
	}{
		{
			name:         "nil WriteRequest returns unevaluated decision",
			decision:     authorizer.DecisionAllow("test"),
			data:         &noWriteRequestData{},
			wantDecision: "Allow",
		},
		{
			name:         "Allow passes through",
			decision:     authorizer.DecisionAllow("already allowed"),
			data:         writeRequestData,
			wantDecision: "Allow",
		},
		{
			name:         "Deny passes through",
			decision:     authorizer.DecisionDeny("already denied"),
			data:         writeRequestData,
			wantDecision: "Deny",
		},
		{
			name:         "NoOpinion passes through",
			decision:     authorizer.DecisionNoOpinion("no opinion"),
			data:         writeRequestData,
			wantDecision: "NoOpinion",
		},
		{
			name: "Conditional of the wrong type cannot be simplified",
			decision: makeConditionalDecision(t, "some.io/unsupported-type", map[string]authorizer.Condition{
				"test-cond": {
					Condition: "true",
					Effect:    authorizer.ConditionEffectAllow,
				},
			}),
			data:         writeRequestData,
			wantDecision: `Conditional(type="some.io/unsupported-type", len=1)`,
		},
		{
			name: "Conditional of the supported CEL type simplifies to Allow",
			decision: makeConditionalDecision(t, ConditionTypeAuthorizationCEL, map[string]authorizer.Condition{
				"test-cond": {
					Condition: "true",
					Effect:    authorizer.ConditionEffectAllow,
				},
			}),
			data:         writeRequestData,
			wantDecision: `Allow`,
		},
		// TODO(luxas): Add tests for ConditionalChain here too.
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := enforcer.EvaluateConditions(t.Context(), tc.decision, tc.data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := result.String(); got != tc.wantDecision {
				t.Errorf("got %s, want %s", got, tc.wantDecision)
			}
		})
	}

	// TODO(luxas): Hopefully we can remove this test/check in the future, and just use data given.
	t.Run("non-attrsShim WriteRequest passes through conditional", func(t *testing.T) {
		conditionalDecision := makeConditionalDecision(t, ConditionTypeAuthorizationCEL, map[string]authorizer.Condition{
			"test-cond": {
				Condition: "true",
				Effect:    authorizer.ConditionEffectAllow,
			},
		})
		result, err := enforcer.evaluateWriteRequest(t.Context(), conditionalDecision, &fakeWriteRequestData{}, celconfig.RuntimeCELCostBudget)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.IsConditional() {
			t.Errorf("got %s, want Conditional (pass-through)", result.String())
		}
	})
}

func TestCelConditionsEnforcer_EvaluateWriteRequest(t *testing.T) {
	tests := []struct {
		name         string
		attrs        admission.Attributes
		conditions   map[string]authorizer.Condition
		costBudget   int64
		wantDecision string
		wantErr      bool
	}{
		{
			name:  "single allow condition evaluates to true",
			attrs: podCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"allow-cond": {
					Condition: "'app' in object.metadata.labels && object.metadata.labels.app == 'web'",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			wantDecision: "Allow",
		},
		{
			name:  "single allow condition evaluates to false",
			attrs: podCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"allow-cond": {
					Condition: "has(object.metadata.labels.app) && object.metadata.labels.app == 'notfound'",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			wantDecision: "NoOpinion",
		},
		{
			name:  "deny condition evaluates to true, takes precedence over allow",
			attrs: podCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"deny-cond": {
					Condition:   "has(object.metadata.labels.app)",
					Effect:      authorizer.ConditionEffectDeny,
					Description: "test-pod not allowed",
				},
				"allow-cond": {
					Condition: "object.metadata.name == 'test-pod'",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			wantDecision: "Deny",
		},
		{
			name:  "single deny condition evaluates to false",
			attrs: podCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"deny-cond": {
					Condition: "has(object.metadata.labels.notexistent)",
					Effect:    authorizer.ConditionEffectDeny,
				},
			},
			wantDecision: "NoOpinion",
		},
		{
			name:  "noopinion condition evaluates to true, takes precedence over allow",
			attrs: podCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"noop-cond": {
					Condition: "object.metadata.name == 'test-pod'",
					Effect:    authorizer.ConditionEffectNoOpinion,
				},
				"allow-cond": {
					Condition: "object.spec.nodeName == 'node1'",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			wantDecision: "NoOpinion",
		},
		{
			name:  "request.kind.kind check",
			attrs: podCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"allow-cond": {
					Condition: "request.kind.kind == 'Pod'",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			wantDecision: "Allow",
		},
		{
			name:  "request.namespace check",
			attrs: podCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"allow-cond": {
					Condition: "request.namespace == 'default'",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			wantDecision: "Allow",
		},
		{
			name:  "request.operation check",
			attrs: podCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"allow-cond": {
					Condition: "request.operation == 'CREATE'",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			wantDecision: "Allow",
		},
		{
			name:  "oldObject and object both present on update",
			attrs: podUpdateAttributes(),
			conditions: map[string]authorizer.Condition{
				"allow-cond": {
					Condition: "oldObject != null && object != null",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			wantDecision: "Allow",
		},
		{
			name:  "oldObject is null on create",
			attrs: podCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"allow-cond": {
					Condition: "oldObject == null",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			wantDecision: "Allow",
		},
		{
			name:  "update comparing old and new object",
			attrs: podUpdateAttributes(),
			conditions: map[string]authorizer.Condition{
				"allow-cond": {
					Condition: "object.spec.nodeName != oldObject.spec.nodeName",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			wantDecision: "Allow",
		},
		{
			name:  "multiple allow conditions one matches",
			attrs: podCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"allow-1": {
					Condition: "object.metadata.name == 'test-pod'",
					Effect:    authorizer.ConditionEffectAllow,
				},
				"allow-2": {
					Condition: "object.metadata.name == 'other-pod'",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			wantDecision: "Allow",
		},
		{
			name:  "no matching conditions returns NoOpinion",
			attrs: podCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"allow-cond": {
					Condition: "object.metadata.name == 'never-matches'",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			wantDecision: "NoOpinion",
		},
		{
			name:  "invalid CEL expression returns error",
			attrs: podCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"bad-cond": {
					Condition: "1 < 'asdf'",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			wantDecision: "NoOpinion",
			wantErr:      true,
		},
		{
			name:  "cost budget exceeded on allow condition",
			attrs: podCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"allow-cond": {
					Condition: "object.spec.nodeName == 'node1'",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			costBudget:   1,
			wantDecision: "NoOpinion",
			wantErr:      true,
		},
		{
			name:  "cost budget exceeded on deny condition",
			attrs: podCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"deny-cond": {
					Condition: "object.spec.nodeName == 'node1'",
					Effect:    authorizer.ConditionEffectDeny,
				},
			},
			costBudget:   1,
			wantDecision: "Deny",
			wantErr:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decision := makeConditionalDecision(t, ConditionTypeAuthorizationCEL, tc.conditions)

			enforcer := &celConditionsEnforcer{}
			va := makeVersionedAttrs(t, tc.attrs)
			wr := &attrsShim{VersionedAttributes: va}

			budget := tc.costBudget
			if budget == 0 {
				budget = celconfig.RuntimeCELCostBudget
			}

			result, err := enforcer.evaluateWriteRequest(t.Context(), decision, wr, budget)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := result.String(); got != tc.wantDecision {
				t.Errorf("got decision %s, want %s", got, tc.wantDecision)
			}
		})
	}
}
