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
	"context"
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

func newObjectInterfacesForTest() admission.ObjectInterfaces {
	scheme := runtime.NewScheme()
	corev1.AddToScheme(scheme)
	return admission.NewObjectInterfacesFromScheme(scheme)
}

func endpointCreateAttributes() admission.Attributes {
	object := &corev1.Endpoints{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Endpoints",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "endpoints1",
			Namespace: "default",
		},
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: []corev1.EndpointAddress{{IP: "127.0.0.1"}},
			},
		},
	}
	gvk := schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Endpoints"}
	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "endpoints"}
	return admission.NewAttributesRecord(object, nil, gvk, "default", "endpoints1", gvr, "", admission.Create, &metav1.CreateOptions{}, false, nil)
}

func endpointUpdateAttributes() admission.Attributes {
	oldObject := &corev1.Endpoints{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Endpoints",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "endpoints1",
			Namespace: "default",
		},
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: []corev1.EndpointAddress{{IP: "127.0.0.1"}},
			},
		},
	}
	newObject := &corev1.Endpoints{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Endpoints",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "endpoints1",
			Namespace: "default",
		},
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: []corev1.EndpointAddress{{IP: "10.0.0.1"}},
			},
		},
	}
	gvk := schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Endpoints"}
	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "endpoints"}
	return admission.NewAttributesRecord(newObject, oldObject, gvk, "default", "endpoints1", gvr, "", admission.Update, &metav1.UpdateOptions{}, false, nil)
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

func TestCelConditionsEnforcer_EvaluateConditions_NilWriteRequest(t *testing.T) {
	enforcer := &celConditionsEnforcer{}
	decision := authorizer.DecisionAllow("test")

	// conditionsData with nil WriteRequest should just return the unevaluated decision
	data := &noWriteRequestData{}
	result, err := enforcer.EvaluateConditions(context.Background(), decision, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsAllowed() {
		t.Errorf("expected Allow decision, got %v", result)
	}
}

type noWriteRequestData struct{}

func (d *noWriteRequestData) WriteRequest() authorizer.WriteRequestConditionData { return nil }
func (d *noWriteRequestData) ImpersonationRequest() authorizer.ImpersonationRequestConditionData {
	return nil
}

func TestCelConditionsEnforcer_ConcreteDecisions(t *testing.T) {
	enforcer := &celConditionsEnforcer{}
	va := makeVersionedAttrs(t, endpointCreateAttributes())
	data := conditionsData{attrsShim: attrsShim{VersionedAttributes: va}}

	tests := []struct {
		name     string
		decision authorizer.Decision
		check    func(t *testing.T, d authorizer.Decision)
	}{
		{
			name:     "Allow passes through",
			decision: authorizer.DecisionAllow("already allowed"),
			check: func(t *testing.T, d authorizer.Decision) {
				if !d.IsAllowed() {
					t.Errorf("expected Allow, got %v", d)
				}
			},
		},
		{
			name:     "Deny passes through",
			decision: authorizer.DecisionDeny("already denied"),
			check: func(t *testing.T, d authorizer.Decision) {
				if !d.IsDenied() {
					t.Errorf("expected Deny, got %v", d)
				}
			},
		},
		{
			name:     "NoOpinion passes through",
			decision: authorizer.DecisionNoOpinion("no opinion"),
			check: func(t *testing.T, d authorizer.Decision) {
				if !d.IsNoOpinion() {
					t.Errorf("expected NoOpinion, got %v", d)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := enforcer.EvaluateConditions(context.Background(), tc.decision, data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			tc.check(t, result)
		})
	}
}

func TestCelConditionsEnforcer_NonAttrsShimWriteRequest(t *testing.T) {
	enforcer := &celConditionsEnforcer{}
	decision := makeConditionalDecision(t, ConditionTypeAuthorizationCEL, map[string]authorizer.Condition{
		"test-cond": {
			Condition: "true",
			Effect:    authorizer.ConditionEffectAllow,
		},
	})

	// Use a ConditionData where WriteRequest() returns a non-attrsShim type
	data := &fakeWriteRequestData{}
	result, err := enforcer.evaluateWriteRequest(context.Background(), decision, data, celconfig.RuntimeCELCostBudget)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should return the unevaluated decision because it can't cast to *attrsShim
	if !result.IsConditional() {
		t.Errorf("expected conditional decision to pass through, got %v", result)
	}
}

type fakeWriteRequestData struct{}

func (d *fakeWriteRequestData) GetOperation() string                { return "CREATE" }
func (d *fakeWriteRequestData) GetOperationOptions() runtime.Object { return nil }
func (d *fakeWriteRequestData) GetObject() runtime.Object           { return nil }
func (d *fakeWriteRequestData) GetOldObject() runtime.Object        { return nil }

func TestCelConditionsEnforcer_EvaluateWriteRequest(t *testing.T) {
	tests := []struct {
		name       string
		attrs      admission.Attributes
		conditions map[string]authorizer.Condition
		check      func(t *testing.T, d authorizer.Decision, err error)
	}{
		{
			name:  "single allow condition evaluates to true",
			attrs: endpointCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"allow-cond": {
					Condition: "object.metadata.name == 'endpoints1'",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			check: func(t *testing.T, d authorizer.Decision, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !d.IsAllowed() {
					t.Errorf("expected Allow, got %v", d)
				}
			},
		},
		{
			name:  "single allow condition evaluates to false",
			attrs: endpointCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"allow-cond": {
					Condition: "object.metadata.name == 'something-else'",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			check: func(t *testing.T, d authorizer.Decision, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !d.IsNoOpinion() {
					t.Errorf("expected NoOpinion (no conditions matched), got %v", d)
				}
			},
		},
		{
			name:  "single deny condition evaluates to true",
			attrs: endpointCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"deny-cond": {
					Condition:   "object.metadata.name == 'endpoints1'",
					Effect:      authorizer.ConditionEffectDeny,
					Description: "endpoints1 not allowed",
				},
			},
			check: func(t *testing.T, d authorizer.Decision, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !d.IsDenied() {
					t.Errorf("expected Deny, got %v", d)
				}
			},
		},
		{
			name:  "single deny condition evaluates to false",
			attrs: endpointCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"deny-cond": {
					Condition: "object.metadata.name == 'something-else'",
					Effect:    authorizer.ConditionEffectDeny,
				},
			},
			check: func(t *testing.T, d authorizer.Decision, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !d.IsNoOpinion() {
					t.Errorf("expected NoOpinion (no conditions matched), got %v", d)
				}
			},
		},
		{
			name:  "single noopinion condition evaluates to true",
			attrs: endpointCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"noop-cond": {
					Condition: "object.metadata.name == 'endpoints1'",
					Effect:    authorizer.ConditionEffectNoOpinion,
				},
			},
			check: func(t *testing.T, d authorizer.Decision, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !d.IsNoOpinion() {
					t.Errorf("expected NoOpinion, got %v", d)
				}
			},
		},
		{
			name:  "allow with object field check",
			attrs: endpointCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"allow-cond": {
					Condition: "has(object.subsets) && object.subsets.size() == 1",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			check: func(t *testing.T, d authorizer.Decision, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !d.IsAllowed() {
					t.Errorf("expected Allow, got %v", d)
				}
			},
		},
		{
			name:  "deny takes precedence over allow",
			attrs: endpointCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"allow-cond": {
					Condition: "object.metadata.name == 'endpoints1'",
					Effect:    authorizer.ConditionEffectAllow,
				},
				"deny-cond": {
					Condition: "object.metadata.name == 'endpoints1'",
					Effect:    authorizer.ConditionEffectDeny,
				},
			},
			check: func(t *testing.T, d authorizer.Decision, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				// Deny conditions are evaluated before Allow conditions, so deny wins
				if !d.IsDenied() {
					t.Errorf("expected Deny (deny takes precedence), got %v", d)
				}
			},
		},
		{
			name:  "noopinion takes precedence over allow",
			attrs: endpointCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"allow-cond": {
					Condition: "object.metadata.name == 'endpoints1'",
					Effect:    authorizer.ConditionEffectAllow,
				},
				"noop-cond": {
					Condition: "object.metadata.name == 'endpoints1'",
					Effect:    authorizer.ConditionEffectNoOpinion,
				},
			},
			check: func(t *testing.T, d authorizer.Decision, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				// NoOpinion conditions are evaluated before Allow conditions
				if !d.IsNoOpinion() {
					t.Errorf("expected NoOpinion (noopinion takes precedence over allow), got %v", d)
				}
			},
		},
		{
			name:  "CEL expression using request object",
			attrs: endpointCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"allow-cond": {
					Condition: "request.kind.kind == 'Endpoints'",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			check: func(t *testing.T, d authorizer.Decision, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !d.IsAllowed() {
					t.Errorf("expected Allow, got %v", d)
				}
			},
		},
		{
			name:  "CEL expression using request namespace",
			attrs: endpointCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"allow-cond": {
					Condition: "request.namespace == 'default'",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			check: func(t *testing.T, d authorizer.Decision, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !d.IsAllowed() {
					t.Errorf("expected Allow, got %v", d)
				}
			},
		},
		{
			name:  "CEL expression using request operation",
			attrs: endpointCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"allow-cond": {
					Condition: "request.operation == 'CREATE'",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			check: func(t *testing.T, d authorizer.Decision, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !d.IsAllowed() {
					t.Errorf("expected Allow, got %v", d)
				}
			},
		},
		{
			name:  "CEL expression with oldObject on update",
			attrs: endpointUpdateAttributes(),
			conditions: map[string]authorizer.Condition{
				"allow-cond": {
					Condition: "oldObject != null && object != null",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			check: func(t *testing.T, d authorizer.Decision, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !d.IsAllowed() {
					t.Errorf("expected Allow, got %v", d)
				}
			},
		},
		{
			name:  "CEL expression with oldObject null on create",
			attrs: endpointCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"allow-cond": {
					Condition: "oldObject == null",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			check: func(t *testing.T, d authorizer.Decision, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !d.IsAllowed() {
					t.Errorf("expected Allow, got %v", d)
				}
			},
		},
		{
			name:  "invalid CEL expression returns error",
			attrs: endpointCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"bad-cond": {
					Condition: "1 < 'asdf'",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			check: func(t *testing.T, d authorizer.Decision, err error) {
				// The condition should produce a compilation error which results
				// in an error from the evaluator.
				if err == nil {
					t.Errorf("expected error for invalid CEL expression, got nil")
				}
			},
		},
		{
			name:  "deny condition with description",
			attrs: endpointCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"deny-desc": {
					Condition:   "object.metadata.name == 'endpoints1'",
					Effect:      authorizer.ConditionEffectDeny,
					Description: "deny this endpoint by name",
				},
			},
			check: func(t *testing.T, d authorizer.Decision, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !d.IsDenied() {
					t.Errorf("expected Deny, got %v", d)
				}
				reason := d.Reason()
				if reason == "" {
					t.Errorf("expected non-empty reason with description, got empty")
				}
			},
		},
		{
			name:  "multiple allow conditions first match wins",
			attrs: endpointCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"allow-1": {
					Condition: "object.metadata.name == 'endpoints1'",
					Effect:    authorizer.ConditionEffectAllow,
				},
				"allow-2": {
					Condition: "object.metadata.name == 'something-else'",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			check: func(t *testing.T, d authorizer.Decision, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !d.IsAllowed() {
					t.Errorf("expected Allow, got %v", d)
				}
			},
		},
		{
			name:  "no matching conditions returns NoOpinion",
			attrs: endpointCreateAttributes(),
			conditions: map[string]authorizer.Condition{
				"allow-1": {
					Condition: "object.metadata.name == 'never-matches'",
					Effect:    authorizer.ConditionEffectAllow,
				},
			},
			check: func(t *testing.T, d authorizer.Decision, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !d.IsNoOpinion() {
					t.Errorf("expected NoOpinion, got %v", d)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decision := makeConditionalDecision(t, ConditionTypeAuthorizationCEL, tc.conditions)

			enforcer := &celConditionsEnforcer{}
			va := makeVersionedAttrs(t, tc.attrs)
			wr := &attrsShim{VersionedAttributes: va}
			result, err := enforcer.evaluateWriteRequest(context.Background(), decision, wr, celconfig.RuntimeCELCostBudget)
			tc.check(t, result, err)
		})
	}
}

func TestCelConditionsEnforcer_WrongConditionType(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, genericfeatures.ConditionalAuthorization, true)

	attrs := authorizer.AttributesRecord{
		ConditionsMode: authorizer.ConditionsModeHumanReadable,
	}
	decision, err := authorizer.DecisionConditional(attrs, "some.io/other-type", maps.All(map[string]authorizer.Condition{
		"allow-cond": {
			Condition: "true",
			Effect:    authorizer.ConditionEffectAllow,
		},
	}))
	if err != nil {
		t.Fatalf("failed to create conditional decision: %v", err)
	}

	enforcer := &celConditionsEnforcer{}
	va := makeVersionedAttrs(t, endpointCreateAttributes())
	wr := &attrsShim{VersionedAttributes: va}
	result, err := enforcer.evaluateWriteRequest(context.Background(), decision, wr, celconfig.RuntimeCELCostBudget)
	if err == nil {
		t.Fatalf("expected error for wrong condition type, got nil")
	}
	// With only allow conditions and wrong type, FailClosedDecision returns NoOpinion
	if !result.IsNoOpinion() {
		t.Errorf("expected NoOpinion for wrong condition type with only allow conditions, got %v", result)
	}
}

func TestCelConditionsEnforcer_WrongConditionTypeWithDeny(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, genericfeatures.ConditionalAuthorization, true)

	attrs := authorizer.AttributesRecord{
		ConditionsMode: authorizer.ConditionsModeHumanReadable,
	}
	decision, err := authorizer.DecisionConditional(attrs, "some.io/other-type", maps.All(map[string]authorizer.Condition{
		"deny-cond": {
			Condition: "true",
			Effect:    authorizer.ConditionEffectDeny,
		},
	}))
	if err != nil {
		t.Fatalf("failed to create conditional decision: %v", err)
	}

	enforcer := &celConditionsEnforcer{}
	va := makeVersionedAttrs(t, endpointCreateAttributes())
	wr := &attrsShim{VersionedAttributes: va}
	result, err := enforcer.evaluateWriteRequest(context.Background(), decision, wr, celconfig.RuntimeCELCostBudget)
	if err == nil {
		t.Fatalf("expected error for wrong condition type, got nil")
	}
	// With deny conditions and wrong type, FailClosedDecision returns Deny
	if !result.IsDenied() {
		t.Errorf("expected Deny for wrong condition type with deny conditions, got %v", result)
	}
}

func TestCelConditionsEnforcer_CostBudgetExceeded(t *testing.T) {
	enforcer := &celConditionsEnforcer{}
	decision := makeConditionalDecision(t, ConditionTypeAuthorizationCEL, map[string]authorizer.Condition{
		"allow-cond": {
			Condition: "has(object.subsets) && object.subsets.size() < 2",
			Effect:    authorizer.ConditionEffectAllow,
		},
	})

	va := makeVersionedAttrs(t, endpointCreateAttributes())
	wr := &attrsShim{VersionedAttributes: va}
	// Use a very small budget to trigger cost exceeded error
	result, err := enforcer.evaluateWriteRequest(context.Background(), decision, wr, 1)
	if err == nil {
		t.Fatalf("expected error for cost budget exceeded, got nil")
	}
	// Allow condition error means NoOpinion (no matching conditions)
	if result.IsAllowed() {
		t.Errorf("expected non-Allow result when cost budget exceeded, got %v", result)
	}
}

func TestCelConditionsEnforcer_CostBudgetExceeded_DenyCondition(t *testing.T) {
	enforcer := &celConditionsEnforcer{}
	decision := makeConditionalDecision(t, ConditionTypeAuthorizationCEL, map[string]authorizer.Condition{
		"deny-cond": {
			Condition: "has(object.subsets) && object.subsets.size() < 2",
			Effect:    authorizer.ConditionEffectDeny,
		},
	})

	va := makeVersionedAttrs(t, endpointCreateAttributes())
	wr := &attrsShim{VersionedAttributes: va}
	// Use a very small budget to trigger cost exceeded error on a deny condition
	result, err := enforcer.evaluateWriteRequest(context.Background(), decision, wr, 1)
	if err == nil {
		t.Fatalf("expected error for cost budget exceeded, got nil")
	}
	// Deny condition error means Deny (fail closed)
	if !result.IsDenied() {
		t.Errorf("expected Deny when deny condition cost budget exceeded, got %v", result)
	}
}

func TestCelConditionsEnforcer_EvaluateConditions_FullFlow(t *testing.T) {
	enforcer := &celConditionsEnforcer{}
	decision := makeConditionalDecision(t, ConditionTypeAuthorizationCEL, map[string]authorizer.Condition{
		"allow-cond": {
			Condition: "object.metadata.name == 'endpoints1'",
			Effect:    authorizer.ConditionEffectAllow,
		},
	})

	va := makeVersionedAttrs(t, endpointCreateAttributes())
	data := conditionsData{attrsShim: attrsShim{VersionedAttributes: va}}

	result, err := enforcer.EvaluateConditions(context.Background(), decision, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsAllowed() {
		t.Errorf("expected Allow, got %v", result)
	}
}

func TestCelConditionsEnforcer_EvaluateConditions_UpdateFlow(t *testing.T) {
	enforcer := &celConditionsEnforcer{}
	decision := makeConditionalDecision(t, ConditionTypeAuthorizationCEL, map[string]authorizer.Condition{
		"allow-cond": {
			Condition: "object != null && oldObject != null && object.metadata.name == oldObject.metadata.name",
			Effect:    authorizer.ConditionEffectAllow,
		},
	})

	va := makeVersionedAttrs(t, endpointUpdateAttributes())
	data := conditionsData{attrsShim: attrsShim{VersionedAttributes: va}}

	result, err := enforcer.EvaluateConditions(context.Background(), decision, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsAllowed() {
		t.Errorf("expected Allow, got %v", result)
	}
}
