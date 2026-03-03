/*
Copyright 2017 The Kubernetes Authors.

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

package authorizationconditionsreview

import (
	"context"
	"encoding/json"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/kubernetes/pkg/apis/admission"
	autoscalingapi "k8s.io/kubernetes/pkg/apis/autoscaling"
	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/utils/ptr"

	"github.com/google/go-cmp/cmp"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	_ "k8s.io/kubernetes/pkg/api/testing"
	authorizationapi "k8s.io/kubernetes/pkg/apis/authorization"
)

type fakeAuthorizer struct {
	evaluateDecision authorizer.Decision
	evaluateErr      error

	gotDecision authorizer.Decision
	gotData     authorizer.ConditionData
}

func (f *fakeAuthorizer) Authorize(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, error) {
	return authorizer.DecisionNoOpinion(), nil
}

func (f *fakeAuthorizer) EvaluateConditions(ctx context.Context, decision authorizer.Decision, data authorizer.ConditionData) (authorizer.Decision, error) {
	f.gotDecision = decision
	f.gotData = data
	return f.evaluateDecision, f.evaluateErr
}

func TestDecodeObject_HPA(t *testing.T) {
	r, err := NewREST(&fakeAuthorizer{}, legacyscheme.Codecs)
	if err != nil {
		t.Fatalf("unexpected error creating REST: %v", err)
	}

	hpaJSON := []byte(`{
		"apiVersion": "autoscaling/v1",
		"kind": "HorizontalPodAutoscaler",
		"metadata": {
			"name": "test-hpa",
			"namespace": "default"
		},
		"spec": {
			"maxReplicas": 10,
			"targetCPUUtilizationPercentage": 80
		}
	}`)

	obj, err := r.decodeObject(hpaJSON)
	if err != nil {
		t.Fatalf("decodeObject returned error: %v", err)
	}

	hpa, ok := obj.(*autoscalingapi.HorizontalPodAutoscaler)
	if !ok {
		t.Fatalf("expected *autoscalingapi.HorizontalPodAutoscaler, got %T", obj)
	}

	expected := &autoscalingapi.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-hpa",
			Namespace: "default",
		},
		Spec: autoscalingapi.HorizontalPodAutoscalerSpec{
			MinReplicas: ptr.To(int32(1)), // from v1 defaults
			MaxReplicas: 10,
			// from v1 -> internal conversion
			Metrics: []autoscalingapi.MetricSpec{
				{
					Type: autoscalingapi.ResourceMetricSourceType,
					Resource: &autoscalingapi.ResourceMetricSource{
						Name: api.ResourceCPU,
						Target: autoscalingapi.MetricTarget{
							Type:               autoscalingapi.UtilizationMetricType,
							AverageUtilization: ptr.To(int32(80)),
						},
					},
				},
			},
		},
	}

	if diff := cmp.Diff(expected, hpa); diff != "" {
		t.Errorf("HPA not as expected, diff=%s", diff)
	}
}

func TestDecodeObject_UnregisteredType(t *testing.T) {
	r, err := NewREST(&fakeAuthorizer{}, legacyscheme.Codecs)
	if err != nil {
		t.Fatalf("unexpected error creating REST: %v", err)
	}

	// A CRD-like object not registered in legacyscheme
	unregisteredJSON := []byte(`{
		"apiVersion": "example.com/v1",
		"kind": "Foo",
		"metadata": {
			"name": "my-foo",
			"namespace": "bar"
		},
		"spec": {
			"field1": "value1"
		}
	}`)

	obj, err := r.decodeObject(unregisteredJSON)
	if err != nil {
		t.Fatalf("decodeObject returned error for unregistered type: %v", err)
	}

	expected := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "example.com/v1",
			"kind":       "Foo",
			"metadata": map[string]any{
				"name":      "my-foo",
				"namespace": "bar",
			},
			"spec": map[string]any{
				"field1": "value1",
			},
		},
	}

	if diff := cmp.Diff(expected, obj); diff != "" {
		t.Errorf("HPA not as expected, diff=%s", diff)
	}
}

func TestDecodeObject_InvalidJSON(t *testing.T) {
	r, err := NewREST(&fakeAuthorizer{}, legacyscheme.Codecs)
	if err != nil {
		t.Fatalf("unexpected error creating REST: %v", err)
	}

	_, err = r.decodeObject([]byte(`{not valid json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestToConditionsData(t *testing.T) {
	r, err := NewREST(&fakeAuthorizer{}, legacyscheme.Codecs)
	if err != nil {
		t.Fatalf("unexpected error creating REST: %v", err)
	}

	podJSON, err := json.Marshal(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "test-pod", "namespace": "default"},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{"name": "nginx", "image": "nginx:latest"},
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to marshal pod JSON: %v", err)
	}

	req := &authorizationapi.AuthorizationConditionsRequest{
		WriteRequest: &authorizationapi.AuthorizationConditionsWriteRequest{
			Operation: admission.Create,
			Object:    runtime.RawExtension{Raw: podJSON},
		},
	}

	data, err := r.toConditionsData(req)
	if err != nil {
		t.Fatalf("toConditionsData returned error: %v", err)
	}

	wr := data.WriteRequest()
	if wr == nil {
		t.Fatal("expected non-nil WriteRequest")
	}
	if wr.GetOperation() != "CREATE" {
		t.Errorf("expected operation %q, got %q", "CREATE", wr.GetOperation())
	}

	obj := wr.GetObject()
	if obj == nil {
		t.Fatal("expected non-nil object")
	}
	pod, ok := obj.(*api.Pod)
	if !ok {
		t.Fatalf("expected *api.Pod, got %T", obj)
	}
	if pod.Name != "test-pod" {
		t.Errorf("expected pod name %q, got %q", "test-pod", pod.Name)
	}

	if wr.GetOldObject() != nil {
		t.Errorf("expected nil old object, got %v", wr.GetOldObject())
	}
}

func TestToConditionsData_NilWriteRequest(t *testing.T) {
	r, err := NewREST(&fakeAuthorizer{}, legacyscheme.Codecs)
	if err != nil {
		t.Fatalf("unexpected error creating REST: %v", err)
	}

	req := &authorizationapi.AuthorizationConditionsRequest{
		WriteRequest: nil,
	}

	_, err = r.toConditionsData(req)
	if err == nil {
		t.Fatal("expected error for nil WriteRequest, got nil")
	}
}

func TestToConditionsData_ObjectAndOldObject(t *testing.T) {
	r, err := NewREST(&fakeAuthorizer{}, legacyscheme.Codecs)
	if err != nil {
		t.Fatalf("unexpected error creating REST: %v", err)
	}

	makePodJSON := func(name string) []byte {
		data, err := json.Marshal(map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata":   map[string]interface{}{"name": name, "namespace": "default"},
			"spec": map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{"name": "nginx", "image": "nginx:latest"},
				},
			},
		})
		if err != nil {
			t.Fatalf("failed to marshal pod JSON: %v", err)
		}
		return data
	}

	req := &authorizationapi.AuthorizationConditionsRequest{
		WriteRequest: &authorizationapi.AuthorizationConditionsWriteRequest{
			Operation: admission.Update,
			Object:    runtime.RawExtension{Raw: makePodJSON("new-pod")},
			OldObject: runtime.RawExtension{Raw: makePodJSON("old-pod")},
		},
	}

	data, err := r.toConditionsData(req)
	if err != nil {
		t.Fatalf("toConditionsData returned error: %v", err)
	}

	wr := data.WriteRequest()
	if wr == nil {
		t.Fatal("expected non-nil WriteRequest")
	}
	if wr.GetOperation() != "UPDATE" {
		t.Errorf("expected operation %q, got %q", "UPDATE", wr.GetOperation())
	}

	newPod, ok := wr.GetObject().(*api.Pod)
	if !ok {
		t.Fatalf("expected *api.Pod for object, got %T", wr.GetObject())
	}
	if newPod.Name != "new-pod" {
		t.Errorf("expected object pod name %q, got %q", "new-pod", newPod.Name)
	}

	oldPod, ok := wr.GetOldObject().(*api.Pod)
	if !ok {
		t.Fatalf("expected *api.Pod for old object, got %T", wr.GetOldObject())
	}
	if oldPod.Name != "old-pod" {
		t.Errorf("expected old object pod name %q, got %q", "old-pod", oldPod.Name)
	}
}

func TestCreate_AllowedDecision(t *testing.T) {
	auth := &fakeAuthorizer{
		evaluateDecision: authorizer.DecisionAllow("allowed"),
	}
	r, err := NewREST(auth, legacyscheme.Codecs)
	if err != nil {
		t.Fatalf("unexpected error creating REST: %v", err)
	}

	podJSON, _ := json.Marshal(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "test-pod"},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{"name": "nginx", "image": "nginx:latest"},
			},
		},
	})

	fakeAttrs := &authorizer.AttributesRecord{
		ConditionsMode: authorizer.ConditionsModeOptimized,
	}
	inputDecision, errs := deserializeDecision(fakeAttrs, authorizationapi.SubjectAccessReviewAuthorizationDecision{
		Allowed: true,
	}, nil)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors from deserializeDecision: %v", errs)
	}
	_ = inputDecision

	acr := &authorizationapi.AuthorizationConditionsReview{
		Request: &authorizationapi.AuthorizationConditionsRequest{
			Decision: authorizationapi.SubjectAccessReviewAuthorizationDecision{
				Allowed: true,
			},
			WriteRequest: &authorizationapi.AuthorizationConditionsWriteRequest{
				Operation: admission.Create,
				Object:    runtime.RawExtension{Raw: podJSON},
			},
		},
	}

	result, err := r.Create(context.Background(), acr, rest.ValidateAllObjectFunc, &metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	review, ok := result.(*authorizationapi.AuthorizationConditionsReview)
	if !ok {
		t.Fatalf("expected *AuthorizationConditionsReview, got %T", result)
	}
	if review.Response == nil {
		t.Fatal("expected non-nil response")
	}
	if !review.Response.Allowed {
		t.Error("expected response to be allowed")
	}

	// Verify the authorizer received the decoded Pod as condition data
	if auth.gotData == nil {
		t.Fatal("expected authorizer to receive condition data")
	}
	wr := auth.gotData.WriteRequest()
	if wr == nil {
		t.Fatal("expected non-nil WriteRequest in condition data")
	}
	pod, ok := wr.GetObject().(*api.Pod)
	if !ok {
		t.Fatalf("expected *api.Pod passed to authorizer, got %T", wr.GetObject())
	}
	if pod.Name != "test-pod" {
		t.Errorf("expected pod name %q, got %q", "test-pod", pod.Name)
	}
}

func TestCreate_InvalidRequest(t *testing.T) {
	auth := &fakeAuthorizer{
		evaluateDecision: authorizer.DecisionAllow(),
	}
	r, err := NewREST(auth, legacyscheme.Codecs)
	if err != nil {
		t.Fatalf("unexpected error creating REST: %v", err)
	}

	// nil Request should fail validation
	acr := &authorizationapi.AuthorizationConditionsReview{
		Request: nil,
	}
	_, err = r.Create(context.Background(), acr, rest.ValidateAllObjectFunc, &metav1.CreateOptions{})
	if err == nil {
		t.Fatal("expected error for nil request")
	}
}

func TestCreate_WrongObjectType(t *testing.T) {
	auth := &fakeAuthorizer{
		evaluateDecision: authorizer.DecisionAllow(),
	}
	r, err := NewREST(auth, legacyscheme.Codecs)
	if err != nil {
		t.Fatalf("unexpected error creating REST: %v", err)
	}

	// Pass a non-AuthorizationConditionsReview object
	_, err = r.Create(context.Background(), &api.Pod{}, rest.ValidateAllObjectFunc, &metav1.CreateOptions{})
	if err == nil {
		t.Fatal("expected error for wrong object type")
	}
}

func TestCreate_MutuallyExclusiveDecision(t *testing.T) {
	auth := &fakeAuthorizer{
		evaluateDecision: authorizer.DecisionAllow(),
	}
	r, err := NewREST(auth, legacyscheme.Codecs)
	if err != nil {
		t.Fatalf("unexpected error creating REST: %v", err)
	}

	acr := &authorizationapi.AuthorizationConditionsReview{
		Request: &authorizationapi.AuthorizationConditionsRequest{
			Decision: authorizationapi.SubjectAccessReviewAuthorizationDecision{
				Allowed: true,
				Denied:  true, // mutually exclusive with Allowed
			},
			WriteRequest: &authorizationapi.AuthorizationConditionsWriteRequest{
				Operation: admission.Create,
			},
		},
	}

	_, err = r.Create(context.Background(), acr, rest.ValidateAllObjectFunc, &metav1.CreateOptions{})
	if err == nil {
		t.Fatal("expected error for mutually exclusive Allowed+Denied")
	}
}

func TestSerializeDeserializeRoundTrip(t *testing.T) {
	fakeAttrs := &authorizer.AttributesRecord{
		ConditionsMode: authorizer.ConditionsModeOptimized,
	}

	tests := []struct {
		name     string
		decision authorizationapi.SubjectAccessReviewAuthorizationDecision
		check    func(t *testing.T, d authorizer.Decision)
	}{
		{
			name: "allowed",
			decision: authorizationapi.SubjectAccessReviewAuthorizationDecision{
				Allowed: true,
				Reason:  "ok",
			},
			check: func(t *testing.T, d authorizer.Decision) {
				if !d.IsAllowed() {
					t.Error("expected allowed")
				}
				if d.Reason() != "ok" {
					t.Errorf("expected reason %q, got %q", "ok", d.Reason())
				}
			},
		},
		{
			name: "denied",
			decision: authorizationapi.SubjectAccessReviewAuthorizationDecision{
				Denied: true,
				Reason: "nope",
			},
			check: func(t *testing.T, d authorizer.Decision) {
				if !d.IsDenied() {
					t.Error("expected denied")
				}
				if d.Reason() != "nope" {
					t.Errorf("expected reason %q, got %q", "nope", d.Reason())
				}
			},
		},
		{
			name:     "no opinion",
			decision: authorizationapi.SubjectAccessReviewAuthorizationDecision{},
			check: func(t *testing.T, d authorizer.Decision) {
				if !d.IsNoOpinion() {
					t.Error("expected no opinion")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, errs := deserializeDecision(fakeAttrs, tc.decision, nil)
			if len(errs) > 0 {
				t.Fatalf("unexpected errors: %v", errs)
			}
			tc.check(t, d)

			serialized := serializeDecision(d)
			d2, errs := deserializeDecision(fakeAttrs, serialized, nil)
			if len(errs) > 0 {
				t.Fatalf("unexpected errors on re-deserialize: %v", errs)
			}
			tc.check(t, d2)
		})
	}
}
