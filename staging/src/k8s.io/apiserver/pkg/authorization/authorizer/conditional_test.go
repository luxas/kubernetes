/*
Copyright 2014 The Kubernetes Authors.

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

package authorizer_test

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/union"
	genericfeatures "k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
)

type mockConditionalAuthorizer struct {
	failureMode       authorizer.FailureMode
	resolveConditions func(ctx context.Context, attrs authorizer.ConditionAttributes, conditionSet *authorizer.ConditionSet) (authorizer.Decision, string, error)
	authorize         func(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, []authorizer.Condition, error)
}

func (mock *mockConditionalAuthorizer) FailureMode() authorizer.FailureMode {
	return mock.failureMode
}

func (mock *mockConditionalAuthorizer) ResolveConditions(ctx context.Context, attrs authorizer.ConditionAttributes, conditionSet *authorizer.ConditionSet) (authorizer.Decision, string, error) {
	return mock.resolveConditions(ctx, attrs, conditionSet)
}

func (mock *mockConditionalAuthorizer) Authorize(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
	decision, reason, conditions, err := mock.authorize(ctx, attrs)
	if decision == authorizer.DecisionConditionalAllow {
		conditionSet, err := authorizer.NewConditionSet(conditions...)
		if err != nil {
			panic(err) // invalid test data
		}
		return authorizer.NewConditionalDecision(ctx, mock, conditionSet)
	}
	return decision, reason, err
}

type mockConditionAttributes struct {
	admission.Attributes
	authorizationVerb string
}

func (mock *mockConditionAttributes) GetAuthorizationVerb() string {
	return mock.authorizationVerb
}

func (mock *mockConditionAttributes) GetOperation() string {
	return string(mock.Attributes.GetOperation())
}

func ExampleAuthorizeWithConditionalSupport_customquerylanguage_allowed() {
	utilfeature.DefaultMutableFeatureGate.SetFromMap(map[string]bool{string(genericfeatures.ConditionalAuthorization): true})

	conditionalAuthorizer := &mockConditionalAuthorizer{
		authorize: func(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, []authorizer.Condition, error) {
			if attrs.GetVerb() == "create" && attrs.GetResource() == "pods" && attrs.GetAPIGroup() == "" {
				return authorizer.DecisionConditionalAllow, "", []authorizer.Condition{
					{
						Type:      authorizer.ConditionType("my-query-language"),
						Effect:    authorizer.ConditionEffectAllow,
						Condition: "spec.nodeName == 'test-node'",
					},
				}, nil
			}
			return authorizer.DecisionNoOpinion, "", nil, nil
		},
		resolveConditions: func(ctx context.Context, attrs authorizer.ConditionAttributes, conditionSet *authorizer.ConditionSet) (authorizer.Decision, string, error) {
			obj := attrs.GetObject().(*unstructured.Unstructured)
			objSpec := obj.Object["spec"].(map[string]interface{})
			if len(conditionSet.GetConditions()) == 1 {
				if conditionSet.GetConditions()[0].Type == authorizer.ConditionType("my-query-language") &&
					conditionSet.GetConditions()[0].Condition == "spec.nodeName == 'test-node'" &&
					conditionSet.GetConditions()[0].Effect == authorizer.ConditionEffectAllow &&
					objSpec["nodeName"] == "test-node" {
					return authorizer.DecisionAllow, "pod node name is test-node, which is allowed", nil
				}
			}
			return authorizer.DecisionNoOpinion, "conditions not met", nil
		},
		failureMode: authorizer.FailureModeNoOpinion,
	}
	attrs := &authorizer.AttributesRecord{
		User: &user.DefaultInfo{
			Name: "test",
		},
		Verb:            "create",
		APIGroup:        "",
		APIVersion:      "v1",
		Resource:        "pods",
		Subresource:     "",
		Namespace:       "default",
		Name:            "test-pod",
		ResourceRequest: true,
	}
	ctx := context.Background()
	// Authorization stage, before the body is processed
	decision, reason, conditionsEnforcer, err := authorizer.AuthorizeWithConditionalSupport(ctx, attrs, conditionalAuthorizer)
	if err != nil {
		fmt.Printf("Unexpected error: %v", err)
		return
	}
	fmt.Printf("Authorization decision: %d\n", decision)
	fmt.Printf("Authorization reason: %v\n", reason)
	// Conditional response, ok to proceed with the request and decode the body

	// Decode the body, and populate it into the admissionAttributes
	object := unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name": "test-pod",
		},
		"spec": map[string]interface{}{
			"nodeName": "test-node",
		},
	}}

	admissionAttributes := &mockConditionAttributes{
		Attributes: admission.NewAttributesRecord(
			&object,
			nil,
			schema.GroupVersionKind{
				Group:   "",
				Version: "v1",
				Kind:    "Pod",
			},
			"default",
			"test-pod",
			schema.GroupVersionResource{
				Group:    "",
				Version:  "v1",
				Resource: "pods",
			},
			"",
			admission.Create,
			nil,
			false,
			&user.DefaultInfo{
				Name: "test",
			},
		),
		authorizationVerb: "create",
	}

	decision, reason, err = conditionsEnforcer.EnforceConditions(ctx, admissionAttributes)
	if err != nil {
		fmt.Printf("Unexpected error: %v", err)
		return
	}
	fmt.Printf("Resolved decision with all available data: %d\n", decision)
	fmt.Printf("Resolved reason: %v\n", reason)
	// Output:
	// Authorization decision: 3
	// Authorization reason: conditionally authorized
	// Resolved decision with all available data: 1
	// Resolved reason: pod node name is test-node, which is allowed
}

func ExampleAuthorizeWithConditionalSupport_customquerylanguage_notallowed() {
	utilfeature.DefaultMutableFeatureGate.SetFromMap(map[string]bool{string(genericfeatures.ConditionalAuthorization): true})

	conditionalAuthorizer := &mockConditionalAuthorizer{
		authorize: func(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, []authorizer.Condition, error) {
			if attrs.GetVerb() == "create" && attrs.GetResource() == "pods" && attrs.GetAPIGroup() == "" {
				return authorizer.DecisionConditionalAllow, "", []authorizer.Condition{
					{
						Type:      authorizer.ConditionType("my-query-language"),
						Effect:    authorizer.ConditionEffectAllow,
						Condition: "spec.nodeName == 'test-node'",
					},
				}, nil
			}
			return authorizer.DecisionNoOpinion, "", nil, nil
		},
		resolveConditions: func(ctx context.Context, attrs authorizer.ConditionAttributes, conditionSet *authorizer.ConditionSet) (authorizer.Decision, string, error) {
			obj := attrs.GetObject().(*unstructured.Unstructured)
			objSpec := obj.Object["spec"].(map[string]interface{})
			if len(conditionSet.GetConditions()) == 1 {
				if conditionSet.GetConditions()[0].Type == authorizer.ConditionType("my-query-language") &&
					conditionSet.GetConditions()[0].Condition == "spec.nodeName == 'test-node'" &&
					conditionSet.GetConditions()[0].Effect == authorizer.ConditionEffectAllow &&
					objSpec["nodeName"] == "test-node" {
					return authorizer.DecisionAllow, "pod node name is test-node, which is allowed", nil
				}
			}
			return authorizer.DecisionNoOpinion, "conditions not met", nil
		},
		failureMode: authorizer.FailureModeNoOpinion,
	}
	attrs := &authorizer.AttributesRecord{
		User: &user.DefaultInfo{
			Name: "test",
		},
		Verb:            "create",
		APIGroup:        "",
		APIVersion:      "v1",
		Resource:        "pods",
		Subresource:     "",
		Namespace:       "default",
		Name:            "test-pod",
		ResourceRequest: true,
	}
	ctx := context.Background()
	// Authorization stage, before the body is processed
	decision, reason, conditionsEnforcer, err := authorizer.AuthorizeWithConditionalSupport(ctx, attrs, conditionalAuthorizer)
	if err != nil {
		fmt.Printf("Unexpected error: %v", err)
		return
	}
	fmt.Printf("Authorization decision: %d\n", decision)
	fmt.Printf("Authorization reason: %v\n", reason)
	// Conditional response, ok to proceed with the request and decode the body

	// Decode the body, and populate it into the admissionAttributes
	object := unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name": "test-pod",
		},
		"spec": map[string]interface{}{
			"nodeName": "unauthorized-node",
		},
	}}

	admissionAttributes := &mockConditionAttributes{
		Attributes: admission.NewAttributesRecord(
			&object,
			nil,
			schema.GroupVersionKind{
				Group:   "",
				Version: "v1",
				Kind:    "Pod",
			},
			"default",
			"test-pod",
			schema.GroupVersionResource{
				Group:    "",
				Version:  "v1",
				Resource: "pods",
			},
			"",
			admission.Create,
			nil,
			false,
			&user.DefaultInfo{
				Name: "test",
			},
		),
		authorizationVerb: "create",
	}

	decision, reason, err = conditionsEnforcer.EnforceConditions(ctx, admissionAttributes)
	if err != nil {
		fmt.Printf("Unexpected error: %v", err)
		return
	}
	fmt.Printf("Resolved decision with all available data: %d\n", decision)
	fmt.Printf("Resolved reason: %v\n", reason)
	// Output:
	// Authorization decision: 3
	// Authorization reason: conditionally authorized
	// Resolved decision with all available data: 2
	// Resolved reason: conditions not met
}

func ExampleAuthorizeWithConditionalSupport_customquerylanguage_authorizerchain() {
	utilfeature.DefaultMutableFeatureGate.SetFromMap(map[string]bool{string(genericfeatures.ConditionalAuthorization): true})

	conditionalAuthorizer := &mockConditionalAuthorizer{
		authorize: func(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, []authorizer.Condition, error) {
			if attrs.GetVerb() == "create" && attrs.GetResource() == "pods" && attrs.GetAPIGroup() == "" {
				return authorizer.DecisionConditionalAllow, "", []authorizer.Condition{
					{
						Type:      authorizer.ConditionType("my-query-language"),
						Effect:    authorizer.ConditionEffectAllow,
						Condition: "spec.nodeName == 'test-node'",
					},
				}, nil
			}
			return authorizer.DecisionNoOpinion, "", nil, nil
		},
		resolveConditions: func(ctx context.Context, attrs authorizer.ConditionAttributes, conditionSet *authorizer.ConditionSet) (authorizer.Decision, string, error) {
			obj := attrs.GetObject().(*unstructured.Unstructured)
			objSpec := obj.Object["spec"].(map[string]interface{})
			if len(conditionSet.GetConditions()) == 1 {
				if conditionSet.GetConditions()[0].Type == authorizer.ConditionType("my-query-language") &&
					conditionSet.GetConditions()[0].Condition == "spec.nodeName == 'test-node'" &&
					conditionSet.GetConditions()[0].Effect == authorizer.ConditionEffectAllow &&
					objSpec["nodeName"] == "test-node" {
					return authorizer.DecisionAllow, "pod node name is test-node, which is allowed", nil
				}
			}
			return authorizer.DecisionNoOpinion, "conditions not met", nil
		},
		failureMode: authorizer.FailureModeNoOpinion,
	}
	attrs := &authorizer.AttributesRecord{
		User: &user.DefaultInfo{
			Name: "test",
		},
		Verb:            "create",
		APIGroup:        "",
		APIVersion:      "v1",
		Resource:        "pods",
		Subresource:     "",
		Namespace:       "default",
		Name:            "test-pod",
		ResourceRequest: true,
	}
	ctx := context.Background()
	// Authorization stage, before the body is processed
	alwaysAllowCreatePodsAuthorizer := authorizer.AuthorizerFunc(func(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
		if attrs.GetVerb() == "create" && attrs.GetResource() == "pods" && attrs.GetAPIGroup() == "" {
			return authorizer.DecisionAllow, "always allow create pods", nil
		}
		return authorizer.DecisionNoOpinion, "", nil
	})
	authorizerChain := union.New(conditionalAuthorizer, alwaysAllowCreatePodsAuthorizer)
	decision, reason, conditionsEnforcer, err := authorizer.AuthorizeWithConditionalSupport(ctx, attrs, authorizerChain)
	if err != nil {
		fmt.Printf("Unexpected error: %v", err)
		return
	}
	fmt.Printf("Authorization decision: %d\n", decision)
	fmt.Printf("Authorization reason: %v\n", reason)
	// Conditional response, ok to proceed with the request and decode the body

	// Decode the body, and populate it into the admissionAttributes
	object := unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name": "test-pod",
		},
		"spec": map[string]interface{}{
			// This means that the conditional authorizer will evaluate the conditions
			// to NoOpinion, but the alwaysAllowCreatePodsAuthorizer will allow the request.
			"nodeName": "unauthorized-node",
		},
	}}

	admissionAttributes := &mockConditionAttributes{
		Attributes: admission.NewAttributesRecord(
			&object,
			nil,
			schema.GroupVersionKind{
				Group:   "",
				Version: "v1",
				Kind:    "Pod",
			},
			"default",
			"test-pod",
			schema.GroupVersionResource{
				Group:    "",
				Version:  "v1",
				Resource: "pods",
			},
			"",
			admission.Create,
			nil,
			false,
			&user.DefaultInfo{
				Name: "test",
			},
		),
		authorizationVerb: "create",
	}

	decision, reason, err = conditionsEnforcer.EnforceConditions(ctx, admissionAttributes)
	if err != nil {
		fmt.Printf("Unexpected error: %v", err)
		return
	}
	fmt.Printf("Resolved decision with all available data: %d\n", decision)
	fmt.Printf("Resolved reason: %v\n", reason)
	// Output:
	// Authorization decision: 3
	// Authorization reason: conditionally authorized
	// Resolved decision with all available data: 1
	// Resolved reason: always allow create pods
}
