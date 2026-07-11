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

package validation

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	authorizationapi "k8s.io/kubernetes/pkg/apis/authorization"
)

func TestValidateSARSpec(t *testing.T) {
	successCases := []authorizationapi.SubjectAccessReviewSpec{
		{ResourceAttributes: &authorizationapi.ResourceAttributes{}, User: "me"},
		{NonResourceAttributes: &authorizationapi.NonResourceAttributes{}, Groups: []string{"my-group"}},
		{ // field raw selector
			User: "me",
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				FieldSelector: &authorizationapi.FieldSelectorAttributes{
					RawSelector: "***foo",
				},
			},
		},
		{ // label raw selector
			User: "me",
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				LabelSelector: &authorizationapi.LabelSelectorAttributes{
					RawSelector: "***foo",
				},
			},
		},
		{ // unknown field operator
			User: "me",
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				FieldSelector: &authorizationapi.FieldSelectorAttributes{
					Requirements: []metav1.FieldSelectorRequirement{
						{
							Key:      "k",
							Operator: metav1.FieldSelectorOperator("fake"),
							Values:   []string{"val"},
						},
					},
				},
			},
		},
		{ // unknown label operator
			User: "me",
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				LabelSelector: &authorizationapi.LabelSelectorAttributes{
					Requirements: []metav1.LabelSelectorRequirement{
						{
							Key:      "k",
							Operator: metav1.LabelSelectorOperator("fake"),
							Values:   []string{"val"},
						},
					},
				},
			},
		},
	}
	for _, successCase := range successCases {
		if errs := ValidateSubjectAccessReviewSpec(successCase, field.NewPath("spec")); len(errs) != 0 {
			t.Errorf("expected success: %v", errs)
		}
	}

	errorCases := []struct {
		name string
		obj  authorizationapi.SubjectAccessReviewSpec
		msg  string
	}{{
		name: "neither request",
		obj:  authorizationapi.SubjectAccessReviewSpec{User: "me"},
		msg:  "exactly one of nonResourceAttributes or resourceAttributes must be specified",
	}, {
		name: "both requests",
		obj: authorizationapi.SubjectAccessReviewSpec{
			ResourceAttributes:    &authorizationapi.ResourceAttributes{},
			NonResourceAttributes: &authorizationapi.NonResourceAttributes{},
			User:                  "me",
		},
		msg: "exactly one of nonResourceAttributes or resourceAttributes must be specified",
	}, {
		name: "no subject",
		obj: authorizationapi.SubjectAccessReviewSpec{
			ResourceAttributes: &authorizationapi.ResourceAttributes{},
		},
		msg: `spec.user: Invalid value: "": at least one of user or group must be specified`,
	}, {
		name: "resource attributes: field selector specify both",
		obj: authorizationapi.SubjectAccessReviewSpec{
			User: "me",
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				FieldSelector: &authorizationapi.FieldSelectorAttributes{
					RawSelector: "foo",
					Requirements: []metav1.FieldSelectorRequirement{
						{},
					},
				},
			},
		},
		msg: `spec.resourceAttributes.fieldSelector.rawSelector: Invalid value: "foo": may not specified at the same time as requirements`,
	}, {
		name: "resource attributes: field selector specify neither",
		obj: authorizationapi.SubjectAccessReviewSpec{
			User: "me",
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				FieldSelector: &authorizationapi.FieldSelectorAttributes{},
			},
		},
		msg: `spec.resourceAttributes.fieldSelector.requirements: Required value: when spec.resourceAttributes.fieldSelector is specified, requirements or rawSelector is required`,
	}, {
		name: "resource attributes: field selector no key",
		obj: authorizationapi.SubjectAccessReviewSpec{
			User: "me",
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				FieldSelector: &authorizationapi.FieldSelectorAttributes{
					Requirements: []metav1.FieldSelectorRequirement{
						{
							Key: "",
						},
					},
				},
			},
		},
		msg: `spec.resourceAttributes.fieldSelector.requirements[0].key: Required value: must be specified`,
	}, {
		name: "resource attributes: field selector no value for in",
		obj: authorizationapi.SubjectAccessReviewSpec{
			User: "me",
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				FieldSelector: &authorizationapi.FieldSelectorAttributes{
					Requirements: []metav1.FieldSelectorRequirement{
						{
							Key:      "k",
							Operator: metav1.FieldSelectorOpIn,
							Values:   []string{},
						},
					},
				},
			},
		},
		msg: "spec.resourceAttributes.fieldSelector.requirements[0].values: Required value: must be specified when `operator` is 'In' or 'NotIn'",
	}, {
		name: "resource attributes: field selector no value for not in",
		obj: authorizationapi.SubjectAccessReviewSpec{
			User: "me",
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				FieldSelector: &authorizationapi.FieldSelectorAttributes{
					Requirements: []metav1.FieldSelectorRequirement{
						{
							Key:      "k",
							Operator: metav1.FieldSelectorOpNotIn,
							Values:   []string{},
						},
					},
				},
			},
		},
		msg: "spec.resourceAttributes.fieldSelector.requirements[0].values: Required value: must be specified when `operator` is 'In' or 'NotIn'",
	}, {
		name: "resource attributes: field selector values for exists",
		obj: authorizationapi.SubjectAccessReviewSpec{
			User: "me",
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				FieldSelector: &authorizationapi.FieldSelectorAttributes{
					Requirements: []metav1.FieldSelectorRequirement{
						{
							Key:      "k",
							Operator: metav1.FieldSelectorOpExists,
							Values:   []string{"val"},
						},
					},
				},
			},
		},
		msg: "spec.resourceAttributes.fieldSelector.requirements[0].values: Forbidden: may not be specified when `operator` is 'Exists' or 'DoesNotExist'",
	}, {
		name: "resource attributes: field selector values for not exists",
		obj: authorizationapi.SubjectAccessReviewSpec{
			User: "me",
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				FieldSelector: &authorizationapi.FieldSelectorAttributes{
					Requirements: []metav1.FieldSelectorRequirement{
						{
							Key:      "k",
							Operator: metav1.FieldSelectorOpDoesNotExist,
							Values:   []string{"val"},
						},
					},
				},
			},
		},
		msg: "spec.resourceAttributes.fieldSelector.requirements[0].values: Forbidden: may not be specified when `operator` is 'Exists' or 'DoesNotExist'",
	}, {
		name: "resource attributes: label selector specify both",
		obj: authorizationapi.SubjectAccessReviewSpec{
			User: "me",
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				LabelSelector: &authorizationapi.LabelSelectorAttributes{
					RawSelector: "foo",
					Requirements: []metav1.LabelSelectorRequirement{
						{},
					},
				},
			},
		},
		msg: `spec.resourceAttributes.labelSelector.rawSelector: Invalid value: "foo": may not specified at the same time as requirements`,
	}, {
		name: "resource attributes: label selector specify neither",
		obj: authorizationapi.SubjectAccessReviewSpec{
			User: "me",
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				LabelSelector: &authorizationapi.LabelSelectorAttributes{},
			},
		},
		msg: `spec.resourceAttributes.labelSelector.requirements: Required value: when spec.resourceAttributes.labelSelector is specified, requirements or rawSelector is required`,
	}, {
		name: "resource attributes: label selector no key",
		obj: authorizationapi.SubjectAccessReviewSpec{
			User: "me",
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				LabelSelector: &authorizationapi.LabelSelectorAttributes{
					Requirements: []metav1.LabelSelectorRequirement{
						{
							Key: "",
						},
					},
				},
			},
		},
		msg: `spec.resourceAttributes.labelSelector.requirements[0].key: Invalid value: "": name part must be non-empty`,
	}, {
		name: "resource attributes: label selector invalid label name",
		obj: authorizationapi.SubjectAccessReviewSpec{
			User: "me",
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				LabelSelector: &authorizationapi.LabelSelectorAttributes{
					Requirements: []metav1.LabelSelectorRequirement{
						{
							Key: "()foo",
						},
					},
				},
			},
		},
		msg: `spec.resourceAttributes.labelSelector.requirements[0].key: Invalid value: "()foo": name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')`,
	}, {
		name: "resource attributes: label selector no value for in",
		obj: authorizationapi.SubjectAccessReviewSpec{
			User: "me",
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				LabelSelector: &authorizationapi.LabelSelectorAttributes{
					Requirements: []metav1.LabelSelectorRequirement{
						{
							Key:      "k",
							Operator: metav1.LabelSelectorOpIn,
							Values:   []string{},
						},
					},
				},
			},
		},
		msg: "spec.resourceAttributes.labelSelector.requirements[0].values: Required value: must be specified when `operator` is 'In' or 'NotIn'",
	}, {
		name: "resource attributes: label selector no value for not in",
		obj: authorizationapi.SubjectAccessReviewSpec{
			User: "me",
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				LabelSelector: &authorizationapi.LabelSelectorAttributes{
					Requirements: []metav1.LabelSelectorRequirement{
						{
							Key:      "k",
							Operator: metav1.LabelSelectorOpNotIn,
							Values:   []string{},
						},
					},
				},
			},
		},
		msg: "spec.resourceAttributes.labelSelector.requirements[0].values: Required value: must be specified when `operator` is 'In' or 'NotIn'",
	}, {
		name: "resource attributes: label selector values for exists",
		obj: authorizationapi.SubjectAccessReviewSpec{
			User: "me",
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				LabelSelector: &authorizationapi.LabelSelectorAttributes{
					Requirements: []metav1.LabelSelectorRequirement{
						{
							Key:      "k",
							Operator: metav1.LabelSelectorOpExists,
							Values:   []string{"val"},
						},
					},
				},
			},
		},
		msg: "spec.resourceAttributes.labelSelector.requirements[0].values: Forbidden: may not be specified when `operator` is 'Exists' or 'DoesNotExist'",
	}, {
		name: "resource attributes: label selector values for not exists",
		obj: authorizationapi.SubjectAccessReviewSpec{
			User: "me",
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				LabelSelector: &authorizationapi.LabelSelectorAttributes{
					Requirements: []metav1.LabelSelectorRequirement{
						{
							Key:      "k",
							Operator: metav1.LabelSelectorOpDoesNotExist,
							Values:   []string{"val"},
						},
					},
				},
			},
		},
		msg: "spec.resourceAttributes.labelSelector.requirements[0].values: Forbidden: may not be specified when `operator` is 'Exists' or 'DoesNotExist'",
	}}

	for _, c := range errorCases {
		t.Run(c.name, func(t *testing.T) {
			errs := ValidateSubjectAccessReviewSpec(c.obj, field.NewPath("spec"))
			if len(errs) == 0 {
				t.Errorf("%s: expected failure for %q", c.name, c.msg)
			} else if !strings.Contains(errs[0].Error(), c.msg) {
				t.Errorf("%s: unexpected error: %q, expected: %q", c.name, errs[0], c.msg)
			}

			errs = ValidateSubjectAccessReview(&authorizationapi.SubjectAccessReview{Spec: c.obj})
			if len(errs) == 0 {
				t.Errorf("%s: expected failure for %q", c.name, c.msg)
			} else if !strings.Contains(errs[0].Error(), c.msg) {
				t.Errorf("%s: unexpected error: %q, expected: %q", c.name, errs[0], c.msg)
			}
			errs = ValidateLocalSubjectAccessReview(&authorizationapi.LocalSubjectAccessReview{Spec: c.obj})
			if len(errs) == 0 {
				t.Errorf("%s: expected failure for %q", c.name, c.msg)
			} else if !strings.Contains(errs[0].Error(), c.msg) {
				t.Errorf("%s: unexpected error: %q, expected: %q", c.name, errs[0], c.msg)
			}
		})
	}
}

func TestValidateSelfSAR(t *testing.T) {
	successCases := []authorizationapi.SelfSubjectAccessReviewSpec{
		{ResourceAttributes: &authorizationapi.ResourceAttributes{}},
	}
	for _, successCase := range successCases {
		if errs := ValidateSelfSubjectAccessReviewSpec(successCase, field.NewPath("spec")); len(errs) != 0 {
			t.Errorf("expected success: %v", errs)
		}
	}

	errorCases := []struct {
		name string
		obj  authorizationapi.SelfSubjectAccessReviewSpec
		msg  string
	}{{
		name: "neither request",
		obj:  authorizationapi.SelfSubjectAccessReviewSpec{},
		msg:  "exactly one of nonResourceAttributes or resourceAttributes must be specified",
	}, {
		name: "both requests",
		obj: authorizationapi.SelfSubjectAccessReviewSpec{
			ResourceAttributes:    &authorizationapi.ResourceAttributes{},
			NonResourceAttributes: &authorizationapi.NonResourceAttributes{},
		},
		msg: "exactly one of nonResourceAttributes or resourceAttributes must be specified",
	}, {
		// here we only test one to be sure the function is called.  The more exhaustive suite is tested above.
		name: "resource attributes: label selector specify both",
		obj: authorizationapi.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationapi.ResourceAttributes{
				LabelSelector: &authorizationapi.LabelSelectorAttributes{
					RawSelector: "foo",
					Requirements: []metav1.LabelSelectorRequirement{
						{},
					},
				},
			},
		},
		msg: `spec.resourceAttributes.labelSelector.rawSelector: Invalid value: "foo": may not specified at the same time as requirements`,
	}}

	for _, c := range errorCases {
		errs := ValidateSelfSubjectAccessReviewSpec(c.obj, field.NewPath("spec"))
		if len(errs) == 0 {
			t.Errorf("%s: expected failure for %q", c.name, c.msg)
		} else if !strings.Contains(errs[0].Error(), c.msg) {
			t.Errorf("%s: unexpected error: %q, expected: %q", c.name, errs[0], c.msg)
		}

		errs = ValidateSelfSubjectAccessReview(&authorizationapi.SelfSubjectAccessReview{Spec: c.obj})
		if len(errs) == 0 {
			t.Errorf("%s: expected failure for %q", c.name, c.msg)
		} else if !strings.Contains(errs[0].Error(), c.msg) {
			t.Errorf("%s: unexpected error: %q, expected: %q", c.name, errs[0], c.msg)
		}
	}
}

func TestValidateLocalSAR(t *testing.T) {
	successCases := []authorizationapi.LocalSubjectAccessReview{{
		Spec: authorizationapi.SubjectAccessReviewSpec{
			ResourceAttributes: &authorizationapi.ResourceAttributes{},
			User:               "user",
		},
	}}
	for _, successCase := range successCases {
		if errs := ValidateLocalSubjectAccessReview(&successCase); len(errs) != 0 {
			t.Errorf("expected success: %v", errs)
		}
	}

	errorCases := []struct {
		name string
		obj  *authorizationapi.LocalSubjectAccessReview
		msg  string
	}{{
		name: "name",
		obj: &authorizationapi.LocalSubjectAccessReview{
			ObjectMeta: metav1.ObjectMeta{Name: "a"},
			Spec: authorizationapi.SubjectAccessReviewSpec{
				ResourceAttributes: &authorizationapi.ResourceAttributes{},
				User:               "user",
			},
		},
		msg: "must be empty except for namespace",
	}, {
		name: "namespace conflict",
		obj: &authorizationapi.LocalSubjectAccessReview{
			ObjectMeta: metav1.ObjectMeta{Namespace: "a"},
			Spec: authorizationapi.SubjectAccessReviewSpec{
				ResourceAttributes: &authorizationapi.ResourceAttributes{},
				User:               "user",
			},
		},
		msg: "must match metadata.namespace",
	}, {
		name: "nonresource",
		obj: &authorizationapi.LocalSubjectAccessReview{
			ObjectMeta: metav1.ObjectMeta{Namespace: "a"},
			Spec: authorizationapi.SubjectAccessReviewSpec{
				NonResourceAttributes: &authorizationapi.NonResourceAttributes{},
				User:                  "user",
			},
		},
		msg: "disallowed on this kind of request",
	}, {
		// here we only test one to be sure the function is called.  The more exhaustive suite is tested above.
		name: "resource attributes: label selector specify both",
		obj: &authorizationapi.LocalSubjectAccessReview{
			Spec: authorizationapi.SubjectAccessReviewSpec{
				User: "user",
				ResourceAttributes: &authorizationapi.ResourceAttributes{
					LabelSelector: &authorizationapi.LabelSelectorAttributes{
						RawSelector: "foo",
						Requirements: []metav1.LabelSelectorRequirement{
							{},
						},
					},
				},
			},
		},
		msg: `spec.resourceAttributes.labelSelector.rawSelector: Invalid value: "foo": may not specified at the same time as requirements`,
	}}

	for _, c := range errorCases {
		errs := ValidateLocalSubjectAccessReview(c.obj)
		if len(errs) == 0 {
			t.Errorf("%s: expected failure for %q", c.name, c.msg)
		} else if !strings.Contains(errs[0].Error(), c.msg) {
			t.Errorf("%s: unexpected error: %q, expected: %q", c.name, errs[0], c.msg)
		}
	}
}

// TestValidateAuthorizationConditionsReview exercises the parts of
// ValidateAuthorizationConditionsReview that are handwritten (i.e. not covered
// by declarative validation): the ObjectMeta emptiness check, the
// domain-prefix separator check on every Condition.ID / Condition.Type across
// the request and response ConditionsMaps, and the MaxBytes checks on
// Condition.Condition and Condition.Description. Errors already covered by
// declarative validation (empty ID, invalid label-key format) are intentionally
// not fired by the handwritten path and are therefore not asserted here.
func TestValidateAuthorizationConditionsReview(t *testing.T) {
	emptyDecision := authorizationapi.ConditionsAwareDecision{}
	validConditionsMap := &authorizationapi.ConditionsMap{
		DenyConditions:      []authorizationapi.Condition{{ID: "example.com/deny-1", Type: "example.com/type-1"}},
		NoOpinionConditions: []authorizationapi.Condition{{ID: "example.com/no-op-1"}},
		AllowConditions:     []authorizationapi.Condition{{ID: "example.com/allow-1", Type: "example.io/allow-type"}},
	}

	successCases := []struct {
		name string
		obj  authorizationapi.AuthorizationConditionsReview
	}{{
		name: "empty request and response decisions",
		obj: authorizationapi.AuthorizationConditionsReview{
			Request:  &authorizationapi.AuthorizationConditionsRequest{Decision: emptyDecision},
			Response: &authorizationapi.AuthorizationConditionsResponse{Decision: emptyDecision},
		},
	}, {
		name: "conditions with valid domain-prefixed keys in all buckets",
		obj: authorizationapi.AuthorizationConditionsReview{
			Request: &authorizationapi.AuthorizationConditionsRequest{
				Decision: authorizationapi.ConditionsAwareDecision{ConditionsMap: validConditionsMap},
			},
			Response: &authorizationapi.AuthorizationConditionsResponse{
				Decision: authorizationapi.ConditionsAwareDecision{ConditionsMap: validConditionsMap},
			},
		},
	}, {
		name: "condition type unset is allowed",
		obj: authorizationapi.AuthorizationConditionsReview{
			Request: &authorizationapi.AuthorizationConditionsRequest{
				Decision: authorizationapi.ConditionsAwareDecision{
					ConditionsMap: &authorizationapi.ConditionsMap{
						AllowConditions: []authorizationapi.Condition{{ID: "example.com/allow"}},
					},
				},
			},
			Response: &authorizationapi.AuthorizationConditionsResponse{Decision: emptyDecision},
		},
	}, {
		name: "only ManagedFields on ObjectMeta is allowed",
		obj: authorizationapi.AuthorizationConditionsReview{
			ObjectMeta: metav1.ObjectMeta{
				ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "test"}},
			},
			Request:  &authorizationapi.AuthorizationConditionsRequest{Decision: emptyDecision},
			Response: &authorizationapi.AuthorizationConditionsResponse{Decision: emptyDecision},
		},
	}, {
		name: "empty id is skipped by handwritten path (declarative covers it)",
		obj: authorizationapi.AuthorizationConditionsReview{
			Request: &authorizationapi.AuthorizationConditionsRequest{
				Decision: authorizationapi.ConditionsAwareDecision{
					ConditionsMap: &authorizationapi.ConditionsMap{
						DenyConditions: []authorizationapi.Condition{{ID: ""}},
					},
				},
			},
			Response: &authorizationapi.AuthorizationConditionsResponse{Decision: emptyDecision},
		},
	}, {
		name: "invalid label-key format is skipped by handwritten path (declarative covers it)",
		obj: authorizationapi.AuthorizationConditionsReview{
			Request: &authorizationapi.AuthorizationConditionsRequest{
				Decision: authorizationapi.ConditionsAwareDecision{
					ConditionsMap: &authorizationapi.ConditionsMap{
						AllowConditions: []authorizationapi.Condition{
							{ID: "example.com/foo/bar"},
							{ID: "example.com/_bad", Type: "example.com/e?"},
						},
					},
				},
			},
			Response: &authorizationapi.AuthorizationConditionsResponse{Decision: emptyDecision},
		},
	}, {
		name: "condition and description exactly at MaxBytes are allowed",
		obj: authorizationapi.AuthorizationConditionsReview{
			Request: &authorizationapi.AuthorizationConditionsRequest{
				Decision: authorizationapi.ConditionsAwareDecision{
					ConditionsMap: &authorizationapi.ConditionsMap{
						AllowConditions: []authorizationapi.Condition{{
							ID:          "example.com/foo",
							Condition:   strings.Repeat("a", authorizer.MaxConditionBytes),
							Description: strings.Repeat("b", authorizer.MaxConditionDescriptionBytes),
						}},
					},
				},
			},
			Response: &authorizationapi.AuthorizationConditionsResponse{Decision: emptyDecision},
		},
	}}

	for _, c := range successCases {
		t.Run("success/"+c.name, func(t *testing.T) {
			if errs := ValidateAuthorizationConditionsReview(&c.obj); len(errs) != 0 {
				t.Errorf("expected success, got: %v", errs)
			}
		})
	}

	errorCases := []struct {
		name string
		obj  authorizationapi.AuthorizationConditionsReview
		msgs []string
	}{{
		name: "non-empty name in ObjectMeta",
		obj: authorizationapi.AuthorizationConditionsReview{
			ObjectMeta: metav1.ObjectMeta{Name: "a-name"},
			Request:    &authorizationapi.AuthorizationConditionsRequest{Decision: emptyDecision},
			Response:   &authorizationapi.AuthorizationConditionsResponse{Decision: emptyDecision},
		},
		msgs: []string{`metadata: Invalid value:`, `must be empty`},
	}, {
		name: "non-empty namespace in ObjectMeta",
		obj: authorizationapi.AuthorizationConditionsReview{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns"},
			Request:    &authorizationapi.AuthorizationConditionsRequest{Decision: emptyDecision},
			Response:   &authorizationapi.AuthorizationConditionsResponse{Decision: emptyDecision},
		},
		msgs: []string{`metadata: Invalid value:`, `must be empty`},
	}, {
		name: "non-empty labels in ObjectMeta",
		obj: authorizationapi.AuthorizationConditionsReview{
			ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"k": "v"}},
			Request:    &authorizationapi.AuthorizationConditionsRequest{Decision: emptyDecision},
			Response:   &authorizationapi.AuthorizationConditionsResponse{Decision: emptyDecision},
		},
		msgs: []string{`metadata: Invalid value:`, `must be empty`},
	}, {
		name: "request allowConditions: id missing domain prefix",
		obj: authorizationapi.AuthorizationConditionsReview{
			Request: &authorizationapi.AuthorizationConditionsRequest{
				Decision: authorizationapi.ConditionsAwareDecision{
					ConditionsMap: &authorizationapi.ConditionsMap{
						AllowConditions: []authorizationapi.Condition{{ID: "no-slash"}},
					},
				},
			},
			Response: &authorizationapi.AuthorizationConditionsResponse{Decision: emptyDecision},
		},
		msgs: []string{`request.decision.conditionsMap.allowConditions[0].id: Invalid value: "no-slash": must be a domain-prefixed key`},
	}, {
		name: "request noOpinionConditions: type missing domain prefix",
		obj: authorizationapi.AuthorizationConditionsReview{
			Request: &authorizationapi.AuthorizationConditionsRequest{
				Decision: authorizationapi.ConditionsAwareDecision{
					ConditionsMap: &authorizationapi.ConditionsMap{
						NoOpinionConditions: []authorizationapi.Condition{{ID: "example.com/id", Type: "no-slash"}},
					},
				},
			},
			Response: &authorizationapi.AuthorizationConditionsResponse{Decision: emptyDecision},
		},
		msgs: []string{`request.decision.conditionsMap.noOpinionConditions[0].type: Invalid value: "no-slash": must be a domain-prefixed key`},
	}, {
		name: "response denyConditions: id at index reflects its position",
		obj: authorizationapi.AuthorizationConditionsReview{
			Request: &authorizationapi.AuthorizationConditionsRequest{Decision: emptyDecision},
			Response: &authorizationapi.AuthorizationConditionsResponse{
				Decision: authorizationapi.ConditionsAwareDecision{
					ConditionsMap: &authorizationapi.ConditionsMap{
						DenyConditions: []authorizationapi.Condition{
							{ID: "example.com/ok"},
							{ID: "bad"},
						},
					},
				},
			},
		},
		msgs: []string{`response.decision.conditionsMap.denyConditions[1].id: Invalid value: "bad": must be a domain-prefixed key`},
	}, {
		name: "condition body over MaxConditionBytes",
		obj: authorizationapi.AuthorizationConditionsReview{
			Request: &authorizationapi.AuthorizationConditionsRequest{
				Decision: authorizationapi.ConditionsAwareDecision{
					ConditionsMap: &authorizationapi.ConditionsMap{
						AllowConditions: []authorizationapi.Condition{{
							ID:        "example.com/foo",
							Condition: strings.Repeat("a", authorizer.MaxConditionBytes+1),
						}},
					},
				},
			},
			Response: &authorizationapi.AuthorizationConditionsResponse{Decision: emptyDecision},
		},
		msgs: []string{`request.decision.conditionsMap.allowConditions[0].condition: Too long`},
	}, {
		name: "description over MaxConditionDescriptionBytes",
		obj: authorizationapi.AuthorizationConditionsReview{
			Request: &authorizationapi.AuthorizationConditionsRequest{Decision: emptyDecision},
			Response: &authorizationapi.AuthorizationConditionsResponse{
				Decision: authorizationapi.ConditionsAwareDecision{
					ConditionsMap: &authorizationapi.ConditionsMap{
						DenyConditions: []authorizationapi.Condition{{
							ID:          "example.com/foo",
							Description: strings.Repeat("b", authorizer.MaxConditionDescriptionBytes+1),
						}},
					},
				},
			},
		},
		msgs: []string{`response.decision.conditionsMap.denyConditions[0].description: Too long`},
	}, {
		name: "traversal covers all three buckets in both request and response",
		obj: authorizationapi.AuthorizationConditionsReview{
			Request: &authorizationapi.AuthorizationConditionsRequest{
				Decision: authorizationapi.ConditionsAwareDecision{
					ConditionsMap: &authorizationapi.ConditionsMap{
						DenyConditions:      []authorizationapi.Condition{{ID: "bad-deny"}},
						NoOpinionConditions: []authorizationapi.Condition{{ID: "bad-noop"}},
						AllowConditions:     []authorizationapi.Condition{{ID: "bad-allow"}},
					},
				},
			},
			Response: &authorizationapi.AuthorizationConditionsResponse{
				Decision: authorizationapi.ConditionsAwareDecision{
					ConditionsMap: &authorizationapi.ConditionsMap{
						DenyConditions:      []authorizationapi.Condition{{ID: "bad-deny"}},
						NoOpinionConditions: []authorizationapi.Condition{{ID: "bad-noop"}},
						AllowConditions:     []authorizationapi.Condition{{ID: "bad-allow"}},
					},
				},
			},
		},
		msgs: []string{
			`request.decision.conditionsMap.denyConditions[0].id`,
			`request.decision.conditionsMap.noOpinionConditions[0].id`,
			`request.decision.conditionsMap.allowConditions[0].id`,
			`response.decision.conditionsMap.denyConditions[0].id`,
			`response.decision.conditionsMap.noOpinionConditions[0].id`,
			`response.decision.conditionsMap.allowConditions[0].id`,
		},
	}, {
		name: "nil ConditionsMap in decision is skipped by handwritten validation",
		obj: authorizationapi.AuthorizationConditionsReview{
			ObjectMeta: metav1.ObjectMeta{Name: "not-empty"},
			Request:    &authorizationapi.AuthorizationConditionsRequest{Decision: emptyDecision},
			Response:   &authorizationapi.AuthorizationConditionsResponse{Decision: emptyDecision},
		},
		msgs: []string{`metadata: Invalid value:`},
	}}

	for _, c := range errorCases {
		t.Run(c.name, func(t *testing.T) {
			errs := ValidateAuthorizationConditionsReview(&c.obj)
			if len(errs) == 0 {
				t.Fatalf("expected failure containing %q", c.msgs)
			}
			joined := errs.ToAggregate().Error()
			for _, msg := range c.msgs {
				if !strings.Contains(joined, msg) {
					t.Errorf("expected error containing %q, got: %s", msg, joined)
				}
			}
		})
	}
}

// TestValidateCondition exercises the handwritten checks in ValidateCondition
// in isolation: the domain-prefix separator on ID and Type (fires only when
// the key is otherwise a valid label key), and MaxBytes on Condition and
// Description. Empty IDs and invalid label-key formats are covered by
// declarative validation and are not asserted here.
func TestValidateCondition(t *testing.T) {
	testCases := []struct {
		name    string
		cond    authorizationapi.Condition
		wantErr bool
		msg     string
	}{{
		name: "valid id only",
		cond: authorizationapi.Condition{ID: "example.com/foo"},
	}, {
		name: "valid id and type",
		cond: authorizationapi.Condition{ID: "example.com/foo", Type: "example.io/bar"},
	}, {
		name: "empty id is skipped (declarative covers required)",
		cond: authorizationapi.Condition{ID: ""},
	}, {
		name: "id with too many slashes is skipped (declarative covers label-key format)",
		cond: authorizationapi.Condition{ID: "example.com/foo/bar"},
	}, {
		name: "id with malformed name part is skipped (declarative covers label-key format)",
		cond: authorizationapi.Condition{ID: "example.com/_bad"},
	}, {
		name: "type empty is skipped",
		cond: authorizationapi.Condition{ID: "example.com/foo", Type: ""},
	}, {
		name:    "id missing domain prefix",
		cond:    authorizationapi.Condition{ID: "no-slash"},
		wantErr: true,
		msg:     `id: Invalid value: "no-slash": must be a domain-prefixed key`,
	}, {
		name:    "type set but not domain-prefixed",
		cond:    authorizationapi.Condition{ID: "example.com/foo", Type: "bad"},
		wantErr: true,
		msg:     `type: Invalid value: "bad": must be a domain-prefixed key`,
	}, {
		name: "condition body at MaxBytes is allowed",
		cond: authorizationapi.Condition{
			ID:        "example.com/foo",
			Condition: strings.Repeat("a", authorizer.MaxConditionBytes),
		},
	}, {
		name: "description at MaxBytes is allowed",
		cond: authorizationapi.Condition{
			ID:          "example.com/foo",
			Description: strings.Repeat("b", authorizer.MaxConditionDescriptionBytes),
		},
	}, {
		name: "condition body just over MaxBytes",
		cond: authorizationapi.Condition{
			ID:        "example.com/foo",
			Condition: strings.Repeat("a", authorizer.MaxConditionBytes+1),
		},
		wantErr: true,
		msg:     `condition: Too long`,
	}, {
		name: "description just over MaxBytes",
		cond: authorizationapi.Condition{
			ID:          "example.com/foo",
			Description: strings.Repeat("b", authorizer.MaxConditionDescriptionBytes+1),
		},
		wantErr: true,
		msg:     `description: Too long`,
	}}

	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			errs := ValidateCondition(&c.cond, field.NewPath("condition"))
			if c.wantErr {
				if len(errs) == 0 {
					t.Fatalf("expected failure containing %q", c.msg)
				}
				if !strings.Contains(errs.ToAggregate().Error(), c.msg) {
					t.Errorf("unexpected error: %v, expected: %q", errs, c.msg)
				}
			} else if len(errs) != 0 {
				t.Errorf("expected success, got: %v", errs)
			}
		})
	}
}
