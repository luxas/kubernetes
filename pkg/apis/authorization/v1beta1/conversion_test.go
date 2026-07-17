/*
Copyright The Kubernetes Authors.

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

package v1beta1_test

import (
	fmt "fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	authorizationv1beta1 "k8s.io/api/authorization/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	authorization "k8s.io/kubernetes/pkg/apis/authorization"
	internalv1beta1 "k8s.io/kubernetes/pkg/apis/authorization/v1beta1"
)

// TestConversion drives every internal→v1beta1 conversion in
// pkg/apis/authorization/v1beta1/conversion.go through runtime.Scheme.Convert,
// registering both the internal and the versioned type registries onto a fresh
// scheme. Substruct-level converters (SelfSubjectAccessReviewSpec,
// SubjectAccessReviewSpec, SubjectAccessReviewStatus) are exercised via the
// top-level runtime.Object wrappers that contain them; enforcement of the
// AuthorizationOptions.HandledDecisionTypes and status ConditionalDecision
// contracts is asserted with exact error strings so any accidental drift in
// the source is caught.
func TestConversion(t *testing.T) {
	// Convenience aliases used only in expected-string construction.
	defaultOpts := &authorization.AuthorizationOptions{
		HandledDecisionTypes: []authorization.ConditionsAwareDecisionType{
			authorization.ConditionsAwareDecisionTypeAllow,
			authorization.ConditionsAwareDecisionTypeDeny,
			authorization.ConditionsAwareDecisionTypeNoOpinion,
		},
	}

	// enforceErr formats the exact string returned by
	// enforceUnconditionalHandledDecisionTypesOnly for a given input slice.
	enforceErr := func(got []authorization.ConditionsAwareDecisionType) string {
		// Mirrors the fmt.Errorf in conversion.go verbatim.
		return "cannot send SubjectAccessReview with non-default AuthorizationOptions to a v1beta1 client. " +
			"Got handledDecisionTypes " + fmt.Sprintf("%v", got) + ", " +
			"supported [Allow Deny NoOpinion]"
	}

	testcases := []struct {
		Name      string
		In        runtime.Object
		Out       runtime.Object
		ExpectOut runtime.Object
		ExpectErr string
	}{
		// ---------- Successful conversions ----------
		{
			Name: "SubjectAccessReview: nil options and nil conditional decision, identity fields preserved",
			In: &authorization.SubjectAccessReview{
				Spec: authorization.SubjectAccessReviewSpec{
					ResourceAttributes: &authorization.ResourceAttributes{Verb: "get", Resource: "pods"},
					User:               "alice",
					Groups:             []string{"admins", "eng"},
					Extra: map[string]authorization.ExtraValue{
						"scopes.authentication.kubernetes.io": {"one", "two"},
					},
					UID: "uid-1",
				},
				Status: authorization.SubjectAccessReviewStatus{
					Allowed: true,
					Reason:  "admin",
				},
			},
			Out: &authorizationv1beta1.SubjectAccessReview{},
			ExpectOut: &authorizationv1beta1.SubjectAccessReview{
				Spec: authorizationv1beta1.SubjectAccessReviewSpec{
					ResourceAttributes: &authorizationv1beta1.ResourceAttributes{Verb: "get", Resource: "pods"},
					User:               "alice",
					Groups:             []string{"admins", "eng"},
					Extra: map[string]authorizationv1beta1.ExtraValue{
						"scopes.authentication.kubernetes.io": {"one", "two"},
					},
					UID: "uid-1",
				},
				Status: authorizationv1beta1.SubjectAccessReviewStatus{
					Allowed: true,
					Reason:  "admin",
				},
			},
		},
		{
			Name: "SubjectAccessReview: canonical [Allow, Deny, NoOpinion] options dropped",
			In: &authorization.SubjectAccessReview{
				Spec: authorization.SubjectAccessReviewSpec{
					User:                 "alice",
					AuthorizationOptions: defaultOpts.DeepCopy(),
				},
			},
			Out: &authorizationv1beta1.SubjectAccessReview{},
			ExpectOut: &authorizationv1beta1.SubjectAccessReview{
				Spec: authorizationv1beta1.SubjectAccessReviewSpec{User: "alice"},
			},
		},
		{
			Name: "SubjectAccessReview: unsorted [NoOpinion, Deny, Allow] options accepted and dropped",
			In: &authorization.SubjectAccessReview{
				Spec: authorization.SubjectAccessReviewSpec{
					User: "alice",
					AuthorizationOptions: &authorization.AuthorizationOptions{
						HandledDecisionTypes: []authorization.ConditionsAwareDecisionType{
							authorization.ConditionsAwareDecisionTypeNoOpinion,
							authorization.ConditionsAwareDecisionTypeDeny,
							authorization.ConditionsAwareDecisionTypeAllow,
						},
					},
				},
			},
			Out: &authorizationv1beta1.SubjectAccessReview{},
			ExpectOut: &authorizationv1beta1.SubjectAccessReview{
				Spec: authorizationv1beta1.SubjectAccessReviewSpec{User: "alice"},
			},
		},
		{
			Name: "SubjectAccessReview: status ConditionalDecision.Type=Deny consistent with Allowed=false Denied=true, decision dropped",
			In: &authorization.SubjectAccessReview{
				Status: authorization.SubjectAccessReviewStatus{
					Allowed:             false,
					Denied:              true,
					Reason:              "explicitly denied",
					ConditionalDecision: &authorization.ConditionsAwareDecision{Type: authorization.ConditionsAwareDecisionTypeDeny},
				},
			},
			Out: &authorizationv1beta1.SubjectAccessReview{},
			ExpectOut: &authorizationv1beta1.SubjectAccessReview{
				Status: authorizationv1beta1.SubjectAccessReviewStatus{
					Denied: true,
					Reason: "explicitly denied",
				},
			},
		},
		{
			Name: "SubjectAccessReview: status ConditionalDecision.Type=NoOpinion consistent with Allowed=false Denied=false, decision dropped",
			In: &authorization.SubjectAccessReview{
				Status: authorization.SubjectAccessReviewStatus{
					Reason:              "no opinion",
					ConditionalDecision: &authorization.ConditionsAwareDecision{Type: authorization.ConditionsAwareDecisionTypeNoOpinion},
				},
			},
			Out: &authorizationv1beta1.SubjectAccessReview{},
			ExpectOut: &authorizationv1beta1.SubjectAccessReview{
				Status: authorizationv1beta1.SubjectAccessReviewStatus{Reason: "no opinion"},
			},
		},
		{
			Name: "SubjectAccessReview: status ConditionalDecision.Type=Allow consistent with Allowed=true Denied=false, decision dropped",
			In: &authorization.SubjectAccessReview{
				Status: authorization.SubjectAccessReviewStatus{
					Allowed:             true,
					Reason:              "admin override",
					EvaluationError:     "note",
					ConditionalDecision: &authorization.ConditionsAwareDecision{Type: authorization.ConditionsAwareDecisionTypeAllow},
				},
			},
			Out: &authorizationv1beta1.SubjectAccessReview{},
			ExpectOut: &authorizationv1beta1.SubjectAccessReview{
				Status: authorizationv1beta1.SubjectAccessReviewStatus{
					Allowed:         true,
					Reason:          "admin override",
					EvaluationError: "note",
				},
			},
		},
		{
			Name: "SelfSubjectAccessReview: nil options, ResourceAttributes only",
			In: &authorization.SelfSubjectAccessReview{
				Spec: authorization.SelfSubjectAccessReviewSpec{
					ResourceAttributes: &authorization.ResourceAttributes{Verb: "get", Resource: "pods"},
				},
			},
			Out: &authorizationv1beta1.SelfSubjectAccessReview{},
			ExpectOut: &authorizationv1beta1.SelfSubjectAccessReview{
				Spec: authorizationv1beta1.SelfSubjectAccessReviewSpec{
					ResourceAttributes: &authorizationv1beta1.ResourceAttributes{Verb: "get", Resource: "pods"},
				},
			},
		},
		{
			Name: "SelfSubjectAccessReview: valid options dropped",
			In: &authorization.SelfSubjectAccessReview{
				Spec: authorization.SelfSubjectAccessReviewSpec{
					NonResourceAttributes: &authorization.NonResourceAttributes{Path: "/healthz", Verb: "get"},
					AuthorizationOptions:  defaultOpts.DeepCopy(),
				},
			},
			Out: &authorizationv1beta1.SelfSubjectAccessReview{},
			ExpectOut: &authorizationv1beta1.SelfSubjectAccessReview{
				Spec: authorizationv1beta1.SelfSubjectAccessReviewSpec{
					NonResourceAttributes: &authorizationv1beta1.NonResourceAttributes{Path: "/healthz", Verb: "get"},
				},
			},
		},
		{
			Name: "LocalSubjectAccessReview: nil options, Namespace preserved",
			In: &authorization.LocalSubjectAccessReview{
				ObjectMeta: metav1.ObjectMeta{Namespace: "team-a"},
				Spec: authorization.SubjectAccessReviewSpec{
					ResourceAttributes: &authorization.ResourceAttributes{Namespace: "team-a", Verb: "list", Resource: "configmaps"},
					User:               "bob",
				},
			},
			Out: &authorizationv1beta1.LocalSubjectAccessReview{},
			ExpectOut: &authorizationv1beta1.LocalSubjectAccessReview{
				ObjectMeta: metav1.ObjectMeta{Namespace: "team-a"},
				Spec: authorizationv1beta1.SubjectAccessReviewSpec{
					ResourceAttributes: &authorizationv1beta1.ResourceAttributes{Namespace: "team-a", Verb: "list", Resource: "configmaps"},
					User:               "bob",
				},
			},
		},
		{
			Name: "LocalSubjectAccessReview: valid options dropped, Namespace preserved",
			In: &authorization.LocalSubjectAccessReview{
				ObjectMeta: metav1.ObjectMeta{Namespace: "team-a"},
				Spec: authorization.SubjectAccessReviewSpec{
					User:                 "bob",
					AuthorizationOptions: defaultOpts.DeepCopy(),
				},
			},
			Out: &authorizationv1beta1.LocalSubjectAccessReview{},
			ExpectOut: &authorizationv1beta1.LocalSubjectAccessReview{
				ObjectMeta: metav1.ObjectMeta{Namespace: "team-a"},
				Spec:       authorizationv1beta1.SubjectAccessReviewSpec{User: "bob"},
			},
		},

		// ---------- Error conversions: HandledDecisionTypes matrix ----------
		{
			Name: "SubjectAccessReview: empty HandledDecisionTypes rejected",
			In: &authorization.SubjectAccessReview{
				Spec: authorization.SubjectAccessReviewSpec{
					AuthorizationOptions: &authorization.AuthorizationOptions{},
				},
			},
			Out:       &authorizationv1beta1.SubjectAccessReview{},
			ExpectErr: enforceErr(nil),
		},
		{
			Name: "SubjectAccessReview: single value [Allow] rejected",
			In: &authorization.SubjectAccessReview{
				Spec: authorization.SubjectAccessReviewSpec{
					AuthorizationOptions: &authorization.AuthorizationOptions{
						HandledDecisionTypes: []authorization.ConditionsAwareDecisionType{
							authorization.ConditionsAwareDecisionTypeAllow,
						},
					},
				},
			},
			Out:       &authorizationv1beta1.SubjectAccessReview{},
			ExpectErr: enforceErr([]authorization.ConditionsAwareDecisionType{authorization.ConditionsAwareDecisionTypeAllow}),
		},
		{
			Name: "SubjectAccessReview: missing NoOpinion rejected",
			In: &authorization.SubjectAccessReview{
				Spec: authorization.SubjectAccessReviewSpec{
					AuthorizationOptions: &authorization.AuthorizationOptions{
						HandledDecisionTypes: []authorization.ConditionsAwareDecisionType{
							authorization.ConditionsAwareDecisionTypeAllow,
							authorization.ConditionsAwareDecisionTypeDeny,
						},
					},
				},
			},
			Out: &authorizationv1beta1.SubjectAccessReview{},
			ExpectErr: enforceErr([]authorization.ConditionsAwareDecisionType{
				authorization.ConditionsAwareDecisionTypeAllow,
				authorization.ConditionsAwareDecisionTypeDeny,
			}),
		},
		{
			Name: "SubjectAccessReview: duplicates in HandledDecisionTypes rejected",
			In: &authorization.SubjectAccessReview{
				Spec: authorization.SubjectAccessReviewSpec{
					AuthorizationOptions: &authorization.AuthorizationOptions{
						HandledDecisionTypes: []authorization.ConditionsAwareDecisionType{
							authorization.ConditionsAwareDecisionTypeAllow,
							authorization.ConditionsAwareDecisionTypeAllow,
							authorization.ConditionsAwareDecisionTypeDeny,
							authorization.ConditionsAwareDecisionTypeNoOpinion,
						},
					},
				},
			},
			Out: &authorizationv1beta1.SubjectAccessReview{},
			ExpectErr: enforceErr([]authorization.ConditionsAwareDecisionType{
				authorization.ConditionsAwareDecisionTypeAllow,
				authorization.ConditionsAwareDecisionTypeAllow,
				authorization.ConditionsAwareDecisionTypeDeny,
				authorization.ConditionsAwareDecisionTypeNoOpinion,
			}),
		},
		{
			Name: "SubjectAccessReview: extra ConditionsMap in HandledDecisionTypes rejected",
			In: &authorization.SubjectAccessReview{
				Spec: authorization.SubjectAccessReviewSpec{
					AuthorizationOptions: &authorization.AuthorizationOptions{
						HandledDecisionTypes: []authorization.ConditionsAwareDecisionType{
							authorization.ConditionsAwareDecisionTypeAllow,
							authorization.ConditionsAwareDecisionTypeDeny,
							authorization.ConditionsAwareDecisionTypeNoOpinion,
							authorization.ConditionsAwareDecisionTypeConditionsMap,
						},
					},
				},
			},
			Out: &authorizationv1beta1.SubjectAccessReview{},
			ExpectErr: enforceErr([]authorization.ConditionsAwareDecisionType{
				authorization.ConditionsAwareDecisionTypeAllow,
				authorization.ConditionsAwareDecisionTypeDeny,
				authorization.ConditionsAwareDecisionTypeNoOpinion,
				authorization.ConditionsAwareDecisionTypeConditionsMap,
			}),
		},
		{
			Name: "SubjectAccessReview: extra Union in HandledDecisionTypes rejected",
			In: &authorization.SubjectAccessReview{
				Spec: authorization.SubjectAccessReviewSpec{
					AuthorizationOptions: &authorization.AuthorizationOptions{
						HandledDecisionTypes: []authorization.ConditionsAwareDecisionType{
							authorization.ConditionsAwareDecisionTypeAllow,
							authorization.ConditionsAwareDecisionTypeDeny,
							authorization.ConditionsAwareDecisionTypeNoOpinion,
							authorization.ConditionsAwareDecisionTypeUnion,
						},
					},
				},
			},
			Out: &authorizationv1beta1.SubjectAccessReview{},
			ExpectErr: enforceErr([]authorization.ConditionsAwareDecisionType{
				authorization.ConditionsAwareDecisionTypeAllow,
				authorization.ConditionsAwareDecisionTypeDeny,
				authorization.ConditionsAwareDecisionTypeNoOpinion,
				authorization.ConditionsAwareDecisionTypeUnion,
			}),
		},
		{
			Name: "SubjectAccessReview: unknown decision type rejected",
			In: &authorization.SubjectAccessReview{
				Spec: authorization.SubjectAccessReviewSpec{
					AuthorizationOptions: &authorization.AuthorizationOptions{
						HandledDecisionTypes: []authorization.ConditionsAwareDecisionType{
							authorization.ConditionsAwareDecisionType("Bogus"),
						},
					},
				},
			},
			Out: &authorizationv1beta1.SubjectAccessReview{},
			ExpectErr: enforceErr([]authorization.ConditionsAwareDecisionType{
				authorization.ConditionsAwareDecisionType("Bogus"),
			}),
		},
		{
			Name: "SelfSubjectAccessReview: empty HandledDecisionTypes fires the shared helper",
			In: &authorization.SelfSubjectAccessReview{
				Spec: authorization.SelfSubjectAccessReviewSpec{
					AuthorizationOptions: &authorization.AuthorizationOptions{},
				},
			},
			Out:       &authorizationv1beta1.SelfSubjectAccessReview{},
			ExpectErr: enforceErr(nil),
		},
		{
			Name: "LocalSubjectAccessReview: extra ConditionsMap fires the shared helper",
			In: &authorization.LocalSubjectAccessReview{
				Spec: authorization.SubjectAccessReviewSpec{
					AuthorizationOptions: &authorization.AuthorizationOptions{
						HandledDecisionTypes: []authorization.ConditionsAwareDecisionType{
							authorization.ConditionsAwareDecisionTypeAllow,
							authorization.ConditionsAwareDecisionTypeDeny,
							authorization.ConditionsAwareDecisionTypeNoOpinion,
							authorization.ConditionsAwareDecisionTypeConditionsMap,
						},
					},
				},
			},
			Out: &authorizationv1beta1.LocalSubjectAccessReview{},
			ExpectErr: enforceErr([]authorization.ConditionsAwareDecisionType{
				authorization.ConditionsAwareDecisionTypeAllow,
				authorization.ConditionsAwareDecisionTypeDeny,
				authorization.ConditionsAwareDecisionTypeNoOpinion,
				authorization.ConditionsAwareDecisionTypeConditionsMap,
			}),
		},

		// ---------- Error conversions: SubjectAccessReviewStatus ConditionalDecision matrix ----------
		{
			Name: "SubjectAccessReview: status Type=Deny inconsistent Allowed=true",
			In: &authorization.SubjectAccessReview{
				Status: authorization.SubjectAccessReviewStatus{
					Allowed:             true,
					Denied:              true,
					ConditionalDecision: &authorization.ConditionsAwareDecision{Type: authorization.ConditionsAwareDecisionTypeDeny},
				},
			},
			Out:       &authorizationv1beta1.SubjectAccessReview{},
			ExpectErr: "inconsistent input object, got in.ConditionalDecision.Type=Deny, but in.Allowed=true (expected false) and in.Denied=true (expected true)",
		},
		{
			Name: "SubjectAccessReview: status Type=Deny inconsistent Denied=false",
			In: &authorization.SubjectAccessReview{
				Status: authorization.SubjectAccessReviewStatus{
					ConditionalDecision: &authorization.ConditionsAwareDecision{Type: authorization.ConditionsAwareDecisionTypeDeny},
				},
			},
			Out:       &authorizationv1beta1.SubjectAccessReview{},
			ExpectErr: "inconsistent input object, got in.ConditionalDecision.Type=Deny, but in.Allowed=false (expected false) and in.Denied=false (expected true)",
		},
		{
			// Note: conversion.go:77 formats the NoOpinion arm with the string
			// literal "Type=Allow"; this test encodes current behavior. If the
			// source is corrected, this test must be updated to match.
			Name: "SubjectAccessReview: status Type=NoOpinion inconsistent Allowed=true",
			In: &authorization.SubjectAccessReview{
				Status: authorization.SubjectAccessReviewStatus{
					Allowed:             true,
					ConditionalDecision: &authorization.ConditionsAwareDecision{Type: authorization.ConditionsAwareDecisionTypeNoOpinion},
				},
			},
			Out:       &authorizationv1beta1.SubjectAccessReview{},
			ExpectErr: "inconsistent input object, got in.ConditionalDecision.Type=Allow, but in.Allowed=true (expected false) and in.Denied=false (expected false)",
		},
		{
			Name: "SubjectAccessReview: status Type=NoOpinion inconsistent Denied=true",
			In: &authorization.SubjectAccessReview{
				Status: authorization.SubjectAccessReviewStatus{
					Denied:              true,
					ConditionalDecision: &authorization.ConditionsAwareDecision{Type: authorization.ConditionsAwareDecisionTypeNoOpinion},
				},
			},
			Out:       &authorizationv1beta1.SubjectAccessReview{},
			ExpectErr: "inconsistent input object, got in.ConditionalDecision.Type=Allow, but in.Allowed=false (expected false) and in.Denied=true (expected false)",
		},
		{
			Name: "SubjectAccessReview: status Type=Allow inconsistent Allowed=false",
			In: &authorization.SubjectAccessReview{
				Status: authorization.SubjectAccessReviewStatus{
					ConditionalDecision: &authorization.ConditionsAwareDecision{Type: authorization.ConditionsAwareDecisionTypeAllow},
				},
			},
			Out:       &authorizationv1beta1.SubjectAccessReview{},
			ExpectErr: "inconsistent input object, got in.ConditionalDecision.Type=Allow, but in.Allowed=false (expected true) and in.Denied=false (expected false)",
		},
		{
			Name: "SubjectAccessReview: status Type=Allow inconsistent Denied=true",
			In: &authorization.SubjectAccessReview{
				Status: authorization.SubjectAccessReviewStatus{
					Allowed:             true,
					Denied:              true,
					ConditionalDecision: &authorization.ConditionsAwareDecision{Type: authorization.ConditionsAwareDecisionTypeAllow},
				},
			},
			Out:       &authorizationv1beta1.SubjectAccessReview{},
			ExpectErr: "inconsistent input object, got in.ConditionalDecision.Type=Allow, but in.Allowed=true (expected true) and in.Denied=true (expected false)",
		},
		{
			Name: "SubjectAccessReview: status Type=ConditionsMap unrepresentable",
			In: &authorization.SubjectAccessReview{
				Status: authorization.SubjectAccessReviewStatus{
					ConditionalDecision: &authorization.ConditionsAwareDecision{Type: authorization.ConditionsAwareDecisionTypeConditionsMap},
				},
			},
			Out:       &authorizationv1beta1.SubjectAccessReview{},
			ExpectErr: "cannot convert SubjectAccessReviewStatus to v1beta1, v1beta1 does not support in.ConditionalDecision.Type=ConditionsMap",
		},
		{
			Name: "SubjectAccessReview: status Type=Union unrepresentable",
			In: &authorization.SubjectAccessReview{
				Status: authorization.SubjectAccessReviewStatus{
					ConditionalDecision: &authorization.ConditionsAwareDecision{Type: authorization.ConditionsAwareDecisionTypeUnion},
				},
			},
			Out:       &authorizationv1beta1.SubjectAccessReview{},
			ExpectErr: "cannot convert SubjectAccessReviewStatus to v1beta1, v1beta1 does not support in.ConditionalDecision.Type=Union",
		},
		{
			Name: "SubjectAccessReview: status Type=\"\" falls into default arm",
			In: &authorization.SubjectAccessReview{
				Status: authorization.SubjectAccessReviewStatus{
					ConditionalDecision: &authorization.ConditionsAwareDecision{},
				},
			},
			Out:       &authorizationv1beta1.SubjectAccessReview{},
			ExpectErr: "cannot convert SubjectAccessReviewStatus to v1beta1, v1beta1 does not support in.ConditionalDecision.Type=",
		},
		{
			Name: "SubjectAccessReview: status Type=\"Bogus\" falls into default arm",
			In: &authorization.SubjectAccessReview{
				Status: authorization.SubjectAccessReviewStatus{
					ConditionalDecision: &authorization.ConditionsAwareDecision{Type: authorization.ConditionsAwareDecisionType("Bogus")},
				},
			},
			Out:       &authorizationv1beta1.SubjectAccessReview{},
			ExpectErr: "cannot convert SubjectAccessReviewStatus to v1beta1, v1beta1 does not support in.ConditionalDecision.Type=Bogus",
		},
	}

	scheme := runtime.NewScheme()
	if err := authorization.AddToScheme(scheme); err != nil {
		t.Fatalf("register internal types: %v", err)
	}
	if err := internalv1beta1.AddToScheme(scheme); err != nil {
		t.Fatalf("register v1beta1 types: %v", err)
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			err := scheme.Convert(tc.In, tc.Out, nil)
			if tc.ExpectErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil (out=%+v)", tc.ExpectErr, tc.Out)
				}
				if diff := cmp.Diff(tc.ExpectErr, err.Error()); diff != "" {
					t.Fatalf("error mismatch (-want +got):\n%s", diff)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tc.ExpectOut, tc.Out); diff != "" {
				t.Fatalf("output mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
