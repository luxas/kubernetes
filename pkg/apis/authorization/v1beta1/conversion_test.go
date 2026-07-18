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

// reviewKind names one of the three internal review types that share the
// SubjectAccessReviewSpec / SubjectAccessReviewStatus conversion helpers.
type reviewKind int

const (
	kindSAR reviewKind = iota
	kindSelfSAR
	kindLocalSAR
)

func (k reviewKind) String() string {
	switch k {
	case kindSAR:
		return "SubjectAccessReview"
	case kindSelfSAR:
		return "SelfSubjectAccessReview"
	case kindLocalSAR:
		return "LocalSubjectAccessReview"
	}
	return ""
}

var allKinds = []reviewKind{kindSAR, kindSelfSAR, kindLocalSAR}

// localNamespace is set on every LocalSubjectAccessReview base so that
// ObjectMeta.Namespace propagation is exercised alongside the shared spec/status conversions.
const localNamespace = "team-a"

// mods captures the modifications a case applies to the internal spec/status
// of a review object. The expected v1beta1 output is derived by translating
// the same values into v1beta1 types and dropping AuthorizationOptions from
// the spec and ConditionalDecision from the status — the two fields the
// conversion is meant to strip. Fields that only exist on SubjectAccessReviewSpec
// (User/Groups/Extra/UID) are silently ignored for SelfSubjectAccessReview.
type mods struct {
	ResourceAttributes    *authorization.ResourceAttributes
	NonResourceAttributes *authorization.NonResourceAttributes
	AuthorizationOptions  *authorization.AuthorizationOptions

	User   string
	Groups []string
	Extra  map[string]authorization.ExtraValue
	UID    string

	Status authorization.SubjectAccessReviewStatus
}

// buildIn constructs a fresh internal review of the given kind with mods applied.
// All pointer/map fields are deep-copied so sibling test iterations cannot alias input state.
func buildIn(k reviewKind, m mods) runtime.Object {
	ra := m.ResourceAttributes.DeepCopy()
	nra := m.NonResourceAttributes.DeepCopy()
	ao := m.AuthorizationOptions.DeepCopy()
	status := *m.Status.DeepCopy()

	switch k {
	case kindSAR:
		return &authorization.SubjectAccessReview{
			Spec: authorization.SubjectAccessReviewSpec{
				ResourceAttributes:    ra,
				NonResourceAttributes: nra,
				AuthorizationOptions:  ao,
				User:                  m.User,
				Groups:                append([]string(nil), m.Groups...),
				Extra:                 copyExtra(m.Extra),
				UID:                   m.UID,
			},
			Status: status,
		}
	case kindSelfSAR:
		return &authorization.SelfSubjectAccessReview{
			Spec: authorization.SelfSubjectAccessReviewSpec{
				ResourceAttributes:    ra,
				NonResourceAttributes: nra,
				AuthorizationOptions:  ao,
			},
			Status: status,
		}
	case kindLocalSAR:
		return &authorization.LocalSubjectAccessReview{
			ObjectMeta: metav1.ObjectMeta{Namespace: localNamespace},
			Spec: authorization.SubjectAccessReviewSpec{
				ResourceAttributes:    ra,
				NonResourceAttributes: nra,
				AuthorizationOptions:  ao,
				User:                  m.User,
				Groups:                append([]string(nil), m.Groups...),
				Extra:                 copyExtra(m.Extra),
				UID:                   m.UID,
			},
			Status: status,
		}
	}
	return nil
}

// newOut returns an empty v1beta1 destination for the given kind.
func newOut(k reviewKind) runtime.Object {
	switch k {
	case kindSAR:
		return &authorizationv1beta1.SubjectAccessReview{}
	case kindSelfSAR:
		return &authorizationv1beta1.SelfSubjectAccessReview{}
	case kindLocalSAR:
		return &authorizationv1beta1.LocalSubjectAccessReview{}
	}
	return nil
}

// buildExpected constructs the expected v1beta1 output for a successful
// conversion of buildIn(k, m): fields are mirrored and AuthorizationOptions +
// ConditionalDecision are stripped.
func buildExpected(k reviewKind, m mods) runtime.Object {
	ra := toV1beta1ResourceAttributes(m.ResourceAttributes)
	nra := toV1beta1NonResourceAttributes(m.NonResourceAttributes)
	status := toV1beta1Status(m.Status)

	switch k {
	case kindSAR:
		return &authorizationv1beta1.SubjectAccessReview{
			Spec: authorizationv1beta1.SubjectAccessReviewSpec{
				ResourceAttributes:    ra,
				NonResourceAttributes: nra,
				User:                  m.User,
				Groups:                append([]string(nil), m.Groups...),
				Extra:                 toV1beta1Extra(m.Extra),
				UID:                   m.UID,
			},
			Status: status,
		}
	case kindSelfSAR:
		return &authorizationv1beta1.SelfSubjectAccessReview{
			Spec: authorizationv1beta1.SelfSubjectAccessReviewSpec{
				ResourceAttributes:    ra,
				NonResourceAttributes: nra,
			},
			Status: status,
		}
	case kindLocalSAR:
		return &authorizationv1beta1.LocalSubjectAccessReview{
			ObjectMeta: metav1.ObjectMeta{Namespace: localNamespace},
			Spec: authorizationv1beta1.SubjectAccessReviewSpec{
				ResourceAttributes:    ra,
				NonResourceAttributes: nra,
				User:                  m.User,
				Groups:                append([]string(nil), m.Groups...),
				Extra:                 toV1beta1Extra(m.Extra),
				UID:                   m.UID,
			},
			Status: status,
		}
	}
	return nil
}

func toV1beta1ResourceAttributes(in *authorization.ResourceAttributes) *authorizationv1beta1.ResourceAttributes {
	if in == nil {
		return nil
	}
	return &authorizationv1beta1.ResourceAttributes{
		Namespace:   in.Namespace,
		Verb:        in.Verb,
		Group:       in.Group,
		Version:     in.Version,
		Resource:    in.Resource,
		Subresource: in.Subresource,
		Name:        in.Name,
	}
}

func toV1beta1NonResourceAttributes(in *authorization.NonResourceAttributes) *authorizationv1beta1.NonResourceAttributes {
	if in == nil {
		return nil
	}
	return &authorizationv1beta1.NonResourceAttributes{Path: in.Path, Verb: in.Verb}
}

func toV1beta1Extra(in map[string]authorization.ExtraValue) map[string]authorizationv1beta1.ExtraValue {
	if in == nil {
		return nil
	}
	out := make(map[string]authorizationv1beta1.ExtraValue, len(in))
	for k, v := range in {
		out[k] = authorizationv1beta1.ExtraValue(append([]string(nil), v...))
	}
	return out
}

// toV1beta1Status mirrors SubjectAccessReviewStatus into v1beta1, stripping
// ConditionalDecision (which has no representation in v1beta1).
func toV1beta1Status(in authorization.SubjectAccessReviewStatus) authorizationv1beta1.SubjectAccessReviewStatus {
	return authorizationv1beta1.SubjectAccessReviewStatus{
		Allowed:         in.Allowed,
		Denied:          in.Denied,
		Reason:          in.Reason,
		EvaluationError: in.EvaluationError,
	}
}

func copyExtra(in map[string]authorization.ExtraValue) map[string]authorization.ExtraValue {
	if in == nil {
		return nil
	}
	out := make(map[string]authorization.ExtraValue, len(in))
	for k, v := range in {
		out[k] = authorization.ExtraValue(append([]string(nil), v...))
	}
	return out
}

// TestConversion drives every internal→v1beta1 conversion in
// pkg/apis/authorization/v1beta1/conversion.go through runtime.Scheme.Convert.
// Every case is run against all three review types (SAR, SelfSAR, LocalSAR),
// as the spec and status converters are shared across all three.
func TestConversion(t *testing.T) {
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
		return fmt.Sprintf(
			"cannot send SubjectAccessReview with non-default AuthorizationOptions to a v1beta1 client. "+
				"Got handledDecisionTypes %v, supported [Allow Deny NoOpinion]", got)
	}
	const conditionalDecisionErr = "cannot convert SubjectAccessReviewStatus to v1beta1, " +
		"v1beta1 does not support in.ConditionalDecision, which is non-nil in the input object"

	testcases := []struct {
		Name      string
		Mods      mods
		ExpectErr string
	}{
		// ---------- Successful conversions ----------
		{
			Name: "identity fields preserved with nil options",
			Mods: mods{
				ResourceAttributes: &authorization.ResourceAttributes{Verb: "get", Resource: "pods"},
				User:               "alice",
				Groups:             []string{"admins", "eng"},
				Extra: map[string]authorization.ExtraValue{
					"scopes.authentication.kubernetes.io": {"one", "two"},
				},
				UID: "uid-1",
				Status: authorization.SubjectAccessReviewStatus{
					Allowed: true,
					Reason:  "admin",
				},
			},
		},
		{
			Name: "NonResourceAttributes preserved",
			Mods: mods{
				NonResourceAttributes: &authorization.NonResourceAttributes{Path: "/healthz", Verb: "get"},
			},
		},
		{
			Name: "canonical [Allow, Deny, NoOpinion] options dropped",
			Mods: mods{
				ResourceAttributes:   &authorization.ResourceAttributes{Verb: "get", Resource: "pods"},
				AuthorizationOptions: defaultOpts.DeepCopy(),
			},
		},
		{
			Name: "unsorted and duplicated HandledDecisionTypes accepted as a set",
			Mods: mods{
				ResourceAttributes: &authorization.ResourceAttributes{Verb: "get", Resource: "pods"},
				AuthorizationOptions: &authorization.AuthorizationOptions{
					HandledDecisionTypes: []authorization.ConditionsAwareDecisionType{
						authorization.ConditionsAwareDecisionTypeNoOpinion,
						authorization.ConditionsAwareDecisionTypeAllow,
						authorization.ConditionsAwareDecisionTypeDeny,
						authorization.ConditionsAwareDecisionTypeAllow,
					},
				},
			},
		},

		// ---------- Error conversions: HandledDecisionTypes matrix ----------
		{
			Name:      "empty HandledDecisionTypes rejected",
			Mods:      mods{AuthorizationOptions: &authorization.AuthorizationOptions{}},
			ExpectErr: enforceErr(nil),
		},
		{
			Name: "missing NoOpinion rejected",
			Mods: mods{
				AuthorizationOptions: &authorization.AuthorizationOptions{
					HandledDecisionTypes: []authorization.ConditionsAwareDecisionType{
						authorization.ConditionsAwareDecisionTypeAllow,
						authorization.ConditionsAwareDecisionTypeDeny,
					},
				},
			},
			ExpectErr: enforceErr([]authorization.ConditionsAwareDecisionType{
				authorization.ConditionsAwareDecisionTypeAllow,
				authorization.ConditionsAwareDecisionTypeDeny,
			}),
		},
		{
			Name: "extra conditional decision type rejected",
			Mods: mods{
				AuthorizationOptions: &authorization.AuthorizationOptions{
					HandledDecisionTypes: []authorization.ConditionsAwareDecisionType{
						authorization.ConditionsAwareDecisionTypeAllow,
						authorization.ConditionsAwareDecisionTypeDeny,
						authorization.ConditionsAwareDecisionTypeNoOpinion,
						authorization.ConditionsAwareDecisionTypeConditionsMap,
					},
				},
			},
			ExpectErr: enforceErr([]authorization.ConditionsAwareDecisionType{
				authorization.ConditionsAwareDecisionTypeAllow,
				authorization.ConditionsAwareDecisionTypeDeny,
				authorization.ConditionsAwareDecisionTypeNoOpinion,
				authorization.ConditionsAwareDecisionTypeConditionsMap,
			}),
		},
		{
			Name: "unknown decision type rejected",
			Mods: mods{
				AuthorizationOptions: &authorization.AuthorizationOptions{
					HandledDecisionTypes: []authorization.ConditionsAwareDecisionType{"Bogus"},
				},
			},
			ExpectErr: enforceErr([]authorization.ConditionsAwareDecisionType{"Bogus"}),
		},

		// ---------- Error conversion: any non-nil ConditionalDecision ----------
		{
			Name: "non-nil ConditionalDecision rejected",
			Mods: mods{
				Status: authorization.SubjectAccessReviewStatus{
					ConditionalDecision: &authorization.ConditionsAwareDecision{Type: authorization.ConditionsAwareDecisionTypeConditionsMap},
				},
			},
			ExpectErr: conditionalDecisionErr,
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
		for _, k := range allKinds {
			t.Run(fmt.Sprintf("%s/%s", k, tc.Name), func(t *testing.T) {
				in := buildIn(k, tc.Mods)
				out := newOut(k)
				err := scheme.Convert(in, out, nil)
				if tc.ExpectErr != "" {
					if err == nil {
						t.Fatalf("expected error %q, got nil (out=%+v)", tc.ExpectErr, out)
					}
					if diff := cmp.Diff(tc.ExpectErr, err.Error()); diff != "" {
						t.Fatalf("error mismatch (-want +got):\n%s", diff)
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if diff := cmp.Diff(buildExpected(k, tc.Mods), out); diff != "" {
					t.Fatalf("output mismatch (-want +got):\n%s", diff)
				}
			})
		}
	}
}
