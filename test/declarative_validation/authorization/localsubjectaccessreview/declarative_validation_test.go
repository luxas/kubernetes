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

// Package localsubjectaccessreview exercises declarative validation for the
// authorization.k8s.io LocalSubjectAccessReview resource.
package localsubjectaccessreview

import (
	"context"
	"strconv"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	genericfeatures "k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	apitesting "k8s.io/kubernetes/pkg/api/testing"
	"k8s.io/kubernetes/pkg/apis/authorization"
	authorizationvalidation "k8s.io/kubernetes/pkg/apis/authorization/validation"
)

func TestDeclarativeValidate(t *testing.T) {
	for _, v := range apiVersions {
		t.Run("version="+v, func(t *testing.T) {
			testDeclarativeValidate(t, v)
		})
	}
}

func testDeclarativeValidate(t *testing.T, apiVersion string) {
	ctx := genericapirequest.WithRequestInfo(genericapirequest.NewDefaultContext(),
		&genericapirequest.RequestInfo{APIGroup: "authorization.k8s.io", APIVersion: apiVersion, Resource: "localsubjectaccessreviews", Namespace: "default"})
	ctx = genericapirequest.WithNamespace(ctx, "default")

	testCases := map[string]struct {
		obj                            authorization.LocalSubjectAccessReview
		enableConditionalAuthorization bool
		expectedErrs                   field.ErrorList
	}{
		"valid": {
			obj: mkLocalSAR(),
		},
		"neither": {
			obj:          mkLocalSAR(clearResourceAttributes()),
			expectedErrs: field.ErrorList{field.Invalid(field.NewPath("spec"), "", "").WithOrigin("union").MarkAlpha()},
		},
		"both": {
			obj: mkLocalSAR(setNonResourceAttributes()),
			expectedErrs: field.ErrorList{field.Invalid(field.NewPath("spec"), "", "").WithOrigin("union").MarkAlpha(),
				field.Invalid(field.NewPath("spec.nonResourceAttributes"), "", "disallowed on this kind of request").MarkFromImperative(),
			},
		},
		"spec.conditionalAuthorization forbidden when feature gate disabled": {
			obj: mkLocalSAR(setConditionalAuthorization(&authorization.ConditionalAuthorizationOptions{Enabled: true})),
			expectedErrs: field.ErrorList{
				field.Forbidden(field.NewPath("spec", "conditionalAuthorization"), ""),
			},
		},
		"spec.conditionalAuthorization.enabled required when feature gate enabled and enabled=false": {
			enableConditionalAuthorization: true,
			obj:                            mkLocalSAR(setConditionalAuthorization(&authorization.ConditionalAuthorizationOptions{Enabled: false})),
			expectedErrs: field.ErrorList{
				field.Required(field.NewPath("spec", "conditionalAuthorization", "enabled"), ""),
			},
		},
		"status.conditionalDecision forbidden when feature gate disabled": {
			obj: mkLocalSAR(setConditionalDecision(&authorization.ConditionsAwareDecision{})),
			expectedErrs: field.ErrorList{
				field.Forbidden(field.NewPath("status", "conditionalDecision"), ""),
			},
		},
		"status.conditionalDecision.type required": {
			enableConditionalAuthorization: true,
			obj:                            mkLocalSAR(setConditionalDecision(&authorization.ConditionsAwareDecision{})),
			expectedErrs: field.ErrorList{
				field.Required(field.NewPath("status", "conditionalDecision", "type"), ""),
			},
		},
		"status.conditionalDecision.type not supported": {
			enableConditionalAuthorization: true,
			obj:                            mkLocalSAR(setConditionalDecision(&authorization.ConditionsAwareDecision{Type: "BogusType"})),
			expectedErrs: field.ErrorList{
				field.NotSupported[authorization.ConditionsAwareDecisionType](field.NewPath("status", "conditionalDecision", "type"), authorization.ConditionsAwareDecisionType("BogusType"), nil),
			},
		},
		"status.conditionalDecision.conditionsMap[deny|noOpinion|allow]Conditions[*].id required": {
			enableConditionalAuthorization: true,
			obj: mkLocalSAR(setConditionalDecision(&authorization.ConditionsAwareDecision{
				Type: authorization.ConditionsAwareDecisionTypeConditionsMap,
				ConditionsMap: &authorization.ConditionsMap{
					DenyConditions:      []authorization.Condition{{ID: ""}},
					NoOpinionConditions: []authorization.Condition{{ID: ""}},
					AllowConditions:     []authorization.Condition{{ID: ""}},
				},
			})),
			expectedErrs: field.ErrorList{
				field.Required(field.NewPath("status", "conditionalDecision", "conditionsMap", "denyConditions").Index(0).Child("id"), ""),
				field.Required(field.NewPath("status", "conditionalDecision", "conditionsMap", "noOpinionConditions").Index(0).Child("id"), ""),
				field.Required(field.NewPath("status", "conditionalDecision", "conditionsMap", "allowConditions").Index(0).Child("id"), ""),
			},
		},
		"status.conditionalDecision.conditionsMap[deny|noOpinion|allow]Conditions[*] duplicate": {
			enableConditionalAuthorization: true,
			obj: mkLocalSAR(setConditionalDecision(&authorization.ConditionsAwareDecision{
				Type: authorization.ConditionsAwareDecisionTypeConditionsMap,
				ConditionsMap: &authorization.ConditionsMap{
					DenyConditions: []authorization.Condition{
						{ID: "example.com/dup"},
						{ID: "example.com/dup"},
					},
					NoOpinionConditions: []authorization.Condition{
						{ID: "example.com/dup"},
						{ID: "example.com/dup"},
					},
					AllowConditions: []authorization.Condition{
						{ID: "example.com/dup"},
						{ID: "example.com/dup"},
					},
				},
			})),
			expectedErrs: field.ErrorList{
				field.Duplicate(field.NewPath("status", "conditionalDecision", "conditionsMap", "denyConditions").Index(1), nil),
				field.Duplicate(field.NewPath("status", "conditionalDecision", "conditionsMap", "noOpinionConditions").Index(1), nil),
				field.Duplicate(field.NewPath("status", "conditionalDecision", "conditionsMap", "allowConditions").Index(1), nil),
			},
		},
		"status.conditionalDecision.union[*].authorizerName required": {
			enableConditionalAuthorization: true,
			obj: mkLocalSAR(setConditionalDecision(&authorization.ConditionsAwareDecision{
				Type: authorization.ConditionsAwareDecisionTypeUnion,
				Union: []authorization.NamedConditionsAwareDecision{
					{AuthorizerName: "", Decision: validNoOpinionDecision()},
				},
			})),
			expectedErrs: field.ErrorList{
				field.Required(field.NewPath("status", "conditionalDecision", "union").Index(0).Child("authorizerName"), ""),
			},
		},
		"status.conditionalDecision.union[*] duplicate": {
			enableConditionalAuthorization: true,
			obj: mkLocalSAR(setConditionalDecision(&authorization.ConditionsAwareDecision{
				Type: authorization.ConditionsAwareDecisionTypeUnion,
				Union: []authorization.NamedConditionsAwareDecision{
					{AuthorizerName: "dup.example.com", Decision: validNoOpinionDecision()},
					{AuthorizerName: "dup.example.com", Decision: validNoOpinionDecision()},
				},
			})),
			expectedErrs: field.ErrorList{
				field.Duplicate(field.NewPath("status", "conditionalDecision", "union").Index(1), nil),
			},
		},
		"status.conditionalDecision.union[*].authorizerName invalid subdomain": {
			enableConditionalAuthorization: true,
			obj: mkLocalSAR(setConditionalDecision(&authorization.ConditionsAwareDecision{
				Type: authorization.ConditionsAwareDecisionTypeUnion,
				Union: []authorization.NamedConditionsAwareDecision{
					{AuthorizerName: "not a valid label", Decision: validNoOpinionDecision()},
				},
			})),
			expectedErrs: field.ErrorList{
				field.Invalid(field.NewPath("status", "conditionalDecision", "union").Index(0).Child("authorizerName"), "", "").WithOrigin("format=k8s-long-name"),
			},
		},
		"status.conditionalDecision.conditionsMap[deny|noOpinion|allow]Conditions too many": {
			enableConditionalAuthorization: true,
			obj: mkLocalSAR(setConditionalDecision(&authorization.ConditionsAwareDecision{
				Type: authorization.ConditionsAwareDecisionTypeConditionsMap,
				ConditionsMap: &authorization.ConditionsMap{
					DenyConditions:      makeConditions(authorizer.MaxConditionsPerMap + 1),
					NoOpinionConditions: makeConditions(authorizer.MaxConditionsPerMap + 1),
					AllowConditions:     makeConditions(authorizer.MaxConditionsPerMap + 1),
				},
			})),
			expectedErrs: field.ErrorList{
				field.TooMany(field.NewPath("status", "conditionalDecision", "conditionsMap", "denyConditions"), authorizer.MaxConditionsPerMap+1, authorizer.MaxConditionsPerMap).WithOrigin("maxItems"),
				field.TooMany(field.NewPath("status", "conditionalDecision", "conditionsMap", "noOpinionConditions"), authorizer.MaxConditionsPerMap+1, authorizer.MaxConditionsPerMap).WithOrigin("maxItems"),
				field.TooMany(field.NewPath("status", "conditionalDecision", "conditionsMap", "allowConditions"), authorizer.MaxConditionsPerMap+1, authorizer.MaxConditionsPerMap).WithOrigin("maxItems"),
			},
		},
		"status.conditionalDecision.conditionsMap[deny|noOpinion|allow]Conditions[*].id invalid label key": {
			enableConditionalAuthorization: true,
			obj: mkLocalSAR(setConditionalDecision(&authorization.ConditionsAwareDecision{
				Type: authorization.ConditionsAwareDecisionTypeConditionsMap,
				ConditionsMap: &authorization.ConditionsMap{
					DenyConditions:      []authorization.Condition{{ID: "not a valid label"}},
					NoOpinionConditions: []authorization.Condition{{ID: "not a valid label"}},
					AllowConditions:     []authorization.Condition{{ID: "not a valid label"}},
				},
			})),
			expectedErrs: field.ErrorList{
				field.Invalid(field.NewPath("status", "conditionalDecision", "conditionsMap", "denyConditions").Index(0).Child("id"), "", "").WithOrigin("format=k8s-label-key"),
				field.Invalid(field.NewPath("status", "conditionalDecision", "conditionsMap", "noOpinionConditions").Index(0).Child("id"), "", "").WithOrigin("format=k8s-label-key"),
				field.Invalid(field.NewPath("status", "conditionalDecision", "conditionsMap", "allowConditions").Index(0).Child("id"), "", "").WithOrigin("format=k8s-label-key"),
			},
		},
		"status.conditionalDecision.conditionsMap[deny|noOpinion|allow]Conditions[*].type invalid label key": {
			enableConditionalAuthorization: true,
			obj: mkLocalSAR(setConditionalDecision(&authorization.ConditionsAwareDecision{
				Type: authorization.ConditionsAwareDecisionTypeConditionsMap,
				ConditionsMap: &authorization.ConditionsMap{
					DenyConditions:      []authorization.Condition{{ID: "example.com/d", Type: "not a valid label"}},
					NoOpinionConditions: []authorization.Condition{{ID: "example.com/n", Type: "not a valid label"}},
					AllowConditions:     []authorization.Condition{{ID: "example.com/a", Type: "not a valid label"}},
				},
			})),
			expectedErrs: field.ErrorList{
				field.Invalid(field.NewPath("status", "conditionalDecision", "conditionsMap", "denyConditions").Index(0).Child("type"), "", "").WithOrigin("format=k8s-label-key"),
				field.Invalid(field.NewPath("status", "conditionalDecision", "conditionsMap", "noOpinionConditions").Index(0).Child("type"), "", "").WithOrigin("format=k8s-label-key"),
				field.Invalid(field.NewPath("status", "conditionalDecision", "conditionsMap", "allowConditions").Index(0).Child("type"), "", "").WithOrigin("format=k8s-label-key"),
			},
		},
		"status.conditionalDecision.conditionsMap[deny|noOpinion|allow]Conditions[*].condition too long": {
			enableConditionalAuthorization: true,
			obj: mkLocalSAR(setConditionalDecision(&authorization.ConditionsAwareDecision{
				Type: authorization.ConditionsAwareDecisionTypeConditionsMap,
				ConditionsMap: &authorization.ConditionsMap{
					DenyConditions:      []authorization.Condition{{ID: "example.com/d", Condition: strings.Repeat("a", authorizer.MaxConditionBytes+1)}},
					NoOpinionConditions: []authorization.Condition{{ID: "example.com/n", Condition: strings.Repeat("a", authorizer.MaxConditionBytes+1)}},
					AllowConditions:     []authorization.Condition{{ID: "example.com/a", Condition: strings.Repeat("a", authorizer.MaxConditionBytes+1)}},
				},
			})),
			expectedErrs: field.ErrorList{
				field.TooLong(field.NewPath("status", "conditionalDecision", "conditionsMap", "denyConditions").Index(0).Child("condition"), "", authorizer.MaxConditionBytes).WithOrigin("maxBytes").MarkBeta(),
				field.TooLong(field.NewPath("status", "conditionalDecision", "conditionsMap", "noOpinionConditions").Index(0).Child("condition"), "", authorizer.MaxConditionBytes).WithOrigin("maxBytes").MarkBeta(),
				field.TooLong(field.NewPath("status", "conditionalDecision", "conditionsMap", "allowConditions").Index(0).Child("condition"), "", authorizer.MaxConditionBytes).WithOrigin("maxBytes").MarkBeta(),
			},
		},
		"status.conditionalDecision.conditionsMap[deny|noOpinion|allow]Conditions[*].description too long": {
			enableConditionalAuthorization: true,
			obj: mkLocalSAR(setConditionalDecision(&authorization.ConditionsAwareDecision{
				Type: authorization.ConditionsAwareDecisionTypeConditionsMap,
				ConditionsMap: &authorization.ConditionsMap{
					DenyConditions:      []authorization.Condition{{ID: "example.com/d", Description: strings.Repeat("a", authorizer.MaxConditionDescriptionBytes+1)}},
					NoOpinionConditions: []authorization.Condition{{ID: "example.com/n", Description: strings.Repeat("a", authorizer.MaxConditionDescriptionBytes+1)}},
					AllowConditions:     []authorization.Condition{{ID: "example.com/a", Description: strings.Repeat("a", authorizer.MaxConditionDescriptionBytes+1)}},
				},
			})),
			expectedErrs: field.ErrorList{
				field.TooLong(field.NewPath("status", "conditionalDecision", "conditionsMap", "denyConditions").Index(0).Child("description"), "", authorizer.MaxConditionDescriptionBytes).WithOrigin("maxBytes").MarkBeta(),
				field.TooLong(field.NewPath("status", "conditionalDecision", "conditionsMap", "noOpinionConditions").Index(0).Child("description"), "", authorizer.MaxConditionDescriptionBytes).WithOrigin("maxBytes").MarkBeta(),
				field.TooLong(field.NewPath("status", "conditionalDecision", "conditionsMap", "allowConditions").Index(0).Child("description"), "", authorizer.MaxConditionDescriptionBytes).WithOrigin("maxBytes").MarkBeta(),
			},
		},
	}

	for k, tc := range testCases {
		t.Run(k, func(t *testing.T) {
			featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, genericfeatures.ConditionalAuthorization, tc.enableConditionalAuthorization)
			apitesting.VerifyValidationEquivalenceFunc(t, ctx, &tc.obj, func(ctx context.Context, obj runtime.Object) field.ErrorList {
				sar := obj.(*authorization.LocalSubjectAccessReview)
				return authorizationvalidation.ValidateLocalSubjectAccessReviewCreate(ctx, legacyscheme.Scheme, sar)
			}, tc.expectedErrs)
		})
	}
}

func mkLocalSAR(tweaks ...func(*authorization.LocalSubjectAccessReview)) authorization.LocalSubjectAccessReview {
	sar := authorization.LocalSubjectAccessReview{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
		Spec: authorization.SubjectAccessReviewSpec{
			ResourceAttributes: &authorization.ResourceAttributes{
				Namespace: "default",
				Verb:      "get",
				Resource:  "pods",
			},
			User: "admin",
		},
	}
	for _, tweak := range tweaks {
		tweak(&sar)
	}
	return sar
}

func clearResourceAttributes() func(*authorization.LocalSubjectAccessReview) {
	return func(sar *authorization.LocalSubjectAccessReview) {
		sar.Spec.ResourceAttributes = nil
	}
}

func setNonResourceAttributes() func(*authorization.LocalSubjectAccessReview) {
	return func(sar *authorization.LocalSubjectAccessReview) {
		sar.Spec.NonResourceAttributes = &authorization.NonResourceAttributes{}
	}
}

func setConditionalAuthorization(opts *authorization.ConditionalAuthorizationOptions) func(*authorization.LocalSubjectAccessReview) {
	return func(sar *authorization.LocalSubjectAccessReview) {
		sar.Spec.ConditionalAuthorization = opts
	}
}

func setConditionalDecision(d *authorization.ConditionsAwareDecision) func(*authorization.LocalSubjectAccessReview) {
	return func(sar *authorization.LocalSubjectAccessReview) {
		sar.Status.ConditionalDecision = d
	}
}

// validNoOpinionDecision returns a minimally-valid ConditionsAwareDecision for
// nesting inside union members: type=NoOpinion with the NoOpinion field set.
func validNoOpinionDecision() authorization.ConditionsAwareDecision {
	return authorization.ConditionsAwareDecision{
		Type:      authorization.ConditionsAwareDecisionTypeNoOpinion,
		NoOpinion: &authorization.UnconditionalDecision{},
	}
}

// makeConditions produces n Conditions with unique domain-prefixed IDs so that only the
// slice-length (maxItems) rule fires, not per-item id/type validation.
func makeConditions(n int) []authorization.Condition {
	out := make([]authorization.Condition, n)
	for i := range out {
		out[i].ID = "example.com/cond-" + strconv.Itoa(i)
	}
	return out
}
