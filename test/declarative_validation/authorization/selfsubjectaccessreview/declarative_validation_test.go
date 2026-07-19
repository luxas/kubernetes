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

// Package selfsubjectaccessreview exercises declarative validation for the
// authorization.k8s.io SelfSubjectAccessReview resource.
package selfsubjectaccessreview

import (
	"context"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	authorizationvalidation "k8s.io/apiserver/pkg/apis/authorization/validation"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	apitesting "k8s.io/kubernetes/pkg/api/testing"
	"k8s.io/kubernetes/pkg/apis/authorization"
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
		&genericapirequest.RequestInfo{APIGroup: "authorization.k8s.io", APIVersion: apiVersion, Resource: "selfsubjectaccessreviews"})

	testCases := map[string]struct {
		obj          authorization.SelfSubjectAccessReview
		expectedErrs field.ErrorList
	}{
		"valid": {
			obj: mkSelfSAR(),
		},
		"neither": {
			obj:          mkSelfSAR(clearResourceAttributes()),
			expectedErrs: field.ErrorList{field.Invalid(field.NewPath("spec"), "", "").WithOrigin("union").MarkAlpha()},
		},
		"both": {
			obj: mkSelfSAR(setNonResourceAttributes()),
			expectedErrs: field.ErrorList{
				field.Invalid(field.NewPath("spec"), "", "").WithOrigin("union").MarkAlpha(),
			},
		},
	}

	for k, tc := range testCases {
		t.Run(k, func(t *testing.T) {
			apitesting.VerifyValidationEquivalenceFunc(t, ctx, &tc.obj, func(ctx context.Context, obj runtime.Object) field.ErrorList {
				sar := obj.(*authorization.SelfSubjectAccessReview)
				sarV1 := &authorizationv1.SelfSubjectAccessReview{}
				if err := legacyscheme.Scheme.Convert(sar, sarV1, nil); err != nil {
					return field.ErrorList{field.InternalError(nil, err)}
				}
				return authorizationvalidation.ValidateSelfSubjectAccessReviewCreate(ctx, legacyscheme.Scheme, sarV1)
			}, tc.expectedErrs)
		})
	}
}

func mkSelfSAR(tweaks ...func(*authorization.SelfSubjectAccessReview)) authorization.SelfSubjectAccessReview {
	sar := authorization.SelfSubjectAccessReview{
		ObjectMeta: metav1.ObjectMeta{},
		Spec: authorization.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorization.ResourceAttributes{
				Namespace: "default",
				Verb:      "get",
				Resource:  "pods",
			},
		},
	}
	for _, tweak := range tweaks {
		tweak(&sar)
	}
	return sar
}

func clearResourceAttributes() func(*authorization.SelfSubjectAccessReview) {
	return func(sar *authorization.SelfSubjectAccessReview) {
		sar.Spec.ResourceAttributes = nil
	}
}

func setNonResourceAttributes() func(*authorization.SelfSubjectAccessReview) {
	return func(sar *authorization.SelfSubjectAccessReview) {
		sar.Spec.NonResourceAttributes = &authorization.NonResourceAttributes{}
	}
}
