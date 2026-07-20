/*
Copyright 2015 The Kubernetes Authors.

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
	"context"
	"fmt"

	authorizationv1 "k8s.io/api/authorization/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/operation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
)

// ValidateSubjectAccessReviewSpec validates a SubjectAccessReviewSpec and returns an
// ErrorList with any errors.
func ValidateSubjectAccessReviewSpec(spec authorizationv1.SubjectAccessReviewSpec, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	if spec.ResourceAttributes != nil && spec.NonResourceAttributes != nil {
		allErrs = append(allErrs, field.Invalid(fldPath, spec.NonResourceAttributes, `exactly one of nonResourceAttributes or resourceAttributes must be specified`).WithOrigin("union").MarkCoveredByDeclarative())
	}
	if spec.ResourceAttributes == nil && spec.NonResourceAttributes == nil {
		allErrs = append(allErrs, field.Invalid(fldPath, spec.NonResourceAttributes, `exactly one of nonResourceAttributes or resourceAttributes must be specified`).WithOrigin("union").MarkCoveredByDeclarative())
	}
	if len(spec.User) == 0 && len(spec.Groups) == 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("user"), spec.User, `at least one of user or group must be specified`))
	}
	allErrs = append(allErrs, validateResourceAttributes(spec.ResourceAttributes, field.NewPath("spec.resourceAttributes"))...)

	return allErrs
}

// ValidateSelfSubjectAccessReviewSpec validates a SelfSubjectAccessReviewSpec and returns an
// ErrorList with any errors.
func ValidateSelfSubjectAccessReviewSpec(spec authorizationv1.SelfSubjectAccessReviewSpec, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	if spec.ResourceAttributes != nil && spec.NonResourceAttributes != nil {
		allErrs = append(allErrs, field.Invalid(fldPath, spec.NonResourceAttributes, `exactly one of nonResourceAttributes or resourceAttributes must be specified`).WithOrigin("union").MarkCoveredByDeclarative())
	}
	if spec.ResourceAttributes == nil && spec.NonResourceAttributes == nil {
		allErrs = append(allErrs, field.Invalid(fldPath, spec.NonResourceAttributes, `exactly one of nonResourceAttributes or resourceAttributes must be specified`).WithOrigin("union").MarkCoveredByDeclarative())
	}
	allErrs = append(allErrs, validateResourceAttributes(spec.ResourceAttributes, field.NewPath("spec.resourceAttributes"))...)

	return allErrs
}

// ValidateSubjectAccessReview validates a SubjectAccessReview and returns an
// ErrorList with any errors.
func ValidateSubjectAccessReview(sar *authorizationv1.SubjectAccessReview) field.ErrorList {
	allErrs := ValidateSubjectAccessReviewSpec(sar.Spec, field.NewPath("spec"))
	objectMetaShallowCopy := sar.ObjectMeta
	objectMetaShallowCopy.ManagedFields = nil
	if !apiequality.Semantic.DeepEqual(metav1.ObjectMeta{}, objectMetaShallowCopy) {
		allErrs = append(allErrs, field.Invalid(field.NewPath("metadata"), sar.ObjectMeta, `must be empty`))
	}
	return allErrs
}

// ValidateSelfSubjectAccessReview validates a SelfSubjectAccessReview and returns an
// ErrorList with any errors.
func ValidateSelfSubjectAccessReview(sar *authorizationv1.SelfSubjectAccessReview) field.ErrorList {
	allErrs := ValidateSelfSubjectAccessReviewSpec(sar.Spec, field.NewPath("spec"))
	objectMetaShallowCopy := sar.ObjectMeta
	objectMetaShallowCopy.ManagedFields = nil
	if !apiequality.Semantic.DeepEqual(metav1.ObjectMeta{}, objectMetaShallowCopy) {
		allErrs = append(allErrs, field.Invalid(field.NewPath("metadata"), sar.ObjectMeta, `must be empty`))
	}
	return allErrs
}

// ValidateLocalSubjectAccessReview validates a LocalSubjectAccessReview and returns an
// ErrorList with any errors.
func ValidateLocalSubjectAccessReview(sar *authorizationv1.LocalSubjectAccessReview) field.ErrorList {
	allErrs := ValidateSubjectAccessReviewSpec(sar.Spec, field.NewPath("spec"))

	objectMetaShallowCopy := sar.ObjectMeta
	objectMetaShallowCopy.Namespace = ""
	objectMetaShallowCopy.ManagedFields = nil
	if !apiequality.Semantic.DeepEqual(metav1.ObjectMeta{}, objectMetaShallowCopy) {
		allErrs = append(allErrs, field.Invalid(field.NewPath("metadata"), sar.ObjectMeta, `must be empty except for namespace`))
	}

	if sar.Spec.ResourceAttributes != nil && sar.Spec.ResourceAttributes.Namespace != sar.Namespace {
		allErrs = append(allErrs, field.Invalid(field.NewPath("spec.resourceAttributes.namespace"), sar.Spec.ResourceAttributes.Namespace, `must match metadata.namespace`))
	}
	if sar.Spec.NonResourceAttributes != nil {
		allErrs = append(allErrs, field.Invalid(field.NewPath("spec.nonResourceAttributes"), sar.Spec.NonResourceAttributes, `disallowed on this kind of request`))
	}

	return allErrs
}

func validateResourceAttributes(resourceAttributes *authorizationv1.ResourceAttributes, fldPath *field.Path) field.ErrorList {
	if resourceAttributes == nil {
		return nil
	}
	allErrs := field.ErrorList{}

	allErrs = append(allErrs, validateFieldSelectorAttributes(resourceAttributes.FieldSelector, fldPath.Child("fieldSelector"))...)
	allErrs = append(allErrs, validateLabelSelectorAttributes(resourceAttributes.LabelSelector, fldPath.Child("labelSelector"))...)

	return allErrs
}

func validateFieldSelectorAttributes(selector *authorizationv1.FieldSelectorAttributes, fldPath *field.Path) field.ErrorList {
	if selector == nil {
		return nil
	}
	allErrs := field.ErrorList{}

	if len(selector.RawSelector) > 0 && len(selector.Requirements) > 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("rawSelector"), selector.RawSelector, "may not specified at the same time as requirements"))
	}
	if len(selector.RawSelector) == 0 && len(selector.Requirements) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("requirements"), fmt.Sprintf("when %s is specified, requirements or rawSelector is required", fldPath)))
	}

	// AllowUnknownOperatorInRequirement enables *SubjectAccessReview requests from newer skewed clients which understand operators kube-apiserver does not know about to be authorized.
	validationOptions := metav1validation.FieldSelectorValidationOptions{AllowUnknownOperatorInRequirement: true}
	for i, requirement := range selector.Requirements {
		allErrs = append(allErrs, metav1validation.ValidateFieldSelectorRequirement(requirement, validationOptions, fldPath.Child("requirements").Index(i))...)
	}

	return allErrs
}

func validateLabelSelectorAttributes(selector *authorizationv1.LabelSelectorAttributes, fldPath *field.Path) field.ErrorList {
	if selector == nil {
		return nil
	}
	allErrs := field.ErrorList{}

	if len(selector.RawSelector) > 0 && len(selector.Requirements) > 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("rawSelector"), selector.RawSelector, "may not specified at the same time as requirements"))
	}
	if len(selector.RawSelector) == 0 && len(selector.Requirements) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("requirements"), fmt.Sprintf("when %s is specified, requirements or rawSelector is required", fldPath)))
	}

	// AllowUnknownOperatorInRequirement enables *SubjectAccessReview requests from newer skewed clients which understand operators kube-apiserver does not know about to be authorized.
	validationOptions := metav1validation.LabelSelectorValidationOptions{AllowUnknownOperatorInRequirement: true}
	for i, requirement := range selector.Requirements {
		allErrs = append(allErrs, metav1validation.ValidateLabelSelectorRequirement(requirement, validationOptions, fldPath.Child("requirements").Index(i))...)
	}

	return allErrs
}

func withRequestInfo(parent context.Context, version, resource string) context.Context {
	return request.WithRequestInfo(parent, &request.RequestInfo{
		// Fields read by staging/src/k8s.io/apiserver/pkg/registry/rest/validate.go func requestInfo
		APIGroup:    authorizationv1.GroupName,
		APIVersion:  version,
		Subresource: "",
		// Other fields that might or might not be used in the future, that are aligned with what would be populated by the WithRequestInfo HTTP filter
		IsResourceRequest: true,
		Path:              fmt.Sprintf("/apis/%s/%s/%s", authorizationv1.GroupName, version, resource),
		Verb:              "create",
		Resource:          resource,
	})
}

// ValidateSubjectAccessReviewCreate is the single composition of handwritten and declarative
// SubjectAccessReview validation.
// version is _just_ the version part of the GroupVersion, for instance, "v1", "v1beta1" or "v1alpha1", and controls what versioned
// validations will be applied (as they might differ between different API versions).
// Usually, this is implicitly derived from the RequestInfo in the context. However, here it is set explicitly, as:
//   - though the validated object is supplied in v1 (treated as the external "hub") version, the original, user-supplied object might have been in another version (e.g. v1beta1)
//   - not all callers might be in the API server with RequestInfo already set up properly (e.g. webhook authorizers that want to perform proper validation),
//     and thus does taking the version as an explicit parameter this dependency explicit.
func ValidateSubjectAccessReviewCreate(ctx context.Context, scheme *runtime.Scheme, sar *authorizationv1.SubjectAccessReview, version string) field.ErrorList {
	errs := ValidateSubjectAccessReview(sar)
	dv := rest.DeclarativeValidation{Scheme: scheme}
	return dv.ValidateDeclaratively(withRequestInfo(ctx, version, "subjectaccessreviews"), sar, nil, errs, operation.Create, rest.DeclarativeValidationConfig{})
}

// ValidateSelfSubjectAccessReviewCreate is the single composition of handwritten and declarative
// SelfSubjectAccessReview validation.
// version is _just_ the version part of the GroupVersion, for instance, "v1", "v1beta1" or "v1alpha1", and controls what versioned
// validations will be applied (as they might differ between different API versions).
// Usually, this is implicitly derived from the RequestInfo in the context. However, here it is set explicitly, as:
//   - though the validated object is supplied in v1 (treated as the external "hub") version, the original, user-supplied object might have been in another version (e.g. v1beta1)
//   - not all callers might be in the API server with RequestInfo already set up properly (e.g. webhook authorizers that want to perform proper validation),
//     and thus does taking the version as an explicit parameter this dependency explicit.
func ValidateSelfSubjectAccessReviewCreate(ctx context.Context, scheme *runtime.Scheme, sar *authorizationv1.SelfSubjectAccessReview, version string) field.ErrorList {
	errs := ValidateSelfSubjectAccessReview(sar)
	dv := rest.DeclarativeValidation{Scheme: scheme}
	return dv.ValidateDeclaratively(withRequestInfo(ctx, version, "selfsubjectaccessreviews"), sar, nil, errs, operation.Create, rest.DeclarativeValidationConfig{})
}

// ValidateLocalSubjectAccessReviewCreate is the single composition of handwritten and declarative
// LocalSubjectAccessReview validation.
// version is _just_ the version part of the GroupVersion, for instance, "v1", "v1beta1" or "v1alpha1", and controls what versioned
// validations will be applied (as they might differ between different API versions).
// Usually, this is implicitly derived from the RequestInfo in the context. However, here it is set explicitly, as:
//   - though the validated object is supplied in v1 (treated as the external "hub") version, the original, user-supplied object might have been in another version (e.g. v1beta1)
//   - not all callers might be in the API server with RequestInfo already set up properly (e.g. webhook authorizers that want to perform proper validation),
//     and thus does taking the version as an explicit parameter this dependency explicit.
func ValidateLocalSubjectAccessReviewCreate(ctx context.Context, scheme *runtime.Scheme, sar *authorizationv1.LocalSubjectAccessReview, version string) field.ErrorList {
	errs := ValidateLocalSubjectAccessReview(sar)
	dv := rest.DeclarativeValidation{Scheme: scheme}
	return dv.ValidateDeclaratively(withRequestInfo(ctx, version, "localsubjectaccessreviews"), sar, nil, errs, operation.Create, rest.DeclarativeValidationConfig{})
}
