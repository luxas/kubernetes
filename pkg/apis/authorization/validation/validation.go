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
	"strings"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/operation"
	"k8s.io/apimachinery/pkg/api/validate/content"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	genericfeatures "k8s.io/apiserver/pkg/features"
	"k8s.io/apiserver/pkg/registry/rest"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	authorizationapi "k8s.io/kubernetes/pkg/apis/authorization"
)

// sarValidationConfig returns the declarative validation config to use for
// SubjectAccessReview-family create validation. It enables the
// "ConditionalAuthorization" option when the corresponding feature gate is
// enabled, so that the +k8s:ifDisabled("ConditionalAuthorization")=+k8s:forbidden
// tag on spec.conditionalAuthorization does not reject the field.
func sarValidationConfig() rest.DeclarativeValidationConfig {
	var options []string
	if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.ConditionalAuthorization) {
		options = append(options, string(genericfeatures.ConditionalAuthorization))
	}
	return rest.DeclarativeValidationConfig{Options: options}
}

// ValidateSubjectAccessReviewSpec validates a SubjectAccessReviewSpec and returns an
// ErrorList with any errors.
func ValidateSubjectAccessReviewSpec(spec authorizationapi.SubjectAccessReviewSpec, fldPath *field.Path) field.ErrorList {
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
func ValidateSelfSubjectAccessReviewSpec(spec authorizationapi.SelfSubjectAccessReviewSpec, fldPath *field.Path) field.ErrorList {
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
func ValidateSubjectAccessReview(sar *authorizationapi.SubjectAccessReview) field.ErrorList {
	allErrs := ValidateSubjectAccessReviewSpec(sar.Spec, field.NewPath("spec"))
	allErrs = append(allErrs, ValidateConditionsAwareDecision(sar.Status.ConditionalDecision, field.NewPath("status", "conditionalDecision"))...)
	objectMetaShallowCopy := sar.ObjectMeta
	objectMetaShallowCopy.ManagedFields = nil
	if !apiequality.Semantic.DeepEqual(metav1.ObjectMeta{}, objectMetaShallowCopy) {
		allErrs = append(allErrs, field.Invalid(field.NewPath("metadata"), sar.ObjectMeta, `must be empty`))
	}
	return allErrs
}

// ValidateSelfSubjectAccessReview validates a SelfSubjectAccessReview and returns an
// ErrorList with any errors.
func ValidateSelfSubjectAccessReview(sar *authorizationapi.SelfSubjectAccessReview) field.ErrorList {
	allErrs := ValidateSelfSubjectAccessReviewSpec(sar.Spec, field.NewPath("spec"))
	allErrs = append(allErrs, ValidateConditionsAwareDecision(sar.Status.ConditionalDecision, field.NewPath("status", "conditionalDecision"))...)
	objectMetaShallowCopy := sar.ObjectMeta
	objectMetaShallowCopy.ManagedFields = nil
	if !apiequality.Semantic.DeepEqual(metav1.ObjectMeta{}, objectMetaShallowCopy) {
		allErrs = append(allErrs, field.Invalid(field.NewPath("metadata"), sar.ObjectMeta, `must be empty`))
	}
	return allErrs
}

// ValidateLocalSubjectAccessReview validates a LocalSubjectAccessReview and returns an
// ErrorList with any errors.
func ValidateLocalSubjectAccessReview(sar *authorizationapi.LocalSubjectAccessReview) field.ErrorList {
	allErrs := ValidateSubjectAccessReviewSpec(sar.Spec, field.NewPath("spec"))
	allErrs = append(allErrs, ValidateConditionsAwareDecision(sar.Status.ConditionalDecision, field.NewPath("status", "conditionalDecision"))...)

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

func validateResourceAttributes(resourceAttributes *authorizationapi.ResourceAttributes, fldPath *field.Path) field.ErrorList {
	if resourceAttributes == nil {
		return nil
	}
	allErrs := field.ErrorList{}

	allErrs = append(allErrs, validateFieldSelectorAttributes(resourceAttributes.FieldSelector, fldPath.Child("fieldSelector"))...)
	allErrs = append(allErrs, validateLabelSelectorAttributes(resourceAttributes.LabelSelector, fldPath.Child("labelSelector"))...)

	return allErrs
}

func validateFieldSelectorAttributes(selector *authorizationapi.FieldSelectorAttributes, fldPath *field.Path) field.ErrorList {
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

func validateLabelSelectorAttributes(selector *authorizationapi.LabelSelectorAttributes, fldPath *field.Path) field.ErrorList {
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

// ValidateAuthorizationConditionsReview validates a AuthorizationConditionsReview and returns an
// ErrorList with any errors.
func ValidateAuthorizationConditionsReview(acr *authorizationapi.AuthorizationConditionsReview) field.ErrorList {
	allErrs := ValidateAuthorizationConditionsRequest(acr.Request, field.NewPath("request"))
	allErrs = append(allErrs, ValidateAuthorizationConditionsResponse(acr.Response, field.NewPath("response"))...)
	objectMetaShallowCopy := acr.ObjectMeta
	objectMetaShallowCopy.ManagedFields = nil
	if !apiequality.Semantic.DeepEqual(metav1.ObjectMeta{}, objectMetaShallowCopy) {
		allErrs = append(allErrs, field.Invalid(field.NewPath("metadata"), acr.ObjectMeta, `must be empty`))
	}
	return allErrs
}

// ValidateAuthorizationConditionsRequest validates a AuthorizationConditionsRequest and returns an
// ErrorList with any errors.
func ValidateAuthorizationConditionsRequest(req *authorizationapi.AuthorizationConditionsRequest, fldPath *field.Path) field.ErrorList {
	allErrs := ValidateConditionsAwareDecision(&req.Decision, fldPath.Child("decision"))
	// TODO(luxas): AdmissionReviewRequest validation here
	return allErrs
}

// ValidateAuthorizationConditionsResponse validates a AuthorizationConditionsResponse and returns an
// ErrorList with any errors.
func ValidateAuthorizationConditionsResponse(resp *authorizationapi.AuthorizationConditionsResponse, fldPath *field.Path) field.ErrorList {
	allErrs := ValidateConditionsAwareDecision(&resp.Decision, fldPath.Child("decision"))
	return allErrs
}

// ValidateConditionsAwareDecision validates a ConditionsAwareDecision and returns an
// ErrorList with any errors. Only the fields not fully covered by Standard declarative
// validation are enforced here; every emitted error mirrors a declarative Beta rule and
// is marked CoveredByDeclarative so the equivalence check treats them as one.
func ValidateConditionsAwareDecision(decision *authorizationapi.ConditionsAwareDecision, fldPath *field.Path) field.ErrorList {
	if decision == nil {
		return nil
	}
	allErrs := field.ErrorList{}
	if decision.ConditionsMap != nil {
		allErrs = append(allErrs, ValidateConditionsMap(decision.ConditionsMap, fldPath.Child("conditionsMap"))...)
	}
	return allErrs
}

// ValidateConditionsMap validates a ConditionsMap by descending into each condition. It
// only fires Beta-shadowed errors (via ValidateCondition); the Standard rules on the
// slices themselves are already covered by declarative validation in every mode.
func ValidateConditionsMap(conditionsMap *authorizationapi.ConditionsMap, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	for i := range conditionsMap.DenyConditions {
		allErrs = append(allErrs, ValidateCondition(&conditionsMap.DenyConditions[i], fldPath.Child("denyConditions").Index(i))...)
	}
	for i := range conditionsMap.NoOpinionConditions {
		allErrs = append(allErrs, ValidateCondition(&conditionsMap.NoOpinionConditions[i], fldPath.Child("noOpinionConditions").Index(i))...)
	}
	for i := range conditionsMap.AllowConditions {
		allErrs = append(allErrs, ValidateCondition(&conditionsMap.AllowConditions[i], fldPath.Child("allowConditions").Index(i))...)
	}

	// TODO(luxas): Consider validating that the length of all conditions <= MaxConditions. However, that is already validated in the
	// core framework.

	return allErrs
}

// ValidateCondition mirrors the Beta declarative rules on Condition (MaxBytes on
// condition and description) so equivalence tests can rely on the errors appearing
// when the DeclarativeValidationBeta gate is off. Each error is CoveredByDeclarative
// so the composition layer folds it with its declarative counterpart.
func ValidateCondition(condition *authorizationapi.Condition, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	// TODO(luxas): Preferably support IsDomainPrefixedKey directly in declarative validation instead of this manual validation.
	// The required-value and label-key format checks are already performed by declarative validation.
	// This handwritten validation is STRICTER: it additionally enforces the domain-prefix separator ("/"),
	// which declarative label-key validation does not cover. We only fire it when the key is otherwise a
	// valid label key so we do not double-emit the format error already reported by declarative.
	allErrs = append(allErrs, validateDomainPrefixSeparator(fldPath.Child("id"), condition.ID)...)
	allErrs = append(allErrs, validateDomainPrefixSeparator(fldPath.Child("type"), condition.Type)...)

	if l := len(condition.Condition); l > authorizer.MaxConditionBytes {
		allErrs = append(allErrs, field.TooLong(fldPath.Child("condition"), condition.Condition, authorizer.MaxConditionBytes).WithOrigin("maxBytes").MarkCoveredByDeclarative())
	}
	if l := len(condition.Description); l > authorizer.MaxConditionDescriptionBytes {
		allErrs = append(allErrs, field.TooLong(fldPath.Child("description"), condition.Description, authorizer.MaxConditionDescriptionBytes).WithOrigin("maxBytes").MarkCoveredByDeclarative())
	}

	return allErrs
}

// validateDomainPrefixSeparator asserts that key has a domain-prefix separator ("/"),
// but only when key is otherwise a valid label key. Empty keys and label-key format
// violations are handled by declarative validation and are skipped here to avoid
// emitting duplicate errors from handwritten and declarative validation.
func validateDomainPrefixSeparator(fldPath *field.Path, key string) field.ErrorList {
	if len(key) == 0 || len(content.IsLabelKey(key)) != 0 {
		return nil
	}
	if len(strings.Split(key, "/")) != 2 {
		return field.ErrorList{field.Invalid(fldPath, key, `must be a domain-prefixed key (such as "acme.io/foo")`)}
	}
	return nil
}

// ValidateSubjectAccessReviewCreate is the single composition of handwritten and declarative
// SubjectAccessReview validation.
func ValidateSubjectAccessReviewCreate(ctx context.Context, scheme *runtime.Scheme, sar *authorizationapi.SubjectAccessReview) field.ErrorList {
	errs := ValidateSubjectAccessReview(sar)
	dv := rest.DeclarativeValidation{Scheme: scheme}
	return dv.ValidateDeclaratively(ctx, sar, nil, errs, operation.Create, sarValidationConfig())
}

// ValidateSelfSubjectAccessReviewCreate is the single composition of handwritten and declarative
// SelfSubjectAccessReview validation.
func ValidateSelfSubjectAccessReviewCreate(ctx context.Context, scheme *runtime.Scheme, sar *authorizationapi.SelfSubjectAccessReview) field.ErrorList {
	errs := ValidateSelfSubjectAccessReview(sar)
	dv := rest.DeclarativeValidation{Scheme: scheme}
	return dv.ValidateDeclaratively(ctx, sar, nil, errs, operation.Create, sarValidationConfig())
}

// ValidateLocalSubjectAccessReviewCreate is the single composition of handwritten and declarative
// LocalSubjectAccessReview validation.
func ValidateLocalSubjectAccessReviewCreate(ctx context.Context, scheme *runtime.Scheme, sar *authorizationapi.LocalSubjectAccessReview) field.ErrorList {
	errs := ValidateLocalSubjectAccessReview(sar)
	dv := rest.DeclarativeValidation{Scheme: scheme}
	return dv.ValidateDeclaratively(ctx, sar, nil, errs, operation.Create, sarValidationConfig())
}

// ValidateAuthorizationConditionsReviewCreate is the single composition of handwritten and declarative
// AuthorizationConditionsReview validation.
func ValidateAuthorizationConditionsReviewCreate(ctx context.Context, scheme *runtime.Scheme, acr *authorizationapi.AuthorizationConditionsReview) field.ErrorList {
	errs := ValidateAuthorizationConditionsReview(acr)
	dv := rest.DeclarativeValidation{Scheme: scheme}
	return dv.ValidateDeclaratively(ctx, acr, nil, errs, operation.Create, sarValidationConfig())
}
