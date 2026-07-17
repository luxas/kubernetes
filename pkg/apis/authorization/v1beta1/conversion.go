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

package v1beta1

import (
	fmt "fmt"
	"slices"

	authorizationv1beta1 "k8s.io/api/authorization/v1beta1"
	conversion "k8s.io/apimachinery/pkg/conversion"
	authorization "k8s.io/kubernetes/pkg/apis/authorization"
)

// unconditionalDecisionTypesSorted represents the default value of HandledDecisionTypes when AuthorizationOptions == nil
var unconditionalDecisionTypesSorted = []authorization.ConditionsAwareDecisionType{
	authorization.ConditionsAwareDecisionTypeAllow,
	authorization.ConditionsAwareDecisionTypeDeny,
	authorization.ConditionsAwareDecisionTypeNoOpinion,
}

func enforceUnconditionalHandledDecisionTypesOnly(ao *authorization.AuthorizationOptions) error {
	// if ao is set, the only allowed value is [Allow, Deny, NoOpinion], which is how callers should interpret
	// ao == nil. Anything else cannot be expressed in v1beta1, and thus error.
	if ao != nil {
		sortedDecisionTypes := slices.Sorted(slices.Values(ao.HandledDecisionTypes))
		if !slices.Equal(sortedDecisionTypes, unconditionalDecisionTypesSorted) {
			return fmt.Errorf("cannot send SubjectAccessReview with non-default AuthorizationOptions to a v1beta1 client. Got handledDecisionTypes %v, supported %v", ao.HandledDecisionTypes, unconditionalDecisionTypesSorted)
		}
	}
	return nil
}

// Convert_authorization_SelfSubjectAccessReviewSpec_To_v1beta1_SelfSubjectAccessReviewSpec explicitly does not propagate the AuthorizationOptions field to the v1beta1
// object; the conversion is thus lossy. However, this is ok, as SelfSubjectAccessReview objects are never stored.
func Convert_authorization_SelfSubjectAccessReviewSpec_To_v1beta1_SelfSubjectAccessReviewSpec(in *authorization.SelfSubjectAccessReviewSpec, out *authorizationv1beta1.SelfSubjectAccessReviewSpec, s conversion.Scope) error {
	if err := enforceUnconditionalHandledDecisionTypesOnly(in.AuthorizationOptions); err != nil {
		return err
	}
	return autoConvert_authorization_SelfSubjectAccessReviewSpec_To_v1beta1_SelfSubjectAccessReviewSpec(in, out, s)
}

// Convert_authorization_SubjectAccessReviewSpec_To_v1beta1_SubjectAccessReviewSpec explicitly does not propagate the AuthorizationOptions field to the v1beta1
// object; the conversion is thus lossy. However, this is ok, as {Local,}SubjectAccessReview objects are never stored.
func Convert_authorization_SubjectAccessReviewSpec_To_v1beta1_SubjectAccessReviewSpec(in *authorization.SubjectAccessReviewSpec, out *authorizationv1beta1.SubjectAccessReviewSpec, s conversion.Scope) error {
	if err := enforceUnconditionalHandledDecisionTypesOnly(in.AuthorizationOptions); err != nil {
		return err
	}
	return autoConvert_authorization_SubjectAccessReviewSpec_To_v1beta1_SubjectAccessReviewSpec(in, out, s)
}

// Convert_authorization_SubjectAccessReviewStatus_To_v1beta1_SubjectAccessReviewStatus explicitly does not propagate the ConditionalDecision field to the v1beta1
// object; the conversion is thus lossy. However, this is ok, as {Local,Self,}SubjectAccessReview objects are never stored.
func Convert_authorization_SubjectAccessReviewStatus_To_v1beta1_SubjectAccessReviewStatus(in *authorization.SubjectAccessReviewStatus, out *authorizationv1beta1.SubjectAccessReviewStatus, s conversion.Scope) error {
	// in.ConditionalDecision is not present (thus always implicitly nil) in v1beta1, ensure that the field either can be dropped (if it's covered by in.Allowed and in.Denied), or reject with an error.
	if in.ConditionalDecision != nil {
		switch in.ConditionalDecision.Type {
		case authorization.ConditionsAwareDecisionTypeDeny:
			if !(in.Allowed == false && in.Denied == true) { // assert against true/false explicitly for readability
				return fmt.Errorf("inconsistent input object, got in.ConditionalDecision.Type=Deny, but in.Allowed=%t (expected false) and in.Denied=%t (expected true)", in.Allowed, in.Denied)
			}
		case authorization.ConditionsAwareDecisionTypeNoOpinion:
			if !(in.Allowed == false && in.Denied == false) {
				return fmt.Errorf("inconsistent input object, got in.ConditionalDecision.Type=Allow, but in.Allowed=%t (expected false) and in.Denied=%t (expected false)", in.Allowed, in.Denied)
			}
		case authorization.ConditionsAwareDecisionTypeAllow:
			if !(in.Allowed == true && in.Denied == false) {
				return fmt.Errorf("inconsistent input object, got in.ConditionalDecision.Type=Allow, but in.Allowed=%t (expected true) and in.Denied=%t (expected false)", in.Allowed, in.Denied)
			}
		default:
			return fmt.Errorf("cannot convert SubjectAccessReviewStatus to v1beta1, v1beta1 does not support in.ConditionalDecision.Type=%s", in.ConditionalDecision.Type)
		}
	}

	return autoConvert_authorization_SubjectAccessReviewStatus_To_v1beta1_SubjectAccessReviewStatus(in, out, s)
}
