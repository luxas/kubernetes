package v1beta1

import (
	authorizationv1beta1 "k8s.io/api/authorization/v1beta1"
	conversion "k8s.io/apimachinery/pkg/conversion"
	authorization "k8s.io/kubernetes/pkg/apis/authorization"
)

func Convert_authorization_SubjectAccessReviewStatus_To_v1beta1_SubjectAccessReviewStatus(in *authorization.SubjectAccessReviewStatus, out *authorizationv1beta1.SubjectAccessReviewStatus, s conversion.Scope) error {
	// TODO: What to do if conditions are set in the internal type, but we want to convert to the v1beta1 type?
	// Error? Annotation? Add the field without a serialization tag?
	return autoConvert_authorization_SubjectAccessReviewStatus_To_v1beta1_SubjectAccessReviewStatus(in, out, s)
}
