package v1alpha1

import (
	unsafe "unsafe"

	admissionv1 "k8s.io/api/admission/v1"
	authorizationv1alpha1 "k8s.io/api/authorization/v1alpha1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/kubernetes/pkg/apis/admission"
	admissionv1internal "k8s.io/kubernetes/pkg/apis/admission/v1"
	authorization "k8s.io/kubernetes/pkg/apis/authorization"
	authorizationv1internal "k8s.io/kubernetes/pkg/apis/authorization/v1"
)

func Convert_v1alpha1_AuthorizationConditionsRequest_To_authorization_AuthorizationConditionsRequest(in *authorizationv1alpha1.AuthorizationConditionsRequest, out *authorization.AuthorizationConditionsRequest, s conversion.Scope) error {
	if err := authorizationv1internal.Convert_v1_ConditionsAwareDecision_To_authorization_ConditionsAwareDecision(&in.Decision, &out.Decision, s); err != nil {
		return err
	}
	if in.AdmissionRequest != nil {
		in, out := &in.AdmissionRequest, &out.AdmissionRequest
		*out = new(admission.AdmissionRequest)
		if err := admissionv1internal.Convert_v1_AdmissionRequest_To_admission_AdmissionRequest(*in, *out, s); err != nil {
			return err
		}
	} else {
		out.AdmissionRequest = nil
	}
	return nil
}

func Convert_authorization_AuthorizationConditionsRequest_To_v1alpha1_AuthorizationConditionsRequest(in *authorization.AuthorizationConditionsRequest, out *authorizationv1alpha1.AuthorizationConditionsRequest, s conversion.Scope) error {
	if err := authorizationv1internal.Convert_authorization_ConditionsAwareDecision_To_v1_ConditionsAwareDecision(&in.Decision, &out.Decision, s); err != nil {
		return err
	}
	if in.AdmissionRequest != nil {
		in, out := &in.AdmissionRequest, &out.AdmissionRequest
		*out = new(admissionv1.AdmissionRequest)
		if err := admissionv1internal.Convert_admission_AdmissionRequest_To_v1_AdmissionRequest(*in, *out, s); err != nil {
			return err
		}
	} else {
		out.AdmissionRequest = nil
	}
	return nil
}

func Convert_v1alpha1_AuthorizationConditionsResponse_To_authorization_AuthorizationConditionsResponse(in *authorizationv1alpha1.AuthorizationConditionsResponse, out *authorization.AuthorizationConditionsResponse, s conversion.Scope) error {
	*out = *(*authorization.AuthorizationConditionsResponse)(unsafe.Pointer(in))
	return nil
}

func Convert_authorization_AuthorizationConditionsResponse_To_v1alpha1_AuthorizationConditionsResponse(in *authorization.AuthorizationConditionsResponse, out *authorizationv1alpha1.AuthorizationConditionsResponse, s conversion.Scope) error {
	*out = *(*authorizationv1alpha1.AuthorizationConditionsResponse)(unsafe.Pointer(in))
	return nil
}
