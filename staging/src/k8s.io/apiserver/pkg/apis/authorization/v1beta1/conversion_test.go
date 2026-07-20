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
	"testing"

	"github.com/google/go-cmp/cmp"

	authorizationv1 "k8s.io/api/authorization/v1"
	authorizationv1beta1 "k8s.io/api/authorization/v1beta1"
)

func TestEnforceUnconditionalHandledDecisionTypesOnly(t *testing.T) {
	tests := []struct {
		name    string
		ao      *authorizationv1.AuthorizationOptions
		wantErr bool
	}{
		{
			name:    "nil accepted (default unconditional)",
			ao:      nil,
			wantErr: false,
		},
		{
			name: "exact unconditional set accepted",
			ao: &authorizationv1.AuthorizationOptions{
				HandledDecisionTypes: []authorizationv1.ConditionsAwareDecisionType{
					authorizationv1.ConditionsAwareDecisionTypeAllow,
					authorizationv1.ConditionsAwareDecisionTypeDeny,
					authorizationv1.ConditionsAwareDecisionTypeNoOpinion,
				},
			},
			wantErr: false,
		},
		{
			name: "empty HandledDecisionTypes rejected",
			ao: &authorizationv1.AuthorizationOptions{
				HandledDecisionTypes: []authorizationv1.ConditionsAwareDecisionType{},
			},
			wantErr: true,
		},
		{
			name: "missing NoOpinion rejected",
			ao: &authorizationv1.AuthorizationOptions{
				HandledDecisionTypes: []authorizationv1.ConditionsAwareDecisionType{
					authorizationv1.ConditionsAwareDecisionTypeAllow,
					authorizationv1.ConditionsAwareDecisionTypeDeny,
				},
			},
			wantErr: true,
		},
		{
			name: "extra ConditionsMap type rejected",
			ao: &authorizationv1.AuthorizationOptions{
				HandledDecisionTypes: []authorizationv1.ConditionsAwareDecisionType{
					authorizationv1.ConditionsAwareDecisionTypeAllow,
					authorizationv1.ConditionsAwareDecisionTypeDeny,
					authorizationv1.ConditionsAwareDecisionTypeNoOpinion,
					authorizationv1.ConditionsAwareDecisionTypeConditionsMap,
				},
			},
			wantErr: true,
		},
		{
			name: "full conditional set rejected",
			ao: &authorizationv1.AuthorizationOptions{
				HandledDecisionTypes: []authorizationv1.ConditionsAwareDecisionType{
					authorizationv1.ConditionsAwareDecisionTypeAllow,
					authorizationv1.ConditionsAwareDecisionTypeDeny,
					authorizationv1.ConditionsAwareDecisionTypeNoOpinion,
					authorizationv1.ConditionsAwareDecisionTypeConditionsMap,
					authorizationv1.ConditionsAwareDecisionTypeUnion,
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := EnforceUnconditionalHandledDecisionTypesOnly(tt.ao)
			if (err != nil) != tt.wantErr {
				t.Errorf("EnforceUnconditionalHandledDecisionTypesOnly() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConvert_v1_SelfSubjectAccessReviewSpec_To_v1beta1_SelfSubjectAccessReviewSpec(t *testing.T) {
	unconditional := &authorizationv1.AuthorizationOptions{
		HandledDecisionTypes: []authorizationv1.ConditionsAwareDecisionType{
			authorizationv1.ConditionsAwareDecisionTypeAllow,
			authorizationv1.ConditionsAwareDecisionTypeDeny,
			authorizationv1.ConditionsAwareDecisionTypeNoOpinion,
		},
	}
	conditional := &authorizationv1.AuthorizationOptions{
		HandledDecisionTypes: []authorizationv1.ConditionsAwareDecisionType{
			authorizationv1.ConditionsAwareDecisionTypeAllow,
			authorizationv1.ConditionsAwareDecisionTypeDeny,
			authorizationv1.ConditionsAwareDecisionTypeNoOpinion,
			authorizationv1.ConditionsAwareDecisionTypeConditionsMap,
			authorizationv1.ConditionsAwareDecisionTypeUnion,
		},
	}
	resourceAttrs := &authorizationv1.ResourceAttributes{
		Namespace: "ns", Verb: "get", Resource: "pods",
	}
	tests := []struct {
		name    string
		in      authorizationv1.SelfSubjectAccessReviewSpec
		want    authorizationv1beta1.SelfSubjectAccessReviewSpec
		wantErr bool
	}{
		{
			name: "nil AuthorizationOptions converts and drops nothing meaningful",
			in: authorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: resourceAttrs,
			},
			want: authorizationv1beta1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: (*authorizationv1beta1.ResourceAttributes)(&authorizationv1beta1.ResourceAttributes{
					Namespace: "ns", Verb: "get", Resource: "pods",
				}),
			},
		},
		{
			name: "unconditional AuthorizationOptions converts (AuthorizationOptions dropped)",
			in: authorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes:   resourceAttrs,
				AuthorizationOptions: unconditional,
			},
			want: authorizationv1beta1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: (*authorizationv1beta1.ResourceAttributes)(&authorizationv1beta1.ResourceAttributes{
					Namespace: "ns", Verb: "get", Resource: "pods",
				}),
			},
		},
		{
			name: "conditional AuthorizationOptions rejected",
			in: authorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes:   resourceAttrs,
				AuthorizationOptions: conditional,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got authorizationv1beta1.SelfSubjectAccessReviewSpec
			err := Convert_v1_SelfSubjectAccessReviewSpec_To_v1beta1_SelfSubjectAccessReviewSpec(&tt.in, &got, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("unexpected out (-want +got):\n%s", diff)
			}
		})
	}
}

func TestConvert_v1_SubjectAccessReviewSpec_To_v1beta1_SubjectAccessReviewSpec(t *testing.T) {
	unconditional := &authorizationv1.AuthorizationOptions{
		HandledDecisionTypes: []authorizationv1.ConditionsAwareDecisionType{
			authorizationv1.ConditionsAwareDecisionTypeAllow,
			authorizationv1.ConditionsAwareDecisionTypeDeny,
			authorizationv1.ConditionsAwareDecisionTypeNoOpinion,
		},
	}
	conditional := &authorizationv1.AuthorizationOptions{
		HandledDecisionTypes: []authorizationv1.ConditionsAwareDecisionType{
			authorizationv1.ConditionsAwareDecisionTypeAllow,
			authorizationv1.ConditionsAwareDecisionTypeDeny,
			authorizationv1.ConditionsAwareDecisionTypeNoOpinion,
			authorizationv1.ConditionsAwareDecisionTypeUnion,
		},
	}
	tests := []struct {
		name    string
		in      authorizationv1.SubjectAccessReviewSpec
		want    authorizationv1beta1.SubjectAccessReviewSpec
		wantErr bool
	}{
		{
			name: "nil AuthorizationOptions propagates all other fields",
			in: authorizationv1.SubjectAccessReviewSpec{
				User:   "alice",
				Groups: []string{"admins", "devs"},
				Extra:  map[string]authorizationv1.ExtraValue{"scope": {"read", "write"}},
				UID:    "uid-1",
			},
			want: authorizationv1beta1.SubjectAccessReviewSpec{
				User:   "alice",
				Groups: []string{"admins", "devs"},
				Extra:  map[string]authorizationv1beta1.ExtraValue{"scope": {"read", "write"}},
				UID:    "uid-1",
			},
		},
		{
			name: "unconditional AuthorizationOptions accepted and dropped",
			in: authorizationv1.SubjectAccessReviewSpec{
				User:                 "bob",
				AuthorizationOptions: unconditional,
			},
			want: authorizationv1beta1.SubjectAccessReviewSpec{
				User: "bob",
			},
		},
		{
			name: "conditional AuthorizationOptions rejected",
			in: authorizationv1.SubjectAccessReviewSpec{
				User:                 "carol",
				AuthorizationOptions: conditional,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got authorizationv1beta1.SubjectAccessReviewSpec
			err := Convert_v1_SubjectAccessReviewSpec_To_v1beta1_SubjectAccessReviewSpec(&tt.in, &got, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("unexpected out (-want +got):\n%s", diff)
			}
		})
	}
}

func TestConvert_v1_SubjectAccessReviewStatus_To_v1beta1_SubjectAccessReviewStatus(t *testing.T) {
	tests := []struct {
		name    string
		in      authorizationv1.SubjectAccessReviewStatus
		want    authorizationv1beta1.SubjectAccessReviewStatus
		wantErr bool
	}{
		{
			name: "unconditional allow propagates",
			in: authorizationv1.SubjectAccessReviewStatus{
				Allowed: true,
				Reason:  "rbac: role/x allowed",
			},
			want: authorizationv1beta1.SubjectAccessReviewStatus{
				Allowed: true,
				Reason:  "rbac: role/x allowed",
			},
		},
		{
			name: "unconditional deny propagates with EvaluationError",
			in: authorizationv1.SubjectAccessReviewStatus{
				Denied:          true,
				Reason:          "webhook: denied",
				EvaluationError: "flaky evaluator",
			},
			want: authorizationv1beta1.SubjectAccessReviewStatus{
				Denied:          true,
				Reason:          "webhook: denied",
				EvaluationError: "flaky evaluator",
			},
		},
		{
			name: "non-nil ConditionalDecision rejected",
			in: authorizationv1.SubjectAccessReviewStatus{
				ConditionalDecision: &authorizationv1.ConditionsAwareDecision{
					Type: authorizationv1.ConditionsAwareDecisionTypeConditionsMap,
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got authorizationv1beta1.SubjectAccessReviewStatus
			err := Convert_v1_SubjectAccessReviewStatus_To_v1beta1_SubjectAccessReviewStatus(&tt.in, &got, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("unexpected out (-want +got):\n%s", diff)
			}
		})
	}
}
