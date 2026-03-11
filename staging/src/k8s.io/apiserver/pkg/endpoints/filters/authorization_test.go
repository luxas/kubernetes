/*
Copyright 2016 The Kubernetes Authors.

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

package filters

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"

	"github.com/stretchr/testify/assert"

	batch "k8s.io/api/batch/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	auditinternal "k8s.io/apiserver/pkg/apis/audit"
	"k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
	genericfeatures "k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
)

func TestGetAuthorizerAttributes(t *testing.T) {
	basicLabelRequirement, err := labels.NewRequirement("foo", selection.DoubleEquals, []string{"bar"})
	if err != nil {
		t.Fatal(err)
	}

	testcases := map[string]struct {
		Verb               string
		Path               string
		ExpectedAttributes *authorizer.AttributesRecord
	}{
		"non-resource root": {
			Verb: http.MethodPost,
			Path: "/",
			ExpectedAttributes: &authorizer.AttributesRecord{
				Verb: "post",
				Path: "/",
			},
		},
		"non-resource api prefix": {
			Verb: http.MethodGet,
			Path: "/api/",
			ExpectedAttributes: &authorizer.AttributesRecord{
				Verb: "get",
				Path: "/api/",
			},
		},
		"non-resource group api prefix": {
			Verb: http.MethodGet,
			Path: "/apis/extensions/",
			ExpectedAttributes: &authorizer.AttributesRecord{
				Verb: "get",
				Path: "/apis/extensions/",
			},
		},

		"resource": {
			Verb: http.MethodPost,
			Path: "/api/v1/nodes/mynode",
			ExpectedAttributes: &authorizer.AttributesRecord{
				Verb:            "create",
				Path:            "/api/v1/nodes/mynode",
				ResourceRequest: true,
				Resource:        "nodes",
				APIVersion:      "v1",
				Name:            "mynode",
			},
		},
		"namespaced resource": {
			Verb: http.MethodPut,
			Path: "/api/v1/namespaces/myns/pods/mypod",
			ExpectedAttributes: &authorizer.AttributesRecord{
				Verb:            "update",
				Path:            "/api/v1/namespaces/myns/pods/mypod",
				ResourceRequest: true,
				Namespace:       "myns",
				Resource:        "pods",
				APIVersion:      "v1",
				Name:            "mypod",
			},
		},
		"API group resource": {
			Verb: http.MethodGet,
			Path: "/apis/batch/v1/namespaces/myns/jobs",
			ExpectedAttributes: &authorizer.AttributesRecord{
				Verb:            "list",
				Path:            "/apis/batch/v1/namespaces/myns/jobs",
				ResourceRequest: true,
				APIGroup:        batch.GroupName,
				APIVersion:      "v1",
				Namespace:       "myns",
				Resource:        "jobs",
			},
		},
		"disabled, ignore good field selector": {
			Verb: http.MethodGet,
			Path: "/apis/batch/v1/namespaces/myns/jobs?fieldSelector%=foo%3Dbar",
			ExpectedAttributes: &authorizer.AttributesRecord{
				Verb:            "list",
				Path:            "/apis/batch/v1/namespaces/myns/jobs",
				ResourceRequest: true,
				APIGroup:        batch.GroupName,
				APIVersion:      "v1",
				Namespace:       "myns",
				Resource:        "jobs",
			},
		},
		"enabled, good field selector": {
			Verb: http.MethodGet,
			Path: "/apis/batch/v1/namespaces/myns/jobs?fieldSelector=foo%3D%3Dbar",
			ExpectedAttributes: &authorizer.AttributesRecord{
				Verb:            "list",
				Path:            "/apis/batch/v1/namespaces/myns/jobs",
				ResourceRequest: true,
				APIGroup:        batch.GroupName,
				APIVersion:      "v1",
				Namespace:       "myns",
				Resource:        "jobs",
				FieldSelectorRequirements: fields.Requirements{
					fields.OneTermEqualSelector("foo", "bar").Requirements()[0],
				},
			},
		},
		"enabled, bad field selector": {
			Verb: http.MethodGet,
			Path: "/apis/batch/v1/namespaces/myns/jobs?fieldSelector=%2Abar",
			ExpectedAttributes: &authorizer.AttributesRecord{
				Verb:                    "list",
				Path:                    "/apis/batch/v1/namespaces/myns/jobs",
				ResourceRequest:         true,
				APIGroup:                batch.GroupName,
				APIVersion:              "v1",
				Namespace:               "myns",
				Resource:                "jobs",
				FieldSelectorParsingErr: errors.New("invalid selector: '*bar'; can't understand '*bar'"),
			},
		},
		"disabled, ignore good label selector": {
			Verb: http.MethodGet,
			Path: "/apis/batch/v1/namespaces/myns/jobs?labelSelector%=foo%3Dbar",
			ExpectedAttributes: &authorizer.AttributesRecord{
				Verb:            "list",
				Path:            "/apis/batch/v1/namespaces/myns/jobs",
				ResourceRequest: true,
				APIGroup:        batch.GroupName,
				APIVersion:      "v1",
				Namespace:       "myns",
				Resource:        "jobs",
			},
		},
		"enabled, good label selector": {
			Verb: http.MethodGet,
			Path: "/apis/batch/v1/namespaces/myns/jobs?labelSelector=foo%3D%3Dbar",
			ExpectedAttributes: &authorizer.AttributesRecord{
				Verb:            "list",
				Path:            "/apis/batch/v1/namespaces/myns/jobs",
				ResourceRequest: true,
				APIGroup:        batch.GroupName,
				APIVersion:      "v1",
				Namespace:       "myns",
				Resource:        "jobs",
				LabelSelectorRequirements: labels.Requirements{
					*basicLabelRequirement,
				},
			},
		},
		"enabled, bad label selector": {
			Verb: http.MethodGet,
			Path: "/apis/batch/v1/namespaces/myns/jobs?labelSelector=%2Abar",
			ExpectedAttributes: &authorizer.AttributesRecord{
				Verb:                    "list",
				Path:                    "/apis/batch/v1/namespaces/myns/jobs",
				ResourceRequest:         true,
				APIGroup:                batch.GroupName,
				APIVersion:              "v1",
				Namespace:               "myns",
				Resource:                "jobs",
				LabelSelectorParsingErr: errors.New("unable to parse requirement: <nil>: Invalid value: \"*bar\": name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')"),
			},
		},
	}

	for k, tc := range testcases {
		t.Run(k, func(t *testing.T) {
			ctx := t.Context()

			req, _ := http.NewRequestWithContext(ctx, tc.Verb, tc.Path, nil)
			req.RemoteAddr = "127.0.0.1"

			var attribs authorizer.Attributes
			var err error
			var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				ctx := req.Context()
				attribs, err = GetAuthorizerAttributes(ctx)
			})
			handler = WithRequestInfo(handler, newTestRequestInfoResolver())
			handler.ServeHTTP(httptest.NewRecorder(), req)

			if err != nil {
				t.Errorf("%s: unexpected error: %v", k, err)
			} else if !reflect.DeepEqual(attribs, tc.ExpectedAttributes) {
				t.Errorf("%s: expected\n\t%#v\ngot\n\t%#v", k, tc.ExpectedAttributes, attribs)
			}
		})
	}
}

type fakeAuthorizer struct {
	decision authorizer.Decision
	reason   string
	err      error
}

func (f fakeAuthorizer) Authorize(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
	return f.decision, f.reason, f.err
}

// AuthorizeConditionsAware is not conditions-aware, converts the Authorize decision.
func (f fakeAuthorizer) AuthorizeConditionsAware(ctx context.Context, a authorizer.Attributes, _ authorizer.ConditionsEncodingPreference) authorizer.ConditionsAwareDecision {
	return authorizer.ConditionsAwareDecisionFromParts(f.Authorize(ctx, a))
}

// EvaluateConditions is not supported by this authorizer.
func (fakeAuthorizer) EvaluateConditions(_ context.Context, _ authorizer.ConditionsAwareDecision, _ authorizer.ConditionsData, _ authorizer.BuiltinConditionsMapEvaluators) authorizer.ConditionsAwareDecision {
	return authorizer.ConditionsAwareDecisionDeny("", authorizer.ErrorConditionEvaluationNotSupported)
}

func TestAuditAnnotation(t *testing.T) {
	testcases := map[string]struct {
		authorizer         fakeAuthorizer
		decisionAnnotation string
		reasonAnnotation   string
	}{
		"decision allow": {
			fakeAuthorizer{
				authorizer.DecisionAllow,
				"RBAC: allowed to patch pod",
				nil,
			},
			"allow",
			"RBAC: allowed to patch pod",
		},
		"decision forbid": {
			fakeAuthorizer{
				authorizer.DecisionDeny,
				"RBAC: not allowed to patch pod",
				nil,
			},
			"forbid",
			"RBAC: not allowed to patch pod",
		},
		"error": {
			fakeAuthorizer{
				authorizer.DecisionNoOpinion,
				"",
				errors.New("can't parse user info"),
			},
			"",
			reasonError,
		},
	}

	scheme := runtime.NewScheme()
	negotiatedSerializer := serializer.NewCodecFactory(scheme).WithoutConversion()
	for k, tc := range testcases {
		ctx := t.Context()
		handler := WithAuthorization(&fakeHTTPHandler{}, tc.authorizer, negotiatedSerializer)
		// TODO: fake audit injector

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/api/v1/namespaces/default/pods", nil)
		req = withTestContext(req, nil, &auditinternal.Event{Level: auditinternal.LevelMetadata})
		ae := audit.AuditContextFrom(req.Context())
		req.RemoteAddr = "127.0.0.1"
		handler.ServeHTTP(httptest.NewRecorder(), req)

		var annotation string
		var ok bool
		if len(tc.decisionAnnotation) > 0 {
			annotation, ok = ae.GetEventAnnotation(decisionAnnotationKey)
			assert.True(t, ok, k+": decision annotation not found")
			assert.Equal(t, tc.decisionAnnotation, annotation, k+": unexpected decision annotation")
		}

		annotation, ok = ae.GetEventAnnotation(reasonAnnotationKey)
		assert.True(t, ok, k+": reason annotation not found")
		assert.Equal(t, tc.reasonAnnotation, annotation, k+": unexpected reason annotation")
	}

}

// conditionsAwareFakeAuthorizer allows returning arbitrary ConditionsAwareDecision values.
type conditionsAwareFakeAuthorizer struct {
	makeDecision func() authorizer.ConditionsAwareDecision
}

func (f *conditionsAwareFakeAuthorizer) Authorize(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
	return authorizer.DecisionPartsFromConditionsAware(f.AuthorizeConditionsAware(ctx, a, authorizer.ConditionsEncodingPreferenceOptimized()))
}

func (f *conditionsAwareFakeAuthorizer) AuthorizeConditionsAware(_ context.Context, _ authorizer.Attributes, _ authorizer.ConditionsEncodingPreference) authorizer.ConditionsAwareDecision {
	return f.makeDecision()
}

func (f *conditionsAwareFakeAuthorizer) EvaluateConditions(_ context.Context, _ authorizer.ConditionsAwareDecision, _ authorizer.ConditionsData, _ authorizer.BuiltinConditionsMapEvaluators) authorizer.ConditionsAwareDecision {
	return authorizer.ConditionsAwareDecisionDeny("", authorizer.ErrorConditionEvaluationNotSupported)
}

func TestWithAuthorization(t *testing.T) {
	scheme := runtime.NewScheme()
	negotiatedSerializer := serializer.NewCodecFactory(scheme).WithoutConversion()

	makeCondMapAllowDecision := func(err error) func() authorizer.ConditionsAwareDecision {
		return func() authorizer.ConditionsAwareDecision {
			return authorizer.ConditionsAwareDecisionConditionMap(
				authorizer.ConditionsTargetAdmissionControl,
				authorizer.ConditionType("cel"),
				maps.All(map[string]authorizer.Condition{
					"c1": {Condition: "object.metadata.name == 'foo'", Effect: authorizer.ConditionEffectAllow},
				}),
				"conditional", err,
			)
		}
	}

	makeCondMapDenyOnlyDecision := func() authorizer.ConditionsAwareDecision {
		return authorizer.ConditionsAwareDecisionConditionMap(
			authorizer.ConditionsTargetAdmissionControl,
			authorizer.ConditionType("cel"),
			maps.All(map[string]authorizer.Condition{
				"c1": {Condition: "object.metadata.name == 'bar'", Effect: authorizer.ConditionEffectDeny},
			}),
			"deny-only-cond", nil,
		)
	}

	classifierAlwaysTrue := ConditionalAuthorizationRequestClassifier(func(_ authorizer.Attributes) bool { return true })
	classifierAlwaysFalse := ConditionalAuthorizationRequestClassifier(func(_ authorizer.Attributes) bool { return false })

	type expectedOutcome struct {
		statusCode           int
		handlerCalled        bool
		decisionAnnotation   string
		reasonAnnotation     string
		conditionalInContext bool
	}

	tests := []struct {
		name                       string
		authorizer                 authorizer.Authorizer
		conditionalAuthzClassifier ConditionalAuthorizationRequestClassifier
		disabled                   expectedOutcome
		enabled                    expectedOutcome
	}{
		{
			name:       "nil authorizer passes through",
			authorizer: nil,
			disabled:   expectedOutcome{statusCode: http.StatusOK, handlerCalled: true},
			enabled:    expectedOutcome{statusCode: http.StatusOK, handlerCalled: true},
		},
		{
			name:       "allow",
			authorizer: fakeAuthorizer{authorizer.DecisionAllow, "RBAC: allowed", nil},
			disabled:   expectedOutcome{statusCode: http.StatusOK, handlerCalled: true, decisionAnnotation: decisionAllow, reasonAnnotation: "RBAC: allowed"},
			enabled:    expectedOutcome{statusCode: http.StatusOK, handlerCalled: true, decisionAnnotation: decisionAllow, reasonAnnotation: "RBAC: allowed"},
		},
		{
			name:       "deny",
			authorizer: fakeAuthorizer{authorizer.DecisionDeny, "RBAC: denied", nil},
			disabled:   expectedOutcome{statusCode: http.StatusForbidden, decisionAnnotation: decisionForbid, reasonAnnotation: "RBAC: denied"},
			enabled:    expectedOutcome{statusCode: http.StatusForbidden, decisionAnnotation: decisionForbid, reasonAnnotation: "RBAC: denied"},
		},
		{
			name:       "no opinion with error",
			authorizer: fakeAuthorizer{authorizer.DecisionNoOpinion, "", errors.New("webhook error")},
			disabled:   expectedOutcome{statusCode: http.StatusInternalServerError, reasonAnnotation: reasonError},
			enabled:    expectedOutcome{statusCode: http.StatusInternalServerError, reasonAnnotation: reasonError},
		},
		{
			name:       "no opinion without error",
			authorizer: fakeAuthorizer{authorizer.DecisionNoOpinion, "no match", nil},
			disabled:   expectedOutcome{statusCode: http.StatusForbidden, decisionAnnotation: decisionForbid, reasonAnnotation: "no match"},
			enabled:    expectedOutcome{statusCode: http.StatusForbidden, decisionAnnotation: decisionForbid, reasonAnnotation: "no match"},
		},
		{
			name: "conditional allow + classifier true",
			authorizer: &conditionsAwareFakeAuthorizer{
				makeDecision: makeCondMapAllowDecision(fmt.Errorf("eval-note")),
			},
			conditionalAuthzClassifier: classifierAlwaysTrue,
			// gate off: condMap constructor fail-closes with non-nil error => 500
			// TODO(luxas): Do we want to "fail softer" in DecisionPartsFromConditionsAware when failing closed?
			disabled: expectedOutcome{statusCode: http.StatusInternalServerError, reasonAnnotation: reasonError},
			// gate on: CanBecomeAllowed=true, classifier=true => conditional path
			enabled: expectedOutcome{statusCode: http.StatusOK, handlerCalled: true, decisionAnnotation: decisionConditional, reasonAnnotation: "conditional", conditionalInContext: true},
		},
		{
			name: "conditional allow + classifier false",
			authorizer: &conditionsAwareFakeAuthorizer{
				makeDecision: makeCondMapAllowDecision(nil),
			},
			conditionalAuthzClassifier: classifierAlwaysFalse,
			// gate off: condMap constructor fail-closes with non-nil error => 500
			disabled: expectedOutcome{statusCode: http.StatusInternalServerError, reasonAnnotation: reasonError},
			// gate on: classifier rejects, err=nil => forbidden
			enabled: expectedOutcome{statusCode: http.StatusForbidden, decisionAnnotation: decisionForbid, reasonAnnotation: "conditional"},
		},
		{
			name: "conditional allow + classifier nil",
			authorizer: &conditionsAwareFakeAuthorizer{
				makeDecision: makeCondMapAllowDecision(nil),
			},
			conditionalAuthzClassifier: nil,
			// gate off: condMap constructor fail-closes with non-nil error => 500
			disabled: expectedOutcome{statusCode: http.StatusInternalServerError, reasonAnnotation: reasonError},
			// gate on: no classifier, err=nil => forbidden
			enabled: expectedOutcome{statusCode: http.StatusForbidden, decisionAnnotation: decisionForbid, reasonAnnotation: "conditional"},
		},
		{
			name: "conditional deny-only + classifier true",
			authorizer: &conditionsAwareFakeAuthorizer{
				makeDecision: makeCondMapDenyOnlyDecision,
			},
			conditionalAuthzClassifier: classifierAlwaysTrue,
			// gate off: condMap constructor fail-closes (hasDenyEffect=true) with non-nil error => 500
			disabled: expectedOutcome{statusCode: http.StatusInternalServerError, reasonAnnotation: reasonError},
			// gate on: CanBecomeAllowed=false, err=nil => forbidden
			enabled: expectedOutcome{statusCode: http.StatusForbidden, decisionAnnotation: decisionForbid, reasonAnnotation: "deny-only-cond"},
		},
		{
			name: "no opinion with error (conditions-aware)",
			authorizer: &conditionsAwareFakeAuthorizer{
				makeDecision: func() authorizer.ConditionsAwareDecision {
					return authorizer.ConditionsAwareDecisionNoOpinion("", fmt.Errorf("internal issue"))
				},
			},
			disabled: expectedOutcome{statusCode: http.StatusInternalServerError, reasonAnnotation: reasonError},
			enabled:  expectedOutcome{statusCode: http.StatusInternalServerError, reasonAnnotation: reasonError},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, mode := range []struct {
				name string
				gate bool
				want expectedOutcome
			}{
				{"disabled", false, tt.disabled},
				{"enabled", true, tt.enabled},
			} {
				t.Run(mode.name, func(t *testing.T) {
					if mode.gate {
						featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, genericfeatures.ConditionalAuthorization, true)
					}

					handlerCalled := false
					var gotConditionalDecision bool

					innerHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						handlerCalled = true
						_, gotConditionalDecision = request.ConditionallyAuthorizedDecisionsFrom(req.Context())
						w.WriteHeader(http.StatusOK)
					})

					noopMetrics := func(_ context.Context, _ string, _, _ time.Time) {}
					handler := withAuthorization(innerHandler, tt.authorizer, negotiatedSerializer, noopMetrics, tt.conditionalAuthzClassifier)

					req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/namespaces/default/pods", nil)
					req = withTestContext(req, nil, &auditinternal.Event{Level: auditinternal.LevelMetadata})
					req.RemoteAddr = "127.0.0.1"

					recorder := httptest.NewRecorder()
					handler.ServeHTTP(recorder, req)

					if recorder.Code != mode.want.statusCode {
						t.Errorf("status code = %d, want %d", recorder.Code, mode.want.statusCode)
					}
					if handlerCalled != mode.want.handlerCalled {
						t.Errorf("handler called = %v, want %v", handlerCalled, mode.want.handlerCalled)
					}

					ae := audit.AuditContextFrom(req.Context())
					if mode.want.decisionAnnotation != "" {
						annotation, ok := ae.GetEventAnnotation(decisionAnnotationKey)
						if !ok {
							t.Errorf("decision annotation not found, expected %q", mode.want.decisionAnnotation)
						} else if annotation != mode.want.decisionAnnotation {
							t.Errorf("decision annotation = %q, want %q", annotation, mode.want.decisionAnnotation)
						}
					}
					if mode.want.reasonAnnotation != "" {
						annotation, ok := ae.GetEventAnnotation(reasonAnnotationKey)
						if !ok {
							t.Errorf("reason annotation not found, expected %q", mode.want.reasonAnnotation)
						} else if annotation != mode.want.reasonAnnotation {
							t.Errorf("reason annotation = %q, want %q", annotation, mode.want.reasonAnnotation)
						}
					}
					if mode.want.conditionalInContext != gotConditionalDecision {
						t.Errorf("conditional decision in context = %v, want %v", gotConditionalDecision, mode.want.conditionalInContext)
					}
				})
			}
		})
	}
}
