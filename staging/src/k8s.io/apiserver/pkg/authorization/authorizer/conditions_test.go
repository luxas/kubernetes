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

package authorizer_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"testing"

	"github.com/google/cel-go/cel"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	genericfeatures "k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
)

// unionDecision builds a ConditionsAwareDecisionUnion from the given decisions, assigning each
// a synthetic authorizerName ("0", "1", ...), and returns the equivalent ConditionsAwareDecision.
// It is a thin shim over the public Add + ToDecision API to keep the existing test cases readable.
func unionDecision(decisions ...authorizer.ConditionsAwareDecision) authorizer.ConditionsAwareDecision {
	var u authorizer.ConditionsAwareDecisionUnion
	for i, d := range decisions {
		u.Add(strconv.Itoa(i), d)
	}
	return u.ToDecision()
}

func TestConditionsAwareDecision(t *testing.T) {
	unexpectedErr := fmt.Errorf("unexpected things happened")
	otherErr := fmt.Errorf("other error")

	ctx := t.Context()
	sampleAttrs := authorizer.AttributesRecord{}

	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, genericfeatures.ConditionalAuthorization, true)

	makeConditionsSlice := func(conditionCount int) []authorizer.Condition {
		allowConditionList := make([]authorizer.Condition, conditionCount)
		for i := range conditionCount {
			allowConditionList[i] = authorizer.GenericCondition{ID: fmt.Sprintf("cond-%d", i)}
		}
		return allowConditionList
	}

	condMapAllow := authorizer.ConditionsAwareDecisionConditionsMap(
		nil, nil,
		[]authorizer.Condition{authorizer.GenericCondition{ID: "allow-cond", Condition: "something", Type: "test-type"}},
	)
	condMapDeny := authorizer.ConditionsAwareDecisionConditionsMap(
		[]authorizer.Condition{authorizer.GenericCondition{ID: "deny-cond", Condition: "something", Type: "test-type"}},
		nil, nil,
	)

	tests := []struct {
		name                    string
		testDecisions           []authorizer.ConditionsAwareDecision
		wantIsAllowed           bool
		wantIsNoOpinion         bool
		wantIsDeny              bool
		wantIsConditionsMap     bool
		wantIsUnion             bool
		wantIsUnconditional     bool
		wantFailClosedIsDeny    bool
		wantContainsAllowOrDeny bool
		wantReason              string
		wantAnyError            bool
		wantErrorIs             error
		wantString              string
	}{
		{
			name: "zero value",
			testDecisions: []authorizer.ConditionsAwareDecision{
				{},
				authorizer.ConditionsAwareDecisionFromParts(0, "", nil),
				authorizer.AuthorizerFunc(func(_ context.Context, _ authorizer.Attributes) (named1 authorizer.Decision, named2 string, named3 error) {
					return
				}).ConditionsAwareAuthorize(ctx, sampleAttrs),
			},
			wantIsDeny:              true,
			wantIsUnconditional:     true,
			wantContainsAllowOrDeny: true,
			wantFailClosedIsDeny:    true,
			wantReason:              "",
			wantErrorIs:             nil,
			wantString:              `Deny`,
		},
		{
			name: "deny constructor",
			testDecisions: []authorizer.ConditionsAwareDecision{
				authorizer.ConditionsAwareDecisionDeny("foo", unexpectedErr),
				authorizer.ConditionsAwareDecisionFromParts(authorizer.DecisionDeny, "foo", unexpectedErr),
				authorizer.AuthorizerFunc(func(_ context.Context, _ authorizer.Attributes) (authorizer.Decision, string, error) {
					return authorizer.DecisionDeny, "foo", unexpectedErr
				}).ConditionsAwareAuthorize(ctx, sampleAttrs),
			},
			wantIsDeny:              true,
			wantIsUnconditional:     true,
			wantContainsAllowOrDeny: true,
			wantFailClosedIsDeny:    true,
			wantReason:              "foo",
			wantErrorIs:             unexpectedErr,
			wantString:              `Deny(reason="foo", err="unexpected things happened")`,
		},
		{
			name: "allow constructor",
			testDecisions: []authorizer.ConditionsAwareDecision{
				authorizer.ConditionsAwareDecisionAllow("ok", nil),
				authorizer.ConditionsAwareDecisionFromParts(authorizer.DecisionAllow, "ok", nil),
				authorizer.AuthorizerFunc(func(_ context.Context, _ authorizer.Attributes) (authorizer.Decision, string, error) {
					return authorizer.DecisionAllow, "ok", nil
				}).ConditionsAwareAuthorize(ctx, sampleAttrs),
			},
			wantIsAllowed:           true,
			wantIsUnconditional:     true,
			wantContainsAllowOrDeny: true,
			wantReason:              "ok",
			wantErrorIs:             nil,
			wantString:              `Allow(reason="ok")`,
		},
		{
			name: "noopinion constructor",
			testDecisions: []authorizer.ConditionsAwareDecision{
				authorizer.ConditionsAwareDecisionNoOpinion("", nil),
				authorizer.ConditionsAwareDecisionFromParts(authorizer.DecisionNoOpinion, "", nil),
				authorizer.AuthorizerFunc(func(_ context.Context, _ authorizer.Attributes) (authorizer.Decision, string, error) {
					return authorizer.DecisionNoOpinion, "", nil
				}).ConditionsAwareAuthorize(ctx, sampleAttrs),
			},
			wantIsNoOpinion:     true,
			wantIsUnconditional: true,
			wantReason:          "",
			wantErrorIs:         nil,
			wantString:          `NoOpinion`,
		},
		{
			name: "from parts: unsupported mode",
			testDecisions: []authorizer.ConditionsAwareDecision{
				authorizer.ConditionsAwareDecisionFromParts(42, "", nil),
				authorizer.AuthorizerFunc(func(_ context.Context, _ authorizer.Attributes) (authorizer.Decision, string, error) {
					return 42, "", nil
				}).ConditionsAwareAuthorize(ctx, sampleAttrs),
			},
			wantIsDeny:              true,
			wantIsUnconditional:     true,
			wantContainsAllowOrDeny: true,
			wantFailClosedIsDeny:    true,
			wantReason:              "",
			wantAnyError:            true,
			wantString:              `Deny(err="unknown unconditional decision type: 42")`,
		},
		{
			name: "from parts: unsupported mode with other error",
			testDecisions: []authorizer.ConditionsAwareDecision{
				authorizer.ConditionsAwareDecisionFromParts(42, "foo", otherErr),
				authorizer.AuthorizerFunc(func(_ context.Context, _ authorizer.Attributes) (authorizer.Decision, string, error) {
					return 42, "foo", otherErr
				}).ConditionsAwareAuthorize(ctx, sampleAttrs),
			},
			wantIsDeny:              true,
			wantIsUnconditional:     true,
			wantContainsAllowOrDeny: true,
			wantFailClosedIsDeny:    true,
			wantReason:              "foo",
			wantErrorIs:             otherErr,
			wantString:              `Deny(reason="foo", err="[other error, unknown unconditional decision type: 42]")`,
		},
		{
			name: "construct valid conditionsmap",
			testDecisions: []authorizer.ConditionsAwareDecision{
				authorizer.ConditionsAwareDecisionConditionsMap(nil, nil, makeConditionsSlice(authorizer.MaxConditionsPerMap)),
			},
			wantIsConditionsMap: true,
			wantIsUnconditional: false,
			wantString:          `ConditionsMap(allows=128)`,
		},
		{
			name: "too many Allow conditions",
			testDecisions: []authorizer.ConditionsAwareDecision{
				authorizer.ConditionsAwareDecisionConditionsMap(nil, nil, makeConditionsSlice(authorizer.MaxConditionsPerMap+1)),
			},
			wantIsNoOpinion:     true,
			wantIsUnconditional: true,
			wantReason:          "failed closed",
			wantAnyError:        true,
			wantString:          `NoOpinion(reason="failed closed", err="too many conditions: 129 exceeds maximum of 128")`,
		},
		{
			name: "too many conditions, with one Deny",
			testDecisions: []authorizer.ConditionsAwareDecision{
				authorizer.ConditionsAwareDecisionConditionsMap([]authorizer.Condition{authorizer.GenericCondition{ID: "deny-cond"}}, nil, makeConditionsSlice(authorizer.MaxConditionsPerMap)),
			},
			wantIsDeny:              true,
			wantIsUnconditional:     true,
			wantFailClosedIsDeny:    true,
			wantContainsAllowOrDeny: true,
			wantReason:              "failed closed",
			wantAnyError:            true,
			wantString:              `Deny(reason="failed closed", err="too many conditions: 129 exceeds maximum of 128")`,
		},
		{
			name: "nil condition is a validation error",
			testDecisions: []authorizer.ConditionsAwareDecision{
				authorizer.ConditionsAwareDecisionConditionsMap(
					nil, nil,
					[]authorizer.Condition{
						authorizer.GenericCondition{ID: "foo"},
						nil,
					},
				),
				authorizer.ConditionsAwareDecisionConditionsMap(
					nil, nil,
					[]authorizer.Condition{
						authorizer.GenericCondition{ID: "foo"},
						typedNil(),
					},
				),
			},
			wantIsNoOpinion:     true,
			wantIsUnconditional: true,
			wantReason:          "failed closed",
			wantAnyError:        true,
			wantString:          `NoOpinion(reason="failed closed", err="encountered nil condition")`,
		},
		{
			name: "duplicate IDs",
			testDecisions: []authorizer.ConditionsAwareDecision{
				authorizer.ConditionsAwareDecisionConditionsMap(
					[]authorizer.Condition{authorizer.GenericCondition{ID: "foo"}},
					nil,
					[]authorizer.Condition{authorizer.GenericCondition{ID: "foo"}},
				),
			},
			wantIsDeny:              true,
			wantIsUnconditional:     true,
			wantContainsAllowOrDeny: true,
			wantFailClosedIsDeny:    true,
			wantReason:              "failed closed",
			wantAnyError:            true,
			wantString:              `Deny(reason="failed closed", err="duplicate condition ID \"foo\"")`,
		},
		{
			name: "condition ID must be a Kubernetes label, one condition error enough to fail closed (in Deny)",
			testDecisions: []authorizer.ConditionsAwareDecision{
				authorizer.ConditionsAwareDecisionConditionsMap(
					[]authorizer.Condition{authorizer.GenericCondition{ID: "not a kubernetes label"}},
					nil,
					[]authorizer.Condition{authorizer.GenericCondition{ID: "foo"}},
				),
			},
			wantIsDeny:              true,
			wantIsUnconditional:     true,
			wantContainsAllowOrDeny: true,
			wantFailClosedIsDeny:    true,
			wantReason:              "failed closed",
			wantAnyError:            true,
			wantString:              `Deny(reason="failed closed", err="invalid condition ID \"not a kubernetes label\": name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')")`,
		},
		{
			name: "condition ID must be a Kubernetes label, one condition error enough to fail closed (in NoOpinion)",
			testDecisions: []authorizer.ConditionsAwareDecision{
				authorizer.ConditionsAwareDecisionConditionsMap(
					nil,
					[]authorizer.Condition{authorizer.GenericCondition{ID: "not a kubernetes label"}},
					[]authorizer.Condition{authorizer.GenericCondition{ID: "foo"}},
				),
			},
			wantIsNoOpinion:     true,
			wantIsUnconditional: true,
			wantReason:          "failed closed",
			wantAnyError:        true,
			wantString:          `NoOpinion(reason="failed closed", err="invalid condition ID \"not a kubernetes label\": name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')")`,
		},
		{
			name: "condition ID must be a Kubernetes label, one condition error enough to fail closed (in NoOpinion)",
			testDecisions: []authorizer.ConditionsAwareDecision{
				authorizer.ConditionsAwareDecisionConditionsMap(
					nil,
					nil,
					[]authorizer.Condition{authorizer.GenericCondition{ID: "not a kubernetes label"}, authorizer.GenericCondition{ID: "foo"}},
				),
			},
			wantIsNoOpinion:     true,
			wantIsUnconditional: true,
			wantReason:          "failed closed",
			wantAnyError:        true,
			wantString:          `NoOpinion(reason="failed closed", err="invalid condition ID \"not a kubernetes label\": name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')")`,
		},
		{
			name: "condition type must be a Kubernetes label",
			testDecisions: []authorizer.ConditionsAwareDecision{
				authorizer.ConditionsAwareDecisionConditionsMap(
					nil,
					[]authorizer.Condition{authorizer.GenericCondition{ID: "bar", Type: "not a kubernetes label"}},
					[]authorizer.Condition{authorizer.GenericCondition{ID: "foo"}},
				),
			},
			wantIsNoOpinion:     true,
			wantIsUnconditional: true,
			wantReason:          "failed closed",
			wantAnyError:        true,
			wantString:          `NoOpinion(reason="failed closed", err="invalid condition type \"not a kubernetes label\": name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')")`,
		},
		{
			name: "empty ConditionsMap",
			testDecisions: []authorizer.ConditionsAwareDecision{
				authorizer.ConditionsAwareDecisionConditionsMap(nil, nil, nil),
			},
			wantIsNoOpinion:     true,
			wantIsUnconditional: true,
			wantReason:          "no conditions",
			wantAnyError:        true,
			wantString:          `NoOpinion(reason="no conditions", err="at least one condition must be passed to ConditionsAwareDecisionConditionsMap(), got none")`,
		},
		{
			// Short-circuit: only NoOpinion conditions => the constructor folds the result to NoOpinion
			// directly, without ever returning a ConditionsMap (which would then evaluate to NoOpinion anyway).
			name: "noopinion-only conditions short-circuit to NoOpinion",
			testDecisions: []authorizer.ConditionsAwareDecision{
				authorizer.ConditionsAwareDecisionConditionsMap(
					nil,
					[]authorizer.Condition{authorizer.GenericCondition{ID: "nop-1"}},
					nil,
				),
			},
			wantIsNoOpinion:     true,
			wantIsUnconditional: true,
			wantReason:          "",
			wantString:          `NoOpinion`,
		},
		// Union constructor simplification cases
		{
			name: "union: empty yields NoOpinion",
			testDecisions: []authorizer.ConditionsAwareDecision{
				unionDecision(),
			},
			wantIsNoOpinion:         true,
			wantIsUnconditional:     true,
			wantContainsAllowOrDeny: false,
			wantReason:              "",
			wantString:              `NoOpinion`,
		},
		{
			// A single unconditional decision is simplified to that decision; the reason gets
			// an "%d: %s" index prefix (the index in the union's inner slice) per ToDecision.
			name: "union: single Allow simplifies to Allow",
			testDecisions: []authorizer.ConditionsAwareDecision{
				unionDecision(authorizer.ConditionsAwareDecisionAllow("ok", nil)),
			},
			wantIsAllowed:           true,
			wantIsUnconditional:     true,
			wantContainsAllowOrDeny: true,
			wantReason:              "0: ok",
			wantString:              `Allow(reason="0: ok")`,
		},
		{
			name: "union: single Deny simplifies to Deny",
			testDecisions: []authorizer.ConditionsAwareDecision{
				unionDecision(authorizer.ConditionsAwareDecisionDeny("denied", nil)),
			},
			wantIsDeny:              true,
			wantIsUnconditional:     true,
			wantContainsAllowOrDeny: true,
			wantFailClosedIsDeny:    true,
			wantReason:              "0: denied",
			wantString:              `Deny(reason="0: denied")`,
		},
		{
			name: "union: single NoOpinion simplifies to NoOpinion",
			testDecisions: []authorizer.ConditionsAwareDecision{
				unionDecision(authorizer.ConditionsAwareDecisionNoOpinion("noop", nil)),
			},
			wantIsNoOpinion:         true,
			wantIsUnconditional:     true,
			wantContainsAllowOrDeny: false,
			wantReason:              "0: noop",
			wantString:              `NoOpinion(reason="0: noop")`,
		},
		{
			name: "union: single ConditionsMap wrapped",
			testDecisions: []authorizer.ConditionsAwareDecision{
				unionDecision(condMapAllow),
			},
			wantIsUnion:             true,
			wantContainsAllowOrDeny: false,
			wantReason:              `[""]`,
			wantString:              `Union[ConditionsMap(allows=1)]`,
		},
		{
			name: "union: single Union wrapped",
			testDecisions: []authorizer.ConditionsAwareDecision{
				unionDecision(unionDecision(condMapDeny, authorizer.ConditionsAwareDecisionAllow("", nil))),
			},
			wantIsUnion:             true,
			wantContainsAllowOrDeny: true,
			wantFailClosedIsDeny:    true,
			wantReason:              `[["", ""]]`,
			wantString:              `Union[Union[ConditionsMap(denies=1), Allow]]`,
		},
		{
			name: "union: all NoOpinion yields merged NoOpinion",
			testDecisions: []authorizer.ConditionsAwareDecision{
				unionDecision(
					authorizer.ConditionsAwareDecisionNoOpinion("a", nil),
					authorizer.ConditionsAwareDecisionNoOpinion("", unexpectedErr),
					authorizer.ConditionsAwareDecisionNoOpinion("c", otherErr),
				),
			},
			wantIsNoOpinion:         true,
			wantIsUnconditional:     true,
			wantContainsAllowOrDeny: false,
			wantFailClosedIsDeny:    false,
			wantReason:              "0: a, 2: c",
			wantErrorIs:             unexpectedErr,
			wantString:              `NoOpinion(reason="0: a, 2: c", err="[1: unexpected things happened, 2: other error]")`,
		},
		{
			// Add short-circuits after the first Allow/Deny leaf, so the trailing Deny("second")
			// is dropped. The remaining inner slice is [NoOpinion, NoOpinion, Allow], so the
			// simplified reason references the Allow at index 2.
			name: "union: Allow before Deny returns Allow, NoOpinions are ignored",
			testDecisions: []authorizer.ConditionsAwareDecision{
				unionDecision(
					authorizer.ConditionsAwareDecisionNoOpinion("skip", nil),
					authorizer.ConditionsAwareDecisionNoOpinion("skip", nil),
					authorizer.ConditionsAwareDecisionAllow("first", nil),
					authorizer.ConditionsAwareDecisionDeny("second", nil),
				),
			},
			wantIsAllowed:           true,
			wantIsUnconditional:     true,
			wantContainsAllowOrDeny: true,
			wantFailClosedIsDeny:    false,
			wantReason:              "2: first",
			wantString:              `Allow(reason="2: first")`,
		},
		{
			name: "union: Deny before Allow returns Deny, NoOpinions are ignored",
			testDecisions: []authorizer.ConditionsAwareDecision{
				unionDecision(
					authorizer.ConditionsAwareDecisionNoOpinion("skip", nil),
					authorizer.ConditionsAwareDecisionNoOpinion("skip", nil),
					authorizer.ConditionsAwareDecisionDeny("first", nil),
					authorizer.ConditionsAwareDecisionAllow("second", nil),
				),
			},
			wantIsDeny:              true,
			wantIsUnconditional:     true,
			wantContainsAllowOrDeny: true,
			wantFailClosedIsDeny:    true,
			wantReason:              "2: first",
			wantString:              `Deny(reason="2: first")`,
		},
		// Actual union decisions (not simplified)
		{
			name: "union: noopinion + conditionsmap(allow) + noopinion",
			testDecisions: []authorizer.ConditionsAwareDecision{
				unionDecision(
					authorizer.ConditionsAwareDecisionNoOpinion("no-op1", nil),
					condMapAllow,
					authorizer.ConditionsAwareDecisionNoOpinion("no-op2", nil)),
			},
			wantIsUnion:             true,
			wantContainsAllowOrDeny: false,
			wantFailClosedIsDeny:    false,
			wantReason:              `[no-op1, "", no-op2]`,
			wantString:              `Union[NoOpinion(reason="no-op1"), ConditionsMap(allows=1), NoOpinion(reason="no-op2")]`,
		},
		{
			// ConditionsMap(allow-only) followed by Allow has PossibleDecisions={Allow}: if the
			// ConditionsMap evaluates to Allow, the answer is Allow; if it evaluates to NoOpinion,
			// the trailing Allow takes over. Either way, the union eagerly simplifies to Allow.
			name: "union: conditionsmap(allow) + allow simplifies to Allow",
			testDecisions: []authorizer.ConditionsAwareDecision{
				unionDecision(condMapAllow, authorizer.ConditionsAwareDecisionAllow("allowed", nil)),
			},
			wantIsAllowed:           true,
			wantIsUnconditional:     true,
			wantContainsAllowOrDeny: true,
			wantFailClosedIsDeny:    false,
			wantReason:              "1: allowed",
			wantString:              `Allow(reason="1: allowed")`,
		},
		{
			name: "union: conditionsmap(allow) + deny",
			testDecisions: []authorizer.ConditionsAwareDecision{
				unionDecision(condMapAllow, authorizer.ConditionsAwareDecisionDeny("no", nil)),
			},
			wantIsUnion:             true,
			wantContainsAllowOrDeny: true, // There is an inner Deny
			wantFailClosedIsDeny:    true,
			wantReason:              `["", no]`,
			wantString:              `Union[ConditionsMap(allows=1), Deny(reason="no")]`,
		},
		{
			name: "union: conditionsmap(deny) + noopinion",
			testDecisions: []authorizer.ConditionsAwareDecision{
				unionDecision(condMapDeny, authorizer.ConditionsAwareDecisionNoOpinion("noop", nil)),
			},
			wantIsUnion:             true,
			wantContainsAllowOrDeny: false,
			wantFailClosedIsDeny:    true, // There are Deny conditions
			wantReason:              `["", noop]`,
			wantString:              `Union[ConditionsMap(denies=1), NoOpinion(reason="noop")]`,
		},
		{
			name: "union: conditionsmap(deny) + allow with error",
			testDecisions: []authorizer.ConditionsAwareDecision{
				unionDecision(condMapDeny, authorizer.ConditionsAwareDecisionAllow("allowed", unexpectedErr)),
			},
			wantIsUnion:             true,
			wantContainsAllowOrDeny: true, // There is an inner Allow
			wantFailClosedIsDeny:    true, // There are Deny conditions
			wantReason:              `["", allowed]`,
			wantErrorIs:             unexpectedErr,
			wantString:              `Union[ConditionsMap(denies=1), Allow(reason="allowed", err="unexpected things happened")]`,
		},
		{
			name: "union: conditionsmap(allow) + conditionsmap(deny)",
			testDecisions: []authorizer.ConditionsAwareDecision{
				unionDecision(condMapAllow, condMapDeny),
			},
			wantIsUnion:             true,
			wantContainsAllowOrDeny: false,
			wantFailClosedIsDeny:    true, // There are Deny conditions
			wantReason:              `["", ""]`,
			wantString:              `Union[ConditionsMap(allows=1), ConditionsMap(denies=1)]`,
		},
		{
			// The inner union [condMapAllow, Allow("ok")] simplifies to Allow(reason="1: ok").
			// The trailing NoOpinion is dropped by the outer Add's short-circuit (an Allow is
			// already present). The remaining outer inner is [condMapAllow, Allow("1: ok")],
			// which again simplifies to Allow with a nested index prefix.
			name: "union: nested with allow simplifies through both levels",
			testDecisions: []authorizer.ConditionsAwareDecision{
				unionDecision(
					condMapAllow,
					unionDecision(condMapAllow, authorizer.ConditionsAwareDecisionAllow("ok", nil)),
					authorizer.ConditionsAwareDecisionNoOpinion("don't care", nil),
				),
			},
			wantIsAllowed:           true,
			wantIsUnconditional:     true,
			wantContainsAllowOrDeny: true,
			wantFailClosedIsDeny:    false,
			wantReason:              "1: 1: ok",
			wantString:              `Allow(reason="1: 1: ok")`,
		},
		{
			name: "union: deep nesting without anything unconditional",
			testDecisions: []authorizer.ConditionsAwareDecision{
				unionDecision(
					condMapAllow,
					unionDecision(
						condMapAllow,
						authorizer.ConditionsAwareDecisionNoOpinion("inner", nil),
						unionDecision(
							condMapDeny,
							authorizer.ConditionsAwareDecisionNoOpinion("inner2", nil)),
					),
				),
			},
			wantIsUnion:             true,
			wantContainsAllowOrDeny: false,
			wantFailClosedIsDeny:    true,
			wantReason:              `["", ["", inner, ["", inner2]]]`,
			wantString:              `Union[ConditionsMap(allows=1), Union[ConditionsMap(allows=1), NoOpinion(reason="inner"), Union[ConditionsMap(denies=1), NoOpinion(reason="inner2")]]]`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i, d := range tt.testDecisions {
				t.Run(fmt.Sprint(i), func(t *testing.T) {
					isAllowed := d.IsAllow()
					if isAllowed != tt.wantIsAllowed {
						t.Errorf("IsAllowed() = %v, want %v", isAllowed, tt.wantIsAllowed)
					}
					isNoOpinion := d.IsNoOpinion()
					if isNoOpinion != tt.wantIsNoOpinion {
						t.Errorf("IsNoOpinion() = %v, want %v", isNoOpinion, tt.wantIsNoOpinion)
					}
					isDeny := d.IsDeny()
					if isDeny != tt.wantIsDeny {
						t.Errorf("IsDeny() = %v, want %v", isDeny, tt.wantIsDeny)
					}
					isConditionsMap := d.IsConditionsMap()
					if isConditionsMap != tt.wantIsConditionsMap {
						t.Errorf("IsConditionsMap() = %v, want %v", isConditionsMap, tt.wantIsConditionsMap)
					}
					isUnion := d.IsUnion()
					if isUnion != tt.wantIsUnion {
						t.Errorf("IsUnion() = %v, want %v", isUnion, tt.wantIsUnion)
					}
					isUnconditional := d.IsUnconditional()
					if isUnconditional != tt.wantIsUnconditional {
						t.Errorf("IsUnconditional() = %v, want %v", isUnconditional, tt.wantIsUnconditional)
					}
					containsAllowOrDeny := d.ContainsAllowOrDeny()
					if containsAllowOrDeny != tt.wantContainsAllowOrDeny {
						t.Errorf("ContainsAllowOrDeny() = %v, want %v", containsAllowOrDeny, tt.wantContainsAllowOrDeny)
					}
					failClosedDecisionIsDeny := d.FailureDecision() == authorizer.DecisionDeny
					if failClosedDecisionIsDeny != tt.wantFailClosedIsDeny {
						t.Errorf("FailureDecision() = %v, want %v", failClosedDecisionIsDeny, tt.wantFailClosedIsDeny)
					}
					gotReason := d.Reason()
					if gotReason != tt.wantReason {
						t.Errorf("Reason() = %v, want %v", gotReason, tt.wantReason)
					}
					gotError := d.Error()
					if tt.wantAnyError {
						if gotError == nil {
							t.Errorf("Error() = %v, want some error", nil)
						}
					} else {
						if !errors.Is(gotError, tt.wantErrorIs) {
							t.Errorf("Error() = %v, want %v", gotError, tt.wantErrorIs)
						}
					}

					gotString := d.String()
					if gotString != tt.wantString {
						t.Errorf("String() = %v, want %v", gotString, tt.wantString)
					}
				})
			}
		})
	}
}

func typedNil() authorizer.Condition {
	var c *authorizer.GenericCondition = nil
	return c
}

var _ authorizer.Authorizer = sampleAuthorizer{}

type sampleAuthorizer struct{}

func (a sampleAuthorizer) Authorize(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
	return unconditionalParts(a.ConditionsAwareAuthorize(ctx, attrs))
}

func (a sampleAuthorizer) ConditionsAwareAuthorize(ctx context.Context, attrs authorizer.Attributes) authorizer.ConditionsAwareDecision {
	switch attrs.GetUser().GetName() {
	case "alice":
		return authorizer.ConditionsAwareDecisionAllow("", nil)
	case "bob":
		return authorizer.ConditionsAwareDecisionDeny("", nil)
	case "carol":
		// allow carol to read anything, but require seting the owner=carol label on writes
		switch attrs.GetVerb() {
		case "list":
			return authorizer.ConditionsAwareDecisionAllow("", nil)
		case "update":
			return authorizer.ConditionsAwareDecisionConditionsMap(
				nil, nil,
				[]authorizer.Condition{authorizer.GenericCondition{
					ID: "owner-label-is-set",
					Condition: `
						(oldObject != null ? (has(oldObject.metadata) && has(oldObject.metadata.labels) && has(oldObject.metadata.labels.owner) && oldObject.metadata.labels.owner == "carol") : true) &&
						(object != null ? (has(object.metadata) && has(object.metadata.labels) && has(object.metadata.labels.owner) && object.metadata.labels.owner == "carol") : true)
					`,
					Type: "test-cel-conditions-type",
				}},
			)
		default:
			return authorizer.ConditionsAwareDecisionNoOpinion("", nil)
		}
	case "dave":
		// allow dave to read anything, but never set the classified label on writes
		switch attrs.GetVerb() {
		case "list":
			return authorizer.ConditionsAwareDecisionAllow("", nil)
		case "create", "update", "delete":
			return authorizer.ConditionsAwareDecisionConditionsMap(
				[]authorizer.Condition{
					authorizer.GenericCondition{
						ID:        "deny-supersecret-label-on-oldObject",
						Condition: "oldObject != null && has(oldObject.metadata) && has(oldObject.metadata.labels) && has(oldObject.metadata.labels.supersecret)",
						Type:      "test-cel-conditions-type",
					},
					authorizer.GenericCondition{
						ID:        "deny-supersecret-label-on-object",
						Condition: "object != null && has(object.metadata) && has(object.metadata.labels) && has(object.metadata.labels.supersecret)",
						Type:      "test-cel-conditions-type",
					},
				},
				nil, nil,
			)
		default:
			return authorizer.ConditionsAwareDecisionNoOpinion("", nil)
		}
	default:
		return authorizer.ConditionsAwareDecisionNoOpinion("", nil)
	}
}

func (a sampleAuthorizer) EvaluateConditions(ctx context.Context, unevaluated authorizer.ConditionsAwareDecision, data authorizer.ConditionsData) (authorizer.Decision, string, error) {
	if unevaluated.IsUnconditional() {
		// TODO: UnconditionalParts here? And/or forbid evaluating unconditional decisions
		return unconditionalParts(unevaluated)
	}
	if !unevaluated.IsConditionsMap() {
		// TODO: FailureDecision here?
		return authorizer.DecisionDeny, "failed closed", errors.New("can only evaluate unconditional or ConditionsMap decisions")
	}

	return celEvaluateConditions(ctx, unevaluated.ConditionsMap(), data)
}

func objWithLabels(lbls map[string]string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{}}
	if len(lbls) > 0 {
		obj.SetLabels(lbls)
	}
	return obj
}

func TestSampleAuthorizer(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, genericfeatures.ConditionalAuthorization, true)
	type evalCase struct {
		name      string
		object    *unstructured.Unstructured
		oldObject *unstructured.Unstructured
		// the first case is with conditions-unaware, the second is conditions-aware.
		authorizeDecision [2]string
		finalDecision     [2]string
	}

	tests := []struct {
		name  string
		attrs authorizer.AttributesRecord
		cases []evalCase
	}{
		// alice: unconditional allow for all verbs
		{
			name: "alice list",
			attrs: authorizer.AttributesRecord{
				User: &user.DefaultInfo{Name: "alice"},
				Verb: "list",
			},
			cases: []evalCase{
				{name: "allow", authorizeDecision: [2]string{`Allow`, `Allow`}},
			},
		},
		{
			name: "alice create",
			attrs: authorizer.AttributesRecord{
				User: &user.DefaultInfo{Name: "alice"},
				Verb: "create",
			},
			cases: []evalCase{
				{name: "allow", authorizeDecision: [2]string{`Allow`, `Allow`}},
			},
		},
		// bob: unconditional deny for all verbs
		{
			name: "bob list",
			attrs: authorizer.AttributesRecord{
				User: &user.DefaultInfo{Name: "bob"},
				Verb: "list",
			},
			cases: []evalCase{
				{name: "deny", authorizeDecision: [2]string{`Deny`, `Deny`}},
			},
		},
		{
			name: "bob create",
			attrs: authorizer.AttributesRecord{
				User: &user.DefaultInfo{Name: "bob"},
				Verb: "create",
			},
			cases: []evalCase{
				{name: "deny", authorizeDecision: [2]string{`Deny`, `Deny`}},
			},
		},
		// carol: allow reads, conditional writes (allow on owner=carol)
		{
			name: "carol list",
			attrs: authorizer.AttributesRecord{
				User: &user.DefaultInfo{Name: "carol"},
				Verb: "list",
			},
			cases: []evalCase{
				{name: "allow", authorizeDecision: [2]string{`Allow`, `Allow`}},
			},
		},
		{
			name: "carol update",
			attrs: authorizer.AttributesRecord{
				User: &user.DefaultInfo{Name: "carol"},
				Verb: "update",
			},
			cases: []evalCase{
				{
					name:      "both objects with owner=carol",
					object:    objWithLabels(map[string]string{"owner": "carol"}),
					oldObject: objWithLabels(map[string]string{"owner": "carol"}),
					authorizeDecision: [2]string{
						`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`,
						`ConditionsMap(allows=1)`,
					},
					finalDecision: [2]string{
						`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`,
						`Allow(reason="condition \"owner-label-is-set\" allowed the request")`,
					},
				},
				{
					name:      "old with owner=carol, new without",
					object:    objWithLabels(map[string]string{"owner": "carol"}),
					oldObject: objWithLabels(nil),
					authorizeDecision: [2]string{
						`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`,
						`ConditionsMap(allows=1)`,
					},
					finalDecision: [2]string{
						`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`,
						`NoOpinion(reason="no conditions matched")`,
					},
				},
				{
					name:      "new with owner=carol, old with owner=alice",
					object:    objWithLabels(map[string]string{"owner": "alice"}),
					oldObject: objWithLabels(map[string]string{"owner": "carol"}),
					authorizeDecision: [2]string{
						`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`,
						`ConditionsMap(allows=1)`,
					},
					finalDecision: [2]string{
						`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`,
						`NoOpinion(reason="no conditions matched")`,
					},
				},
			},
		},
		{
			name: "carol unsupported verb",
			attrs: authorizer.AttributesRecord{
				User: &user.DefaultInfo{Name: "carol"},
				Verb: "patch",
			},
			cases: []evalCase{
				{name: "no opinion", authorizeDecision: [2]string{`NoOpinion`, `NoOpinion`}},
			},
		},
		// dave: allow reads, conditional writes (deny on supersecret label)
		{
			name: "dave list",
			attrs: authorizer.AttributesRecord{
				User: &user.DefaultInfo{Name: "dave"},
				Verb: "list",
			},
			cases: []evalCase{
				{name: "allow", authorizeDecision: [2]string{`Allow`, `Allow`}},
			},
		},

		{
			name: "dave update",
			attrs: authorizer.AttributesRecord{
				User: &user.DefaultInfo{Name: "dave"},
				Verb: "update",
			},
			cases: []evalCase{
				{
					name:              "both objects with supersecret",
					object:            objWithLabels(map[string]string{"supersecret": "yes"}),
					oldObject:         objWithLabels(map[string]string{"supersecret": "yes"}),
					authorizeDecision: [2]string{`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `ConditionsMap(denies=2)`},
					finalDecision:     [2]string{`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `Deny(reason="condition \"deny-supersecret-label-on-oldObject\" denied the request, condition \"deny-supersecret-label-on-object\" denied the request")`},
				},
				{
					name:              "new with supersecret old without",
					object:            objWithLabels(map[string]string{"supersecret": "yes"}),
					oldObject:         objWithLabels(nil),
					authorizeDecision: [2]string{`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `ConditionsMap(denies=2)`},
					finalDecision:     [2]string{`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `Deny(reason="condition \"deny-supersecret-label-on-object\" denied the request")`},
				},
				{
					name:              "new without old with supersecret",
					object:            objWithLabels(nil),
					oldObject:         objWithLabels(map[string]string{"supersecret": "yes"}),
					authorizeDecision: [2]string{`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `ConditionsMap(denies=2)`},
					finalDecision:     [2]string{`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `Deny(reason="condition \"deny-supersecret-label-on-oldObject\" denied the request")`},
				},
				{
					name:              "both without supersecret",
					object:            objWithLabels(map[string]string{"safe": "true"}),
					oldObject:         objWithLabels(map[string]string{"safe": "true"}),
					authorizeDecision: [2]string{`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `ConditionsMap(denies=2)`},
					finalDecision:     [2]string{`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `NoOpinion(reason="no conditions matched")`},
				},
			},
		},
		{
			name: "dave create",
			attrs: authorizer.AttributesRecord{
				User: &user.DefaultInfo{Name: "dave"},
				Verb: "create",
			},
			cases: []evalCase{
				{
					name:              "create with supersecret",
					object:            objWithLabels(map[string]string{"supersecret": "yes"}),
					authorizeDecision: [2]string{`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `ConditionsMap(denies=2)`},
					finalDecision:     [2]string{`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `Deny(reason="condition \"deny-supersecret-label-on-object\" denied the request")`},
				},
				{
					name:              "create without supersecret",
					object:            objWithLabels(map[string]string{"safe": "true"}),
					authorizeDecision: [2]string{`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `ConditionsMap(denies=2)`},
					finalDecision:     [2]string{`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `NoOpinion(reason="no conditions matched")`},
				},
			},
		},
		{
			name: "dave delete",
			attrs: authorizer.AttributesRecord{
				User: &user.DefaultInfo{Name: "dave"},
				Verb: "delete",
			},
			cases: []evalCase{
				{
					name:              "delete with supersecret on old object",
					oldObject:         objWithLabels(map[string]string{"supersecret": "yes"}),
					authorizeDecision: [2]string{`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `ConditionsMap(denies=2)`},
					finalDecision:     [2]string{`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `Deny(reason="condition \"deny-supersecret-label-on-oldObject\" denied the request")`},
				},
				{
					name:              "delete without supersecret on old object",
					oldObject:         objWithLabels(map[string]string{"safe": "true"}),
					authorizeDecision: [2]string{`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `ConditionsMap(denies=2)`},
					finalDecision:     [2]string{`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `NoOpinion(reason="no conditions matched")`},
				},
			},
		},
		{
			name: "dave unsupported verb",
			attrs: authorizer.AttributesRecord{
				User: &user.DefaultInfo{Name: "dave"},
				Verb: "patch",
			},
			cases: []evalCase{
				{name: "no opinion", authorizeDecision: [2]string{`NoOpinion`, `NoOpinion`}},
			},
		},
		// unknown user: no opinion
		{
			name: "unknown user get",
			attrs: authorizer.AttributesRecord{
				User: &user.DefaultInfo{Name: "unknown"},
				Verb: "list",
			},
			cases: []evalCase{
				{name: "no opinion", authorizeDecision: [2]string{`NoOpinion`, `NoOpinion`}},
			},
		},
	}

	authz := sampleAuthorizer{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, tc := range tt.cases {
				// if only the authorization decision is specified, the final one is the same
				if len(tc.finalDecision[0]) == 0 && len(tc.finalDecision[1]) == 0 {
					tc.finalDecision[0] = tc.authorizeDecision[0]
					tc.finalDecision[1] = tc.authorizeDecision[1]
				}
				for i, supportsConditions := range [2]bool{false, true} {
					t.Run(fmt.Sprintf("%s/%t", tc.name, supportsConditions), func(t *testing.T) {
						var decision authorizer.ConditionsAwareDecision
						if supportsConditions {
							decision = authz.ConditionsAwareAuthorize(t.Context(), tt.attrs)
						} else {
							decision = authorizer.ConditionsAwareDecisionFromParts(authz.Authorize(t.Context(), tt.attrs))
						}

						if decision.String() != tc.authorizeDecision[i] {
							t.Errorf("got Authorize() decision %s, want %s", decision.String(), tc.authorizeDecision[i])
						}

						// Only object and oldObject is used in celEvaluateConditions, so let all other values be zero here, as they are anyways unused.
						data := authorizer.ConditionsData{
							AdmissionControl: admission.NewAttributesRecord(tc.object, tc.oldObject, schema.GroupVersionKind{}, "", "", schema.GroupVersionResource{}, "", "", nil, false, nil),
						}

						// Wrap in the ConditionsAwareDecision format just to get an unified string comparison mechanism.
						final := authorizer.ConditionsAwareDecisionFromParts(authz.EvaluateConditions(t.Context(), decision, data))
						if final.String() != tc.finalDecision[i] {
							t.Errorf("got Evaluate() decision %s, want %s", final.String(), tc.finalDecision[i])
						}
					})
				}
			}
		})
	}
}

func celEvaluateConditions(ctx context.Context, conditionsMap authorizer.ConditionsMap, data authorizer.ConditionsData) (authorizer.Decision, string, error) {
	env, err := cel.NewEnv(
		cel.Variable("object", cel.DynType),
		cel.Variable("oldObject", cel.DynType),
	)
	if err != nil {
		return conditionsMap.FailureDecision(), "failed closed", fmt.Errorf("failed to create CEL env: %w", err)
	}

	if data.AdmissionControl == nil {
		return conditionsMap.FailureDecision(), "failed closed", errors.New("evaluating a CEL condition requires non-nil data.AdmissionControl")
	}

	obj, err := objectToResolveVal(data.AdmissionControl.GetObject())
	if err != nil {
		return conditionsMap.FailureDecision(), "failed closed", fmt.Errorf("failed to convert object to CEL ref.Val: %w", err)
	}

	oldObj, err := objectToResolveVal(data.AdmissionControl.GetOldObject())
	if err != nil {
		return conditionsMap.FailureDecision(), "failed closed", fmt.Errorf("failed to convert object to CEL ref.Val: %w", err)
	}

	vars := map[string]any{
		"object":    obj,
		"oldObject": oldObj,
	}

	return conditionsMap.Evaluate(ctx, data, func(ctx context.Context, c authorizer.Condition, _ authorizer.ConditionsData) (bool, error) {
		return evalCEL(env, c.GetCondition(), vars)
	})
}

// evalCEL compiles and evaluates a single CEL expression, returning true/false.
func evalCEL(env *cel.Env, expr string, vars map[string]any) (bool, error) {
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return false, fmt.Errorf("CEL compile error for %q: %w", expr, issues.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		return false, fmt.Errorf("CEL program error for %q: %w", expr, err)
	}
	out, _, err := prg.Eval(vars)
	if err != nil {
		return false, fmt.Errorf("CEL eval error for %q: %w", expr, err)
	}
	result, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("CEL expression %q did not return bool, got %T", expr, out.Value())
	}
	return result, nil
}

func objectToResolveVal(r runtime.Object) (interface{}, error) {
	if r == nil || reflect.ValueOf(r).IsNil() {
		return nil, nil
	}
	ret, err := runtime.DefaultUnstructuredConverter.ToUnstructured(r)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func unconditionalParts(d authorizer.ConditionsAwareDecision) (authorizer.Decision, string, error) {
	switch {
	case d.IsAllow():
		return authorizer.DecisionAllow, d.Reason(), d.Error()
	case d.IsDeny():
		return authorizer.DecisionDeny, d.Reason(), d.Error()
	case d.IsNoOpinion():
		return authorizer.DecisionNoOpinion, d.Reason(), d.Error()
	default:
		// An error is not returned here, as that could yield a HTTP response code of 500 instead of 403.
		// For the use-case described above with regards to calling this function in Authorize, not returning
		// an error is important, as it is valid to always fail closed, as if this happens, no unconditional
		// permissions were given the requestor.
		// TODO: FailureDecision here?
		return authorizer.DecisionDeny, "failed closed: tried to return conditional decision to conditions-unaware authorizer", nil
	}
}

func TestConditionsAwareDecisionUnionedDecisions(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, genericfeatures.ConditionalAuthorization, true)

	condMap := authorizer.ConditionsAwareDecisionConditionsMap(
		nil, nil,
		[]authorizer.Condition{authorizer.GenericCondition{ID: "test", Condition: "true", Type: "test-type"}},
	)
	noOp := authorizer.ConditionsAwareDecisionNoOpinion("noop", nil)

	t.Run("non-union has empty iterator", func(t *testing.T) {
		noUnionTestcases := []authorizer.ConditionsAwareDecision{
			condMap,
			noOp,
			authorizer.ConditionsAwareDecisionAllow("ok", nil),
			authorizer.ConditionsAwareDecisionDeny("not ok", nil),
		}
		for i, tc := range noUnionTestcases {
			t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
				count := 0
				for range tc.UnionedDecisions() {
					count++
				}
				if count != 0 {
					t.Errorf("expected 0 unioned decisions for %s, got %d", tc, count)
				}
			})
		}
	})

	t.Run("union iterates sub-decisions in order", func(t *testing.T) {
		union := unionDecision(condMap, noOp)
		var got []string
		for _, sub := range union.UnionedDecisions() {
			got = append(got, sub.Reason())
		}
		want := []string{"", "noop"}
		if len(got) != len(want) {
			t.Fatalf("expected %d sub-decisions, got %d", len(want), len(got))
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("sub-decision[%d].Reason() = %q, want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("early break in iterator", func(t *testing.T) {
		union := unionDecision(condMap, noOp)
		count := 0
		for range union.UnionedDecisions() {
			count++
			break
		}
		if count != 1 {
			t.Errorf("expected early break after 1 iteration, got %d", count)
		}
	})
}

func TestPartiallyEvaluateConditionsAwareDecision(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, genericfeatures.ConditionalAuthorization, true)

	// mkCM builds a ConditionsMap decision from individually-tagged (effect, condition) pairs,
	// preserving the inline readability of the original test cases (which carried .Effect on
	// each GenericCondition).
	mkCM := func(items ...effectCondition) authorizer.ConditionsAwareDecision {
		var deny, nop, allow []authorizer.Condition
		for _, it := range items {
			switch it.effect {
			case effectAllow:
				allow = append(allow, it.cond)
			case effectDeny:
				deny = append(deny, it.cond)
			case effectNoOpinion:
				nop = append(nop, it.cond)
			}
		}
		return authorizer.ConditionsAwareDecisionConditionsMap(deny, nop, allow)
	}

	// genericCond is a shorthand for an authorizer.GenericCondition. Description is optional.
	cnd := func(effect conditionEffect, id, condition, typ, description string) effectCondition {
		return effectCondition{
			effect: effect,
			cond: authorizer.GenericCondition{
				ID: id, Condition: condition, Type: typ, Description: description,
			},
		}
	}

	type testCase struct {
		name string

		// decision is the input passed to PartiallyEvaluateConditionsAwareDecision.
		decision authorizer.ConditionsAwareDecision

		// noACRReviewer: in the original test suite this flag meant "no webhook required for
		// this case because the partial evaluator simplifies fully to an unconditional decision".
		// Here it means: the partial result must be Unconditional (Allow/Deny/NoOpinion), and
		// only wantDecision / wantReason are checked.
		noACRReviewer bool

		// builtinConditionsEvaluator is the PartialEvaluateConditionFunc supplied to the partial
		// evaluator. Returning Unevaluatable leaves the condition in a refined ConditionsMap.
		builtinConditionsEvaluator authorizer.PartialEvaluateConditionFunc

		wantDecision authorizer.Decision
		wantReason   string

		// verifyPartial is the replacement for verifyACR. When the partial result is still
		// conditional (noACRReviewer == false), it asserts the shape of the returned
		// ConditionsAwareDecision tree.
		verifyPartial func(t *testing.T, partial authorizer.ConditionsAwareDecision)
	}

	tests := []testCase{
		{
			name: "full builtin evaluation of one ConditionsMap => Deny",
			decision: mkCM(
				cnd(effectAllow, "c", "c", "transparent", "all ok"),
				cnd(effectDeny, "d", "d", "transparent", "very bad"),
			),
			noACRReviewer: true,
			builtinConditionsEvaluator: func(_ context.Context, condition authorizer.Condition, _ authorizer.ConditionsData) authorizer.ConditionEvaluationResult {
				return authorizer.ConditionEvaluationResultBoolean(condition.GetCondition() == "d")
			},
			wantDecision: authorizer.DecisionDeny,
			wantReason:   `condition "d" denied the request with description "very bad"`,
		},
		{
			name: "full builtin evaluation of one ConditionsMap => NoOpinion",
			decision: mkCM(
				cnd(effectAllow, "c", "c", "transparent", "all ok"),
				cnd(effectDeny, "d", "d", "transparent", "very bad"),
			),
			noACRReviewer: true,
			builtinConditionsEvaluator: func(_ context.Context, _ authorizer.Condition, _ authorizer.ConditionsData) authorizer.ConditionEvaluationResult {
				return authorizer.ConditionEvaluationResultBoolean(false)
			},
			wantDecision: authorizer.DecisionNoOpinion,
			wantReason:   `no conditions matched`,
		},
		{
			name: "full builtin evaluation of one ConditionsMap => Allow",
			decision: mkCM(
				cnd(effectAllow, "c", "c", "transparent", "all ok"),
				cnd(effectDeny, "d", "d", "transparent", "very bad"),
			),
			noACRReviewer: true,
			builtinConditionsEvaluator: func(_ context.Context, condition authorizer.Condition, _ authorizer.ConditionsData) authorizer.ConditionEvaluationResult {
				return authorizer.ConditionEvaluationResultBoolean(condition.GetCondition() == "c")
			},
			wantDecision: authorizer.DecisionAllow,
			wantReason:   `condition "c" allowed the request with description "all ok"`,
		},
		{
			// The opaque allow condition cannot be evaluated in-process, so the partial result
			// is a refined ConditionsMap containing only that condition. (Previously a webhook
			// was consulted to finish the evaluation; here we just verify the partial tree.)
			name: "partial builtin evaluation of one ConditionsMap => refined ConditionsMap",
			decision: mkCM(
				cnd(effectAllow, "c", "c", "opaque", "all ok"),       // needs a webhook due to opaque type
				cnd(effectDeny, "d", "d", "transparent", "very bad"), // simplified in-process
			),
			builtinConditionsEvaluator: func(_ context.Context, condition authorizer.Condition, _ authorizer.ConditionsData) authorizer.ConditionEvaluationResult {
				if condition.GetType() == "transparent" {
					return authorizer.ConditionEvaluationResultBoolean(condition.GetCondition() == "c")
				}
				return authorizer.ConditionsEvaluationResultUnevaluatable()
			},
			verifyPartial: assertDecisionTree(snapDecision{
				Kind: "ConditionsMap",
				CM: &snapCM{
					Allow: []snapCondition{
						{ID: "c", Condition: "c", Type: "opaque", Description: "all ok"},
					},
				},
			}),
		},
		{
			name: "builtin evaluation of union succeeds => Allow",
			decision: unionDecision(
				mkCM(
					cnd(effectAllow, "a", "a", "transparent", ""),
					cnd(effectDeny, "b", "b", "transparent", ""),
				),
				mkCM(
					cnd(effectAllow, "c", "c", "transparent", ""),
					cnd(effectDeny, "d", "d", "transparent", ""),
				),
			),
			noACRReviewer: true,
			builtinConditionsEvaluator: func(_ context.Context, condition authorizer.Condition, _ authorizer.ConditionsData) authorizer.ConditionEvaluationResult {
				return authorizer.ConditionEvaluationResultBoolean(condition.GetCondition() == "c")
			},
			wantDecision: authorizer.DecisionAllow,
			wantReason:   `condition "c" allowed the request`,
		},
		{
			name: "builtin evaluation of union succeeds => Deny",
			decision: unionDecision(
				mkCM(
					cnd(effectAllow, "a", "a", "transparent", ""),
					cnd(effectDeny, "b", "b", "transparent", ""),
				),
				mkCM(
					cnd(effectAllow, "c", "c", "transparent", ""),
					cnd(effectDeny, "d", "d", "transparent", ""),
				),
			),
			noACRReviewer: true,
			builtinConditionsEvaluator: func(_ context.Context, condition authorizer.Condition, _ authorizer.ConditionsData) authorizer.ConditionEvaluationResult {
				return authorizer.ConditionEvaluationResultBoolean(condition.GetCondition() == "d")
			},
			wantDecision: authorizer.DecisionDeny,
			wantReason:   `condition "d" denied the request`,
		},
		{
			// First CM has an opaque allow condition that cannot be simplified, so the union
			// short-circuits to "collect remaining sub-decisions as-is" after that point. The
			// second CM is preserved unchanged (it never gets a chance to be evaluated).
			name: "first conditionsmap cannot be simplified fully",
			decision: unionDecision(
				mkCM(
					cnd(effectAllow, "a", "a", "opaque", ""),
					cnd(effectDeny, "b", "b", "transparent", ""),
				),
				mkCM(
					cnd(effectAllow, "c", "c", "transparent", ""),
					cnd(effectDeny, "d", "d", "transparent", ""),
				),
			),
			builtinConditionsEvaluator: func(_ context.Context, condition authorizer.Condition, _ authorizer.ConditionsData) authorizer.ConditionEvaluationResult {
				if condition.GetType() == "transparent" {
					return authorizer.ConditionEvaluationResultBoolean(condition.GetCondition() == "c")
				}
				return authorizer.ConditionsEvaluationResultUnevaluatable()
			},
			verifyPartial: assertDecisionTree(snapDecision{
				Kind: "Union",
				Union: []snapDecision{
					{
						Kind: "ConditionsMap",
						CM: &snapCM{
							Allow: []snapCondition{{ID: "a", Condition: "a", Type: "opaque"}},
						},
					},
					{
						Kind: "ConditionsMap",
						CM: &snapCM{
							Deny:  []snapCondition{{ID: "d", Condition: "d", Type: "transparent"}},
							Allow: []snapCondition{{ID: "c", Condition: "c", Type: "transparent"}},
						},
					},
				},
			}),
		},
		{
			// First CM simplifies fully to NoOpinion (none of its transparent conditions match).
			// Second CM has an opaque deny condition, so it cannot be simplified and stays a
			// (refined) ConditionsMap. Third entry is an unconditional Deny that survives as-is.
			name: "first conditionsmap can be simplified fully, but not second",
			decision: unionDecision(
				mkCM(
					cnd(effectAllow, "a", "a", "transparent", ""),
					cnd(effectDeny, "b", "b", "transparent", ""),
				),
				mkCM(
					cnd(effectAllow, "c", "c", "transparent", ""),
					cnd(effectDeny, "d", "d", "opaque", ""),
				),
				authorizer.ConditionsAwareDecisionDeny("something later denies", nil),
			),
			builtinConditionsEvaluator: func(_ context.Context, condition authorizer.Condition, _ authorizer.ConditionsData) authorizer.ConditionEvaluationResult {
				if condition.GetType() == "transparent" {
					return authorizer.ConditionEvaluationResultBoolean(condition.GetCondition() == "c")
				}
				return authorizer.ConditionsEvaluationResultUnevaluatable()
			},
			verifyPartial: assertDecisionTree(snapDecision{
				Kind: "Union",
				Union: []snapDecision{
					{Kind: "NoOpinion", Reason: "no conditions matched"},
					{
						Kind: "ConditionsMap",
						CM: &snapCM{
							Deny:  []snapCondition{{ID: "d", Condition: "d", Type: "opaque"}},
							Allow: []snapCondition{{ID: "c", Condition: "c", Type: "transparent"}},
						},
					},
					{Kind: "Deny", Reason: "something later denies"},
				},
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := authorizer.PartiallyEvaluateConditionsAwareDecision(
				t.Context(),
				tt.decision,
				authorizer.ConditionsData{},
				tt.builtinConditionsEvaluator,
			)

			if tt.noACRReviewer {
				if !got.IsUnconditional() {
					t.Fatalf("expected unconditional decision, got %s", got.String())
				}
				gotDecision, gotReason, _ := got.UnconditionalParts()
				if gotDecision != tt.wantDecision {
					t.Errorf("decision = %v, want %v", gotDecision, tt.wantDecision)
				}
				if gotReason != tt.wantReason {
					t.Errorf("reason = %q, want %q", gotReason, tt.wantReason)
				}
				return
			}
			if tt.verifyPartial == nil {
				t.Fatalf("test case %q must set either noACRReviewer or verifyPartial", tt.name)
			}
			tt.verifyPartial(t, got)
		})
	}
}
