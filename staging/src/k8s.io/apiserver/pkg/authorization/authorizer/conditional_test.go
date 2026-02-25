/*
Copyright 2025 The Kubernetes Authors.

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

package authorizer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
)

func TestDecisionZeroValueIsDeny(t *testing.T) {
	d := Decision{}
	if !d.IsDenied() {
		t.Fatal("Expected the zero value of Decision{} to be a Deny")
	}
	if d.String() != "Deny" {
		t.Fatal("Expected the zero value to string encode to 'Deny'")
	}
}

// TODO: Check that the Decision can only return true for one of the Is.. methods

type sampleAuthorizer struct{}

func (a sampleAuthorizer) Authorize(ctx context.Context, attrs Attributes) (Decision, error) {
	switch attrs.GetUser().GetName() {
	case "alice":
		return DecisionAllow(), nil
	case "bob":
		return DecisionDeny(), nil
	case "carol":
		// allow carol to read anything, but require seting the owner=carol label on writes
		switch attrs.GetVerb() {
		case "list":
			return DecisionAllow(), nil
		case "update":
			conditions, err := NewConditionSet("labelSelectorApplies", []Condition{
				{
					ID: "owner-label-is-set",
					// (oldobject != nil && has(oldobject.metadata.labels.owner) && oldobject.metadata.labels.owner == "carol") &&
					// (object != nil && has(object.metadata.labels.owner) && object.metadata.labels.owner == "carol")
					Condition: "owner=carol|owner=carol",
					Effect:    ConditionEffectAllow,
				},
			})
			if err != nil {
				return DecisionNoOpinion(), err
			}
			// the authorizer is misbehaving here, it SHOULD check attrs.GetConditionsMode() and
			// fail closed to NoOpinion or Deny whenever it would like to return a conditional decision,
			// but the client does not support it. However, this check is also done in DecisionConditional here.
			return DecisionConditional(*conditions, a, attrs), nil
		default:
			return DecisionNoOpinion(), nil
		}
	case "dave":
		// allow dave to read anything, but never set the classified label on writes
		switch attrs.GetVerb() {
		case "list":
			return DecisionAllow(), nil
		case "create", "update", "delete":
			conditions, err := NewConditionSet("labelSelectorApplies", []Condition{
				{
					ID: "deny-supersecret-label-on-oldobject",
					// (oldobject != nil && has(oldobject.metadata.labels.supersecret)) && true
					Condition: "supersecret|",
					Effect:    ConditionEffectDeny,
				},
				{
					ID: "deny-supersecret-label-on-object",
					// true && (object != nil && has(object.metadata.labels.supersecret))
					Condition: "|supersecret",
					Effect:    ConditionEffectDeny,
				},
			})
			if err != nil {
				return DecisionNoOpinion(), err
			}
			// the authorizer is misbehaving here, it SHOULD check attrs.GetConditionsMode() and
			// fail closed to NoOpinion or Deny whenever it would like to return a conditional decision,
			// but the client does not support it. However, this check is also done in DecisionConditional here.
			return DecisionConditional(*conditions, a, attrs), nil
		default:
			return DecisionNoOpinion(), nil
		}
	default:
		return DecisionNoOpinion(), nil
	}
}

func (a sampleAuthorizer) EvaluateConditions(ctx context.Context, conditionSet *ConditionSet, data ConditionData) (Decision, error) {
	// TODO: improve this
	if data.WriteRequest() == nil {
		return conditionSet.FailClosedDecision(), errors.New("only supports conditions for write requests")
	}

	enforceObjects := []runtime.Object{
		data.WriteRequest().GetOldObject(),
		data.WriteRequest().GetObject(),
	}

	return EvaluateConditionSet(conditionSet, "labelSelectorApplies", func(condition string) (bool, error) {
		// condition is of form: "label-selector-for-oldobject|label-selector-for-object"
		// if label-selector-for-oldobject is empty, it means "true"
		selectorStrs := strings.Split(condition, "|")
		if len(selectorStrs) != 2 {
			return false, errors.New("invalid labelselector condition")
		}
		for i, selectorStr := range selectorStrs {
			if len(selectorStr) == 0 {
				continue
			}
			runtimeObj := enforceObjects[i]
			if runtimeObj == nil {
				return false, nil
			}
			obj, ok := runtimeObj.(metav1.Object)
			if !ok {
				return false, errors.New("only supports objects with metadata")
			}
			selector, err := labels.Parse(selectorStr)
			if err != nil {
				return false, err
			}

			if !selector.Matches(labels.Set(obj.GetLabels())) {
				return false, nil
			}
		}
		return true, nil
	})
}

// testConditionData implements ConditionData for testing.
type testConditionData struct {
	writeReq *testWriteRequest
}

func (d *testConditionData) WriteRequest() WriteRequestConditionData {
	if d.writeReq == nil {
		return nil
	}
	return d.writeReq
}

func (d *testConditionData) ImpersonationRequest() ImpersonationRequestConditionData {
	return nil
}

// testWriteRequest implements WriteRequestConditionData for testing.
type testWriteRequest struct {
	object    runtime.Object
	oldObject runtime.Object
}

func (r *testWriteRequest) GetOperation() string {
	switch {
	case r.object != nil && r.oldObject == nil:
		return "CREATE"
	case r.object != nil && r.oldObject != nil:
		return "UPDATE"
	case r.object == nil && r.oldObject != nil:
		return "DELETE"
	default:
		return "UNKNOWN"
	}
}
func (r *testWriteRequest) GetOperationOptions() runtime.Object { return nil }
func (r *testWriteRequest) GetObject() runtime.Object           { return r.object }
func (r *testWriteRequest) GetOldObject() runtime.Object        { return r.oldObject }

func objWithLabels(lbls map[string]string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{}}
	if len(lbls) > 0 {
		obj.SetLabels(lbls)
	}
	return obj
}

// if we just cast a nil but u to runtime.Object, the runtimeObj == nil gives false when
// one wants true.
func runtimeObj(u *unstructured.Unstructured) runtime.Object {
	if u == nil {
		return nil
	}
	return u
}

func TestSampleAuthorizer(t *testing.T) {
	type evalCase struct {
		name      string
		object    *unstructured.Unstructured
		oldObject *unstructured.Unstructured
		// the first case is with ConditionsModeNone, the second with ConditionsModeHumanReadable
		authorizeDecision [2]string
		finalDecision     [2]string
	}

	tests := []struct {
		name  string
		attrs AttributesRecord
		cases []evalCase
	}{
		// alice: unconditional allow for all verbs
		{
			name: "alice list",
			attrs: AttributesRecord{
				User: &user.DefaultInfo{Name: "alice"},
				Verb: "list",
			},
			cases: []evalCase{
				{name: "allow", authorizeDecision: [2]string{"Allow", "Allow"}},
			},
		},
		{
			name: "alice create",
			attrs: AttributesRecord{
				User: &user.DefaultInfo{Name: "alice"},
				Verb: "create",
			},
			cases: []evalCase{
				{name: "allow", authorizeDecision: [2]string{"Allow", "Allow"}},
			},
		},
		// bob: unconditional deny for all verbs
		{
			name: "bob list",
			attrs: AttributesRecord{
				User: &user.DefaultInfo{Name: "bob"},
				Verb: "list",
			},
			cases: []evalCase{
				{name: "deny", authorizeDecision: [2]string{"Deny", "Deny"}},
			},
		},
		{
			name: "bob create",
			attrs: AttributesRecord{
				User: &user.DefaultInfo{Name: "bob"},
				Verb: "create",
			},
			cases: []evalCase{
				{name: "deny", authorizeDecision: [2]string{"Deny", "Deny"}},
			},
		},
		// carol: allow reads, conditional writes (EffectAllow on owner=carol)
		{
			name: "carol list",
			attrs: AttributesRecord{
				User: &user.DefaultInfo{Name: "carol"},
				Verb: "list",
			},
			cases: []evalCase{
				{name: "allow", authorizeDecision: [2]string{"Allow", "Allow"}},
			},
		},
		{
			name: "carol update",
			attrs: AttributesRecord{
				User: &user.DefaultInfo{Name: "carol"},
				Verb: "update",
			},
			cases: []evalCase{
				{
					name:              "both objects with owner=carol",
					object:            objWithLabels(map[string]string{"owner": "carol"}),
					oldObject:         objWithLabels(map[string]string{"owner": "carol"}),
					authorizeDecision: [2]string{"NoOpinion", "Conditional"},
					finalDecision:     [2]string{"NoOpinion", "Allow"},
				},
				{
					name:              "old with owner=carol, new without",
					object:            objWithLabels(map[string]string{"owner": "carol"}),
					oldObject:         objWithLabels(nil),
					authorizeDecision: [2]string{"NoOpinion", "Conditional"},
					finalDecision:     [2]string{"NoOpinion", "NoOpinion"},
				},
				{
					name:              "new with owner=carol, old with owner=alice",
					object:            objWithLabels(map[string]string{"owner": "alice"}),
					oldObject:         objWithLabels(map[string]string{"owner": "carol"}),
					authorizeDecision: [2]string{"NoOpinion", "Conditional"},
					finalDecision:     [2]string{"NoOpinion", "NoOpinion"},
				},
			},
		},
		{
			name: "carol unsupported verb",
			attrs: AttributesRecord{
				User: &user.DefaultInfo{Name: "carol"},
				Verb: "patch",
			},
			cases: []evalCase{
				{name: "no opinion", authorizeDecision: [2]string{"NoOpinion", "NoOpinion"}},
			},
		},
		// dave: allow reads, conditional writes (EffectDeny on supersecret label)
		{
			name: "dave list",
			attrs: AttributesRecord{
				User: &user.DefaultInfo{Name: "dave"},
				Verb: "list",
			},
			cases: []evalCase{
				{name: "allow", authorizeDecision: [2]string{"Allow", "Allow"}},
			},
		},

		{
			name: "dave update",
			attrs: AttributesRecord{
				User: &user.DefaultInfo{Name: "dave"},
				Verb: "update",
			},
			cases: []evalCase{
				{
					name:              "both objects with supersecret",
					object:            objWithLabels(map[string]string{"supersecret": "yes"}),
					oldObject:         objWithLabels(map[string]string{"supersecret": "yes"}),
					authorizeDecision: [2]string{"Deny", "Conditional"},
					finalDecision:     [2]string{"Deny", "Deny"},
				},
				{
					name:              "new with supersecret old without",
					object:            objWithLabels(map[string]string{"supersecret": "yes"}),
					oldObject:         objWithLabels(nil),
					authorizeDecision: [2]string{"Deny", "Conditional"},
					finalDecision:     [2]string{"Deny", "Deny"},
				},
				{
					name:              "new without old with supersecret",
					object:            objWithLabels(nil),
					oldObject:         objWithLabels(map[string]string{"supersecret": "yes"}),
					authorizeDecision: [2]string{"Deny", "Conditional"},
					finalDecision:     [2]string{"Deny", "Deny"},
				},
				{
					name:              "both without supersecret",
					object:            objWithLabels(map[string]string{"safe": "true"}),
					oldObject:         objWithLabels(map[string]string{"safe": "true"}),
					authorizeDecision: [2]string{"Deny", "Conditional"},
					finalDecision:     [2]string{"Deny", "NoOpinion"},
				},
			},
		},
		{
			name: "dave unsupported verb",
			attrs: AttributesRecord{
				User: &user.DefaultInfo{Name: "dave"},
				Verb: "patch",
			},
			cases: []evalCase{
				{name: "no opinion", authorizeDecision: [2]string{"NoOpinion", "NoOpinion"}},
			},
		},
		// unknown user: no opinion
		{
			name: "unknown user get",
			attrs: AttributesRecord{
				User: &user.DefaultInfo{Name: "unknown"},
				Verb: "list",
			},
			cases: []evalCase{
				{name: "no opinion", authorizeDecision: [2]string{"NoOpinion", "NoOpinion"}},
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
				for i, conditionsMode := range [2]ConditionsMode{ConditionsModeNone, ConditionsModeHumanReadable} {
					t.Run(fmt.Sprintf("%s/%s", tc.name, conditionsMode), func(t *testing.T) {
						localAttrs := tt.attrs
						localAttrs.ConditionsMode = conditionsMode

						ctx := context.Background()
						decision, err := authz.Authorize(ctx, localAttrs)
						if err != nil {
							t.Fatalf("Authorize() returned unexpected error: %v", err)
						}

						if decision.String() != tc.authorizeDecision[i] {
							t.Errorf("got Authorize() decision %s (reason: %q), want %s", decision.String(), decision.Reason(), tc.authorizeDecision[i])
						}

						data := &testConditionData{
							writeReq: &testWriteRequest{
								object:    runtimeObj(tc.object),
								oldObject: runtimeObj(tc.oldObject),
							},
						}

						final, err := decision.Evaluate(ctx, data)
						if err != nil {
							t.Fatalf("Evaluate() returned unexpected error: %v", err)
						}
						if final.String() != tc.finalDecision[i] {
							t.Errorf("got Evaluate() decision %s (reason: %q), want %s", final.String(), final.Reason(), tc.finalDecision[i])
						}
					})
				}
			}
		})
	}
}
