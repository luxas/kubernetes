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
	"testing"

	"github.com/google/go-cmp/cmp"

	"k8s.io/apiserver/pkg/authorization/authorizer"
)

// conditionEffect mirrors the deny/noOpinion/allow categorization the old
// GenericCondition.Effect field encoded, but lives entirely in the test rather than the API.
type conditionEffect int

const (
	effectAllow conditionEffect = iota
	effectDeny
	effectNoOpinion
)

// effectCondition pairs a Condition with the effect slice it should be placed into.
type effectCondition struct {
	effect conditionEffect
	cond   authorizer.Condition
}

// snapDecision is a deep-comparable snapshot of an authorizer.ConditionsAwareDecision tree,
// used in lieu of comparing against the (now-removed) authorizationv1alpha1 wire types.
type snapDecision struct {
	Kind   string // "Allow" | "Deny" | "NoOpinion" | "ConditionsMap" | "Union"
	Reason string
	CM     *snapCM
	Union  []snapDecision
}

type snapCM struct {
	Deny      []snapCondition
	NoOpinion []snapCondition
	Allow     []snapCondition
}

type snapCondition struct {
	ID          string
	Condition   string
	Type        string
	Description string
}

func snapshotDecision(d authorizer.ConditionsAwareDecision) snapDecision {
	switch {
	case d.IsAllow():
		return snapDecision{Kind: "Allow", Reason: d.Reason()}
	case d.IsDeny():
		return snapDecision{Kind: "Deny", Reason: d.Reason()}
	case d.IsNoOpinion():
		return snapDecision{Kind: "NoOpinion", Reason: d.Reason()}
	case d.IsConditionsMap():
		return snapDecision{Kind: "ConditionsMap", CM: snapshotConditionsMap(d.ConditionsMap())}
	case d.IsUnion():
		var subs []snapDecision
		for _, sub := range d.UnionedDecisions() {
			subs = append(subs, snapshotDecision(sub))
		}
		return snapDecision{Kind: "Union", Union: subs}
	}
	return snapDecision{Kind: "Unknown"}
}

func snapshotConditionsMap(cm authorizer.ConditionsMap) *snapCM {
	out := &snapCM{}
	for c := range cm.DenyConditions() {
		out.Deny = append(out.Deny, snapshotCondition(c))
	}
	for c := range cm.NoOpinionConditions() {
		out.NoOpinion = append(out.NoOpinion, snapshotCondition(c))
	}
	for c := range cm.AllowConditions() {
		out.Allow = append(out.Allow, snapshotCondition(c))
	}
	return out
}

func snapshotCondition(c authorizer.Condition) snapCondition {
	return snapCondition{
		ID:          c.GetID(),
		Condition:   c.GetCondition(),
		Type:        c.GetType(),
		Description: c.GetDescription(),
	}
}

// assertDecisionTree returns a verifyPartial that snapshots the actual partial decision and
// compares it against want using cmp.Diff. This is the modern equivalent of the verifyACR
// helper that used cmp.Diff on the (now-removed) authorizationv1alpha1 wire decision tree.
func assertDecisionTree(want snapDecision) func(t *testing.T, got authorizer.ConditionsAwareDecision) {
	return func(t *testing.T, got authorizer.ConditionsAwareDecision) {
		t.Helper()
		if diff := cmp.Diff(want, snapshotDecision(got)); diff != "" {
			t.Errorf("partial decision mismatch (-want +got):\n%s", diff)
		}
	}
}
