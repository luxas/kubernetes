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
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	genericfeatures "k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
)

// genericCond builds a no-op GenericCondition with the given ID.
func genericCond(id string) authorizer.Condition {
	return authorizer.GenericCondition{ID: id, Condition: "x", Type: "test"}
}

// possibleDecisionsTestSetup enables the conditional authorization feature gate.
func possibleDecisionsTestSetup(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, genericfeatures.ConditionalAuthorization, true)
}

// TestConditionsAwareDecisionUnionAdd exercises the Add method's bookkeeping behavior:
// it must reject duplicate authorizer names and stop appending after the first Allow/Deny leaf.
func TestConditionsAwareDecisionUnionAdd(t *testing.T) {
	possibleDecisionsTestSetup(t)

	noOp := authorizer.ConditionsAwareDecisionNoOpinion("", nil)
	allow := authorizer.ConditionsAwareDecisionAllow("a", nil)
	deny := authorizer.ConditionsAwareDecisionDeny("d", nil)
	condMapAllow := authorizer.ConditionsAwareDecisionConditionsMap(nil, nil, []authorizer.Condition{genericCond("allow-1")})
	condMapDeny := authorizer.ConditionsAwareDecisionConditionsMap([]authorizer.Condition{genericCond("deny-1")}, nil, nil)

	t.Run("duplicate conditional authorizers fails closed", func(t *testing.T) {
		var u authorizer.ConditionsAwareDecisionUnion
		u.Add("nop", noOp)
		u.Add("dup", condMapAllow)
		u.Add("dup", condMapAllow)

		d := u.ToDecision()
		if !d.IsNoOpinion() {
			t.Errorf("expected NoOpinion (no Deny leaf), got %s", d.String())
		}
		if d.Error() == nil || !containsString(d.Error().Error(), `duplicate authorizerName "dup"`) {
			t.Errorf("expected aggregated duplicate error, got %v", d.Error())
		}
	})

	t.Run("duplicate when outcome could be deny fails closed", func(t *testing.T) {
		var u authorizer.ConditionsAwareDecisionUnion
		u.Add("dup", condMapAllow)
		u.Add("dup", condMapDeny)
		u.Add("a", allow)

		d := u.ToDecision()
		if !d.IsDeny() {
			t.Errorf("expected Deny (deny leaf present), got %s", d.String())
		}
		if d.Error() == nil || !containsString(d.Error().Error(), `duplicate authorizerName "dup"`) {
			t.Errorf("expected aggregated duplicate error, got %v", d.Error())
		}
	})

	t.Run("Allow leaf short-circuits subsequent Adds", func(t *testing.T) {
		var u authorizer.ConditionsAwareDecisionUnion
		u.Add("0", noOp)
		u.Add("1", allow)
		// These additions must be silently dropped by the ContainsAllowOrDeny short-circuit.
		u.Add("2", deny)
		u.Add("3", condMapAllow)

		d := u.ToDecision()
		if !d.IsAllow() {
			t.Errorf("expected Allow after short-circuit, got %s", d.String())
		}

		// Iterating the resulting union should only see the entries before/at the short-circuit point.
		seen := map[string]bool{}
		for name := range d.UnionedDecisions() {
			seen[name] = true
		}
		// The wrapped decision is unconditional Allow, so UnionedDecisions is empty.
		if len(seen) != 0 {
			t.Errorf("expected unconditional Allow to expose no unioned decisions, got %v", seen)
		}
	})

	t.Run("Deny leaf short-circuits subsequent Adds", func(t *testing.T) {
		var u authorizer.ConditionsAwareDecisionUnion
		u.Add("0", noOp)
		u.Add("1", deny)
		u.Add("2", allow)
		u.Add("3", condMapAllow)

		d := u.ToDecision()
		if !d.IsDeny() {
			t.Errorf("expected Deny after short-circuit, got %s", d.String())
		}
	})

	t.Run("ConditionsMap leaves do not short-circuit Add", func(t *testing.T) {
		var u authorizer.ConditionsAwareDecisionUnion
		u.Add("0", condMapAllow)
		u.Add("1", condMapAllow) // distinct authorizerName, still appended
		u.Add("2", noOp)

		d := u.ToDecision()
		if !d.IsUnion() {
			t.Fatalf("expected Union, got %s", d.String())
		}

		var names []string
		for name := range d.UnionedDecisions() {
			names = append(names, name)
		}
		want := []string{"0", "1", "2"}
		if !stringSlicesEqual(names, want) {
			t.Errorf("UnionedDecisions names = %v, want %v", names, want)
		}
	})
}

// TestConditionsAwareDecisionUnionToDecisionPostMutation verifies that mutating the source
// ConditionsAwareDecisionUnion after calling ToDecision does NOT change the returned decision.
// (The patch explicitly clones the inner slice in ToDecision for this reason.)
func TestConditionsAwareDecisionUnionToDecisionPostMutation(t *testing.T) {
	possibleDecisionsTestSetup(t)

	condMapAllow := authorizer.ConditionsAwareDecisionConditionsMap(nil, nil, []authorizer.Condition{genericCond("allow-1")})

	var u authorizer.ConditionsAwareDecisionUnion
	u.Add("0", condMapAllow)
	u.Add("1", condMapAllow) // distinct name -> distinct entry
	snapshot := u.ToDecision()

	// Sanity: snapshot has 2 inner entries.
	var beforeNames []string
	for name := range snapshot.UnionedDecisions() {
		beforeNames = append(beforeNames, name)
	}
	if !stringSlicesEqual(beforeNames, []string{"0", "1"}) {
		t.Fatalf("setup: snapshot inner = %v, want [0 1]", beforeNames)
	}

	// Mutate u after the snapshot was taken. snapshot must remain unchanged.
	u.Add("2", condMapAllow)

	var afterNames []string
	for name := range snapshot.UnionedDecisions() {
		afterNames = append(afterNames, name)
	}
	if !stringSlicesEqual(afterNames, []string{"0", "1"}) {
		t.Errorf("post-mutation snapshot inner = %v, want [0 1]; ToDecision must clone", afterNames)
	}
}

// containsString reports whether s contains substr (replacement for strings.Contains to
// avoid adding another import).
func containsString(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// stringSlicesEqual reports whether two []string are element-wise equal.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sortedDecisions returns the elements of s as a stable, sorted slice for error messages.
func sortedDecisions(s sets.Set[authorizer.Decision]) []string {
	out := make([]string, 0, s.Len())
	for _, d := range s.UnsortedList() {
		out = append(out, fmt.Sprintf("%v", d))
	}
	// simple insertion sort to avoid an extra dep
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
