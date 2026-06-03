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
	"errors"
	"fmt"
	"strconv"
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

// TestConditionsAwareDecisionPossibleDecisions exercises ConditionsAwareDecision.PossibleDecisions
// for every variant of the decision enum.
func TestConditionsAwareDecisionPossibleDecisions(t *testing.T) {
	possibleDecisionsTestSetup(t)

	condMapAllow := authorizer.ConditionsAwareDecisionConditionsMap(nil, nil, []authorizer.Condition{genericCond("allow-1")})
	condMapDeny := authorizer.ConditionsAwareDecisionConditionsMap([]authorizer.Condition{genericCond("deny-1")}, nil, nil)
	condMapDenyAndAllow := authorizer.ConditionsAwareDecisionConditionsMap(
		[]authorizer.Condition{genericCond("deny-1")},
		nil,
		[]authorizer.Condition{genericCond("allow-1")},
	)

	tests := []struct {
		name string
		d    authorizer.ConditionsAwareDecision
		want sets.Set[authorizer.Decision]
	}{
		{
			name: "Allow",
			d:    authorizer.ConditionsAwareDecisionAllow("ok", nil),
			want: sets.New(authorizer.DecisionAllow),
		},
		{
			name: "Allow with error still yields only Allow",
			d:    authorizer.ConditionsAwareDecisionAllow("ok", errors.New("warning")),
			want: sets.New(authorizer.DecisionAllow),
		},
		{
			name: "Deny",
			d:    authorizer.ConditionsAwareDecisionDeny("no", nil),
			want: sets.New(authorizer.DecisionDeny),
		},
		{
			name: "NoOpinion",
			d:    authorizer.ConditionsAwareDecisionNoOpinion("meh", nil),
			want: sets.New(authorizer.DecisionNoOpinion),
		},
		{
			name: "zero value is Deny",
			d:    authorizer.ConditionsAwareDecision{},
			want: sets.New(authorizer.DecisionDeny),
		},
		{
			name: "ConditionsMap delegates: allow-only",
			d:    condMapAllow,
			want: sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionAllow),
		},
		{
			name: "ConditionsMap delegates: deny-only",
			d:    condMapDeny,
			want: sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionDeny),
		},
		{
			name: "ConditionsMap delegates: deny + allow",
			d:    condMapDenyAndAllow,
			want: sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionAllow, authorizer.DecisionDeny),
		},
		{
			name: "Union delegates: single ConditionsMap(allow)",
			d:    unionDecision(condMapAllow),
			want: sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionAllow),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.d.PossibleDecisions()
			if !got.Equal(tt.want) {
				t.Errorf("PossibleDecisions() = %v, want %v", sortedDecisions(got), sortedDecisions(tt.want))
			}
		})
	}
}

// TestConditionsMapPossibleDecisions exercises ConditionsMap.PossibleDecisions for every
// non-empty combination of effect groups (deny/noOpinion/allow) the constructor accepts.
func TestConditionsMapPossibleDecisions(t *testing.T) {
	possibleDecisionsTestSetup(t)

	// extractConditionsMap returns the ConditionsMap inside a ConditionsAwareDecision.
	// For decisions that are not of ConditionsMap type (e.g. the empty-input constructor
	// short-circuits to NoOpinion), the embedded zero-value ConditionsMap is returned —
	// which itself has well-defined PossibleDecisions = {NoOpinion}.
	extractConditionsMap := func(_ *testing.T, d authorizer.ConditionsAwareDecision) authorizer.ConditionsMap {
		return d.ConditionsMap()
	}

	allow := []authorizer.Condition{genericCond("allow-1")}
	nop := []authorizer.Condition{genericCond("nop-1")}
	deny := []authorizer.Condition{genericCond("deny-1")}

	tests := []struct {
		name string
		d    authorizer.ConditionsAwareDecision
		want sets.Set[authorizer.Decision]
	}{
		{
			name: "empty -> static NoOpinion", // in fact folded to a NoOpinion with an error
			d:    authorizer.ConditionsAwareDecisionConditionsMap(nil, nil, nil),
			want: sets.New(authorizer.DecisionNoOpinion),
		},
		{
			name: "allow-only -> {NoOpinion, Allow}",
			d:    authorizer.ConditionsAwareDecisionConditionsMap(nil, nil, allow),
			want: sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionAllow),
		},
		{
			name: "deny-only -> {NoOpinion, Deny}",
			d:    authorizer.ConditionsAwareDecisionConditionsMap(deny, nil, nil),
			want: sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionDeny),
		},
		{
			name: "noOpinion + allow -> {NoOpinion, Allow}",
			d:    authorizer.ConditionsAwareDecisionConditionsMap(nil, nop, allow),
			want: sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionAllow),
		},
		{
			name: "deny + noOpinion -> {NoOpinion, Deny}",
			d:    authorizer.ConditionsAwareDecisionConditionsMap(deny, nop, nil),
			want: sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionDeny),
		},
		{
			name: "deny + allow -> {NoOpinion, Allow, Deny}",
			d:    authorizer.ConditionsAwareDecisionConditionsMap(deny, nil, allow),
			want: sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionAllow, authorizer.DecisionDeny),
		},
		{
			name: "deny + noOpinion + allow -> {NoOpinion, Allow, Deny}",
			d:    authorizer.ConditionsAwareDecisionConditionsMap(deny, nop, allow),
			want: sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionAllow, authorizer.DecisionDeny),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := extractConditionsMap(t, tt.d)
			got := cm.PossibleDecisions()
			if !got.Equal(tt.want) {
				t.Errorf("PossibleDecisions() = %v, want %v", sortedDecisions(got), sortedDecisions(tt.want))
			}
		})
	}
}

// TestConditionsAwareDecisionUnionPossibleDecisions exercises the PossibleDecisions method
// on ConditionsAwareDecisionUnion via the public Add/ToDecision API.
//
// Semantics:
//   - The default outcome of a union is NoOpinion (when every sub-decision evaluates to NoOpinion).
//   - A union short-circuits at the first sub-decision that yields a concrete Allow or Deny.
//   - A ConditionsMap sub-decision can yield NoOpinion at runtime, in which case evaluation
//     continues to the next sub-decision; therefore later concrete Allow/Deny outcomes remain reachable.
func TestConditionsAwareDecisionUnionPossibleDecisions(t *testing.T) {
	possibleDecisionsTestSetup(t)

	condMapAllow := authorizer.ConditionsAwareDecisionConditionsMap(nil, nil, []authorizer.Condition{genericCond("allow-1")})
	condMapDeny := authorizer.ConditionsAwareDecisionConditionsMap([]authorizer.Condition{genericCond("deny-1")}, nil, nil)
	condMapAllowDeny := authorizer.ConditionsAwareDecisionConditionsMap(
		[]authorizer.Condition{genericCond("deny-1")}, nil,
		[]authorizer.Condition{genericCond("allow-1")},
	)
	allow := authorizer.ConditionsAwareDecisionAllow("", nil)
	deny := authorizer.ConditionsAwareDecisionDeny("", nil)
	noOp := authorizer.ConditionsAwareDecisionNoOpinion("", nil)

	tests := []struct {
		name      string
		decisions []authorizer.ConditionsAwareDecision
		want      sets.Set[authorizer.Decision]
	}{
		{
			name:      "empty union -> {NoOpinion}",
			decisions: nil,
			want:      sets.New(authorizer.DecisionNoOpinion),
		},
		{
			name:      "single NoOpinion -> {NoOpinion}",
			decisions: []authorizer.ConditionsAwareDecision{noOp},
			want:      sets.New(authorizer.DecisionNoOpinion),
		},
		{
			name:      "single Allow -> {Allow}",
			decisions: []authorizer.ConditionsAwareDecision{allow},
			want:      sets.New(authorizer.DecisionAllow),
		},
		{
			name:      "single Deny -> {Deny}",
			decisions: []authorizer.ConditionsAwareDecision{deny},
			want:      sets.New(authorizer.DecisionDeny),
		},
		{
			name:      "single ConditionsMap(allow) -> {NoOpinion, Allow}",
			decisions: []authorizer.ConditionsAwareDecision{condMapAllow},
			want:      sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionAllow),
		},
		{
			name:      "single ConditionsMap(deny) -> {NoOpinion, Deny}",
			decisions: []authorizer.ConditionsAwareDecision{condMapDeny},
			want:      sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionDeny),
		},
		{
			name:      "all NoOpinions -> {NoOpinion}",
			decisions: []authorizer.ConditionsAwareDecision{noOp, noOp, noOp},
			want:      sets.New(authorizer.DecisionNoOpinion),
		},
		{
			name:      "[NoOpinion, Allow] -> {Allow} (Allow short-circuits past upstream NoOpinions)",
			decisions: []authorizer.ConditionsAwareDecision{noOp, allow},
			want:      sets.New(authorizer.DecisionAllow),
		},
		{
			name:      "[NoOpinion, Deny] -> {Deny}",
			decisions: []authorizer.ConditionsAwareDecision{noOp, deny},
			want:      sets.New(authorizer.DecisionDeny),
		},
		{
			name:      "[ConditionsMap(allow), Allow] -> {Allow} (CM allow or NoOpinion-then-Allow both yield Allow)",
			decisions: []authorizer.ConditionsAwareDecision{condMapAllow, allow},
			want:      sets.New(authorizer.DecisionAllow),
		},
		{
			name:      "[ConditionsMap(allow), Deny] -> {Allow, Deny} (CM allow -> Allow; CM NoOpinion -> Deny)",
			decisions: []authorizer.ConditionsAwareDecision{condMapAllow, deny},
			want:      sets.New(authorizer.DecisionAllow, authorizer.DecisionDeny),
		},
		{
			name:      "[ConditionsMap(deny), Allow] -> {Allow, Deny} (CM deny -> Deny; CM NoOpinion -> Allow)",
			decisions: []authorizer.ConditionsAwareDecision{condMapDeny, allow},
			want:      sets.New(authorizer.DecisionAllow, authorizer.DecisionDeny),
		},
		{
			name:      "[ConditionsMap(deny), Deny] -> {Deny}",
			decisions: []authorizer.ConditionsAwareDecision{condMapDeny, deny},
			want:      sets.New(authorizer.DecisionDeny),
		},
		{
			name:      "[ConditionsMap(allow), NoOpinion] -> {NoOpinion, Allow} (no downstream short-circuit)",
			decisions: []authorizer.ConditionsAwareDecision{condMapAllow, noOp},
			want:      sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionAllow),
		},
		{
			name:      "[ConditionsMap(allow), ConditionsMap(deny)] -> {NoOpinion, Allow, Deny}",
			decisions: []authorizer.ConditionsAwareDecision{condMapAllow, condMapDeny},
			want:      sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionAllow, authorizer.DecisionDeny),
		},
		{
			name:      "[ConditionsMap(deny+allow)] -> {NoOpinion, Allow, Deny}",
			decisions: []authorizer.ConditionsAwareDecision{condMapAllowDeny},
			want:      sets.New(authorizer.DecisionNoOpinion, authorizer.DecisionAllow, authorizer.DecisionDeny),
		},
		{
			name:      "[NoOpinion, ConditionsMap(allow), Deny] -> {Allow, Deny}",
			decisions: []authorizer.ConditionsAwareDecision{noOp, condMapAllow, deny},
			want:      sets.New(authorizer.DecisionAllow, authorizer.DecisionDeny),
		},
		{
			name:      "[ConditionsMap(allow), ConditionsMap(deny), Allow] -> {Allow, Deny}",
			decisions: []authorizer.ConditionsAwareDecision{condMapAllow, condMapDeny, allow},
			want:      sets.New(authorizer.DecisionAllow, authorizer.DecisionDeny),
		},
		{
			name:      "after first Allow, later elements are dropped by Add and have no effect",
			decisions: []authorizer.ConditionsAwareDecision{allow, deny, condMapAllow},
			want:      sets.New(authorizer.DecisionAllow),
		},
		{
			name:      "after first Deny, later elements are dropped by Add and have no effect",
			decisions: []authorizer.ConditionsAwareDecision{deny, allow, condMapAllow},
			want:      sets.New(authorizer.DecisionDeny),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var u authorizer.ConditionsAwareDecisionUnion
			for i, d := range tt.decisions {
				u.Add(strconv.Itoa(i), d)
			}
			got := u.PossibleDecisions()
			if !got.Equal(tt.want) {
				t.Errorf("PossibleDecisions() = %v, want %v", sortedDecisions(got), sortedDecisions(tt.want))
			}

			// Also verify that the equivalent ConditionsAwareDecision (via ToDecision) delegates
			// to the same set, so the two PossibleDecisions methods stay consistent.
			wrapped := u.ToDecision()
			if got := wrapped.PossibleDecisions(); !got.Equal(tt.want) {
				t.Errorf("wrapped.PossibleDecisions() = %v, want %v", sortedDecisions(got), sortedDecisions(tt.want))
			}
		})
	}
}

// TestConditionsAwareDecisionUnionAdd exercises the Add method's bookkeeping behavior:
// it must reject duplicate authorizer names and stop appending after the first Allow/Deny leaf.
func TestConditionsAwareDecisionUnionAdd(t *testing.T) {
	possibleDecisionsTestSetup(t)

	noOp := authorizer.ConditionsAwareDecisionNoOpinion("", nil)
	allow := authorizer.ConditionsAwareDecisionAllow("a", nil)
	deny := authorizer.ConditionsAwareDecisionDeny("d", nil)
	condMapAllow := authorizer.ConditionsAwareDecisionConditionsMap(nil, nil, []authorizer.Condition{genericCond("allow-1")})

	t.Run("duplicate authorizer name fails closed", func(t *testing.T) {
		var u authorizer.ConditionsAwareDecisionUnion
		u.Add("dup", noOp)
		u.Add("dup", noOp)
		u.Add("allow", authorizer.ConditionsAwareDecisionAllow("", nil))

		d := u.ToDecision()
		if !d.IsNoOpinion() {
			t.Errorf("expected NoOpinion (no Deny leaf), got %s", d.String())
		}
		if d.Error() == nil || !containsString(d.Error().Error(), `duplicate authorizerName "dup"`) {
			t.Errorf("expected aggregated duplicate error, got %v", d.Error())
		}
	})

	t.Run("duplicate after Deny leaf fails closed with Deny", func(t *testing.T) {
		var u authorizer.ConditionsAwareDecisionUnion
		u.Add("a", deny)
		// Add another duplicate "a" - this should NOT be skipped by the Allow/Deny short-circuit,
		// because the duplicate check runs first and appends to errs.
		u.Add("a", noOp)
		u.Add("allow", authorizer.ConditionsAwareDecisionAllow("", nil))

		d := u.ToDecision()
		if !d.IsDeny() {
			t.Errorf("expected Deny (deny leaf present), got %s", d.String())
		}
		if d.Error() == nil || !containsString(d.Error().Error(), `duplicate authorizerName "a"`) {
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

// TestConditionsAwareDecisionUnionToDecision exercises the simplification behavior
// of ToDecision when the set of PossibleDecisions has cardinality 1.
func TestConditionsAwareDecisionUnionToDecision(t *testing.T) {
	possibleDecisionsTestSetup(t)

	condMapAllow := authorizer.ConditionsAwareDecisionConditionsMap(nil, nil, []authorizer.Condition{genericCond("allow-1")})
	condMapDeny := authorizer.ConditionsAwareDecisionConditionsMap([]authorizer.Condition{genericCond("deny-1")}, nil, nil)
	allow := authorizer.ConditionsAwareDecisionAllow("a", nil)
	deny := authorizer.ConditionsAwareDecisionDeny("d", nil)
	noOp := authorizer.ConditionsAwareDecisionNoOpinion("n", nil)

	tests := []struct {
		name          string
		decisions     []authorizer.ConditionsAwareDecision
		wantDecision  authorizer.Decision // the unconditional decision type, or -1 if expecting Union
		wantIsUnion   bool
		wantInnerLen  int      // when wantIsUnion, expected number of wrapped sub-decisions
		wantInnerStrs []string // when wantIsUnion, expected String() values of the wrapped sub-decisions
	}{
		{
			name:         "empty -> NoOpinion (default)",
			decisions:    nil,
			wantDecision: authorizer.DecisionNoOpinion,
		},
		{
			name:         "single Allow -> Allow",
			decisions:    []authorizer.ConditionsAwareDecision{allow},
			wantDecision: authorizer.DecisionAllow,
		},
		{
			name:         "single Deny -> Deny",
			decisions:    []authorizer.ConditionsAwareDecision{deny},
			wantDecision: authorizer.DecisionDeny,
		},
		{
			name:         "single NoOpinion -> NoOpinion",
			decisions:    []authorizer.ConditionsAwareDecision{noOp},
			wantDecision: authorizer.DecisionNoOpinion,
		},
		{
			name:         "all NoOpinions -> NoOpinion",
			decisions:    []authorizer.ConditionsAwareDecision{noOp, noOp, noOp},
			wantDecision: authorizer.DecisionNoOpinion,
		},
		{
			name:         "[NoOpinion, Allow] simplifies to Allow",
			decisions:    []authorizer.ConditionsAwareDecision{noOp, allow},
			wantDecision: authorizer.DecisionAllow,
		},
		{
			name:         "[NoOpinion, Deny] simplifies to Deny",
			decisions:    []authorizer.ConditionsAwareDecision{noOp, deny},
			wantDecision: authorizer.DecisionDeny,
		},
		{
			name:         "[ConditionsMap(allow), Allow] simplifies to Allow",
			decisions:    []authorizer.ConditionsAwareDecision{condMapAllow, allow},
			wantDecision: authorizer.DecisionAllow,
		},
		{
			name:         "[ConditionsMap(deny), Deny] simplifies to Deny",
			decisions:    []authorizer.ConditionsAwareDecision{condMapDeny, deny},
			wantDecision: authorizer.DecisionDeny,
		},
		{
			// ConditionsMap may evaluate to NoOpinion or Allow; with a downstream Deny, both Allow and Deny remain reachable.
			name:          "[ConditionsMap(allow), Deny] stays Union",
			decisions:     []authorizer.ConditionsAwareDecision{condMapAllow, deny},
			wantIsUnion:   true,
			wantInnerLen:  2,
			wantInnerStrs: []string{`ConditionsMap(len=1)`, `Deny(reason="d")`},
		},
		{
			name:          "[ConditionsMap(deny), Allow] stays Union",
			decisions:     []authorizer.ConditionsAwareDecision{condMapDeny, allow},
			wantIsUnion:   true,
			wantInnerLen:  2,
			wantInnerStrs: []string{`ConditionsMap(len=1)`, `Allow(reason="a")`},
		},
		{
			name:          "[ConditionsMap(allow), NoOpinion] stays Union",
			decisions:     []authorizer.ConditionsAwareDecision{condMapAllow, noOp},
			wantIsUnion:   true,
			wantInnerLen:  2,
			wantInnerStrs: []string{`ConditionsMap(len=1)`, `NoOpinion(reason="n")`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var u authorizer.ConditionsAwareDecisionUnion
			for i, d := range tt.decisions {
				u.Add(strconv.Itoa(i), d)
			}
			got := u.ToDecision()

			if tt.wantIsUnion {
				if !got.IsUnion() {
					t.Fatalf("expected Union, got %s", got.String())
				}
				var innerStrs []string
				for _, sub := range got.UnionedDecisions() {
					innerStrs = append(innerStrs, sub.String())
				}
				if len(innerStrs) != tt.wantInnerLen {
					t.Errorf("expected %d inner decisions, got %d (%v)", tt.wantInnerLen, len(innerStrs), innerStrs)
				}
				if !stringSlicesEqual(innerStrs, tt.wantInnerStrs) {
					t.Errorf("inner decisions = %v, want %v", innerStrs, tt.wantInnerStrs)
				}
				return
			}

			switch tt.wantDecision {
			case authorizer.DecisionAllow:
				if !got.IsAllow() {
					t.Errorf("expected Allow, got %s", got.String())
				}
			case authorizer.DecisionDeny:
				if !got.IsDeny() {
					t.Errorf("expected Deny, got %s", got.String())
				}
			case authorizer.DecisionNoOpinion:
				if !got.IsNoOpinion() {
					t.Errorf("expected NoOpinion, got %s", got.String())
				}
			default:
				t.Fatalf("test setup error: wantDecision=%v", tt.wantDecision)
			}
		})
	}
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
