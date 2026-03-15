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
	"testing"
)

func TestConditionsMapEvaluate(t *testing.T) {
	evalErr := errors.New("eval error")

	// TODO: Prefix all these with authorizer.XX, as the test package != authorizer package (to test as external consumers)
	trueResult := ConditionEvaluationResultBoolean(true)
	falseResult := ConditionEvaluationResultBoolean(false)
	errResult := ConditionEvaluationResultError(evalErr)

	cond := func(id string, effect ConditionEffect, result ConditionEvaluationResult) GenericCondition {
		return GenericCondition{
			ID:     id,
			Effect: effect,
			EvaluateFunc: func(context.Context, ConditionsData) ConditionEvaluationResult {
				return result
			},
		}
	}
	condDesc := func(id string, effect ConditionEffect, desc string, result ConditionEvaluationResult) GenericCondition {
		c := cond(id, effect, result)
		c.Description = desc
		return c
	}
	unevalCond := func(id string, effect ConditionEffect) GenericCondition {
		return GenericCondition{ID: id, Effect: effect} // nil EvaluateFunc → unevaluatable
	}

	tests := []struct {
		name string
		// TODO: break out cm and evaluateFunc into sub-testcases, that assert the same output.
		cm           ConditionsMap
		evaluateFunc func(context.Context, ConditionsData, Condition) ConditionEvaluationResult
		wantString   string
		// For ConditionsMap results, additionally verify structure:
		wantIsConditionsMap bool
		wantDenyCount       int
		wantNoOpinionCount  int
		wantAllowCount      int
	}{
		// ===== Deny evaluation =====
		{
			name:       "at least one deny matches",
			cm:         ConditionsMap{denyConditions: []Condition{cond("deny-1", ConditionEffectDeny, trueResult)}},
			wantString: `Deny(reason="[condition \"deny-1\" denied the request]")`,
		},
		{
			name:       "at least one deny matches with description",
			cm:         ConditionsMap{denyConditions: []Condition{condDesc("deny-1", ConditionEffectDeny, "access denied", trueResult)}},
			wantString: `Deny(reason="[condition \"deny-1\" denied the request with description \"access denied\"]")`,
		},
		{
			// TODO: Add false Deny conditions and Allow conditions that are unevaluated, false, and error
			name:       "no deny condition matches, but at least one error",
			cm:         ConditionsMap{denyConditions: []Condition{cond("deny-1", ConditionEffectDeny, errResult)}},
			wantString: `Deny(reason="one or more conditional evaluation errors occurred", err="Deny condition \"deny-1\" produced error: eval error")`,
		},
		{
			// TODO: Add false Allow and NoOpinion conditions here
			name:       "no deny condition matches, and no errors",
			cm:         ConditionsMap{denyConditions: []Condition{cond("deny-1", ConditionEffectDeny, falseResult)}},
			wantString: `NoOpinion(reason="no conditions matched")`,
		},

		// ===== NoOpinion evaluation =====
		{
			// TODO: Add some NoOpinion conditions that are unevaluated, false, and error.
			// TODO: Add false Deny conditions and Allow conditions that are unevaluated, false, and error
			name:       "at least one noopinion matches",
			cm:         ConditionsMap{noOpinionConditions: []Condition{cond("nop-1", ConditionEffectNoOpinion, trueResult)}},
			wantString: `NoOpinion(reason="[condition \"nop-1\" evaluated to NoOpinion]")`,
		},
		{
			// TODO: Add some NoOpinion conditions that are unevaluated, false, and error.
			// TODO: Add false Deny conditions and Allow conditions that are unevaluated, false, and error
			name:       "at least one noopinion matches with description",
			cm:         ConditionsMap{noOpinionConditions: []Condition{condDesc("nop-1", ConditionEffectNoOpinion, "not relevant", trueResult)}},
			wantString: `NoOpinion(reason="[condition \"nop-1\" evaluated to NoOpinion with description \"not relevant\"]")`,
		},
		{
			// TODO: Add some NoOpinion conditions that are unevaluated and false too.
			// TODO: Add false Deny conditions and Allow conditions that are unevaluated, false, and error
			name:       "no noopinion condition matches, but at least one error",
			cm:         ConditionsMap{noOpinionConditions: []Condition{cond("nop-1", ConditionEffectNoOpinion, errResult)}},
			wantString: `NoOpinion(reason="one or more conditional evaluation errors occurred", err="NoOpinion condition \"nop-1\" produced error: eval error")`,
		},
		{
			// TODO: Add false Deny and Allow conditions here
			name:       "no noopinion condition matches, and no errors",
			cm:         ConditionsMap{noOpinionConditions: []Condition{cond("nop-1", ConditionEffectNoOpinion, falseResult)}},
			wantString: `NoOpinion(reason="no conditions matched")`,
		},

		// ===== Basic allow evaluation =====
		{
			// TODO: Add false NoOpinion and Deny conditions here
			name:       "at least one allow matches",
			cm:         ConditionsMap{allowConditions: []Condition{cond("allow-1", ConditionEffectAllow, trueResult)}},
			wantString: `Allow(reason="[condition \"allow-1\" allowed the request]")`,
		},
		{
			// TODO: Add false NoOpinion and Deny conditions here
			name:       "at least one allow matches with description",
			cm:         ConditionsMap{allowConditions: []Condition{condDesc("allow-1", ConditionEffectAllow, "access granted", trueResult)}},
			wantString: `Allow(reason="[condition \"allow-1\" allowed the request with description \"access granted\"]")`,
		},
		{
			// TODO: Add false NoOpinion and Deny conditions here
			name:       "no allow condition matches, but at least one error",
			cm:         ConditionsMap{allowConditions: []Condition{cond("allow-1", ConditionEffectAllow, errResult)}},
			wantString: `NoOpinion(reason="one or more conditional evaluation errors occurred", err="Allow condition \"allow-1\" produced error: eval error")`,
		},
		{
			// TODO: Add false NoOpinion and Deny conditions here
			name:       "no allow condition matches, and no errors",
			cm:         ConditionsMap{allowConditions: []Condition{cond("allow-1", ConditionEffectAllow, falseResult)}},
			wantString: `NoOpinion(reason="no conditions matched")`,
		},

		// ===== Precedence: Deny > NoOpinion > Allow =====
		// TODO: Bake these test cases into the assertions above.
		{
			name: "deny takes precedence over allow",
			cm: ConditionsMap{
				denyConditions:  []Condition{cond("deny-1", ConditionEffectDeny, trueResult)},
				allowConditions: []Condition{cond("allow-1", ConditionEffectAllow, trueResult)},
			},
			wantString: `Deny(reason="[condition \"deny-1\" denied the request]")`,
		},
		{
			name: "deny takes precedence over noopinion and allow",
			cm: ConditionsMap{
				denyConditions:      []Condition{cond("deny-1", ConditionEffectDeny, trueResult)},
				noOpinionConditions: []Condition{cond("nop-1", ConditionEffectNoOpinion, trueResult)},
				allowConditions:     []Condition{cond("allow-1", ConditionEffectAllow, trueResult)},
			},
			wantString: `Deny(reason="[condition \"deny-1\" denied the request]")`,
		},
		{
			name: "noopinion takes precedence over allow",
			cm: ConditionsMap{
				noOpinionConditions: []Condition{cond("nop-1", ConditionEffectNoOpinion, trueResult)},
				allowConditions:     []Condition{cond("allow-1", ConditionEffectAllow, trueResult)},
			},
			wantString: `NoOpinion(reason="[condition \"nop-1\" evaluated to NoOpinion]")`,
		},
		{
			name: "deny no match, noopinion matches, allow matches",
			cm: ConditionsMap{
				denyConditions:      []Condition{cond("deny-1", ConditionEffectDeny, falseResult)},
				noOpinionConditions: []Condition{cond("nop-1", ConditionEffectNoOpinion, trueResult)},
				allowConditions:     []Condition{cond("allow-1", ConditionEffectAllow, trueResult)},
			},
			wantString: `NoOpinion(reason="[condition \"nop-1\" evaluated to NoOpinion]")`,
		},
		{
			name: "only allow matches",
			cm: ConditionsMap{
				denyConditions:      []Condition{cond("deny-1", ConditionEffectDeny, falseResult)},
				noOpinionConditions: []Condition{cond("nop-1", ConditionEffectNoOpinion, falseResult)},
				allowConditions:     []Condition{cond("allow-1", ConditionEffectAllow, trueResult)},
			},
			wantString: `Allow(reason="[condition \"allow-1\" allowed the request]")`,
		},
		{
			name: "no conditions match across all effects",
			cm: ConditionsMap{
				denyConditions:      []Condition{cond("deny-1", ConditionEffectDeny, falseResult)},
				noOpinionConditions: []Condition{cond("nop-1", ConditionEffectNoOpinion, falseResult)},
				allowConditions:     []Condition{cond("allow-1", ConditionEffectAllow, falseResult)},
			},
			wantString: `NoOpinion(reason="no conditions matched")`,
		},

		// ===== Multiple conditions of the same effect =====
		{
			name: "multiple deny conditions, one match is enough",
			cm: ConditionsMap{denyConditions: []Condition{
				cond("deny-yes", ConditionEffectDeny, trueResult),
				cond("deny-no", ConditionEffectDeny, falseResult),
			}},
			wantString: `Deny(reason="[condition \"deny-yes\" denied the request]")`,
		},
		{
			name: "first noopinion no match, second matches",
			cm: ConditionsMap{noOpinionConditions: []Condition{
				cond("nop-no", ConditionEffectNoOpinion, falseResult),
				cond("nop-yes", ConditionEffectNoOpinion, trueResult),
			}},
			wantString: `NoOpinion(reason="[condition \"nop-yes\" evaluated to NoOpinion]")`,
		},
		{
			name: "first allow no match, second matches",
			cm: ConditionsMap{allowConditions: []Condition{
				cond("allow-no", ConditionEffectAllow, falseResult),
				cond("allow-yes", ConditionEffectAllow, trueResult),
			}},
			wantString: `NoOpinion(reason="[condition \"allow-yes\" allowed the request]")`,
		},

		// ===== Matching condition ignores errors of same effect =====
		{
			name: "deny matches + deny errors + deny unevaluatable -> match wins, no error",
			cm: ConditionsMap{denyConditions: []Condition{
				cond("deny-nomatch", ConditionEffectDeny, falseResult), // false is ignored
				cond("deny-err", ConditionEffectDeny, errResult),       // ignored due to match below
				unevalCond("deny-uneval", ConditionEffectDeny),         // ignored due to match below
				cond("deny-match", ConditionEffectDeny, trueResult),
			}},
			wantString: `Deny(reason="[condition \"deny-match\" denied the request]")`,
		},
		{
			name: "noopinion matches + noopinion errors + noopinion unevaluatable -> match wins, no error",
			cm: ConditionsMap{noOpinionConditions: []Condition{
				cond("deny-nomatch", ConditionEffectDeny, falseResult),     // false is ignored
				cond("nop-nomatch", ConditionEffectNoOpinion, falseResult), // false is ignored
				cond("nop-err", ConditionEffectNoOpinion, errResult),       // ignored due to match below
				unevalCond("nop-uneval", ConditionEffectNoOpinion),         // ignored due to match below
				cond("nop-match", ConditionEffectNoOpinion, trueResult),
			}},
			wantString: `NoOpinion(reason="[condition \"nop-match\" evaluated to NoOpinion]")`,
		},

		// ===== Error precedence across effects =====
		{
			name: "deny errors + allow matches -> deny error trumps allow",
			cm: ConditionsMap{
				denyConditions:  []Condition{cond("deny-1", ConditionEffectDeny, errResult)},
				allowConditions: []Condition{cond("allow-1", ConditionEffectAllow, trueResult)},
			},
			wantString: `Deny(reason="one or more conditional evaluation errors occurred", err="Deny condition \"deny-1\" produced error: eval error")`,
		},
		{
			name: "noopinion errors + allow matches -> noopinion error trumps allow",
			cm: ConditionsMap{
				noOpinionConditions: []Condition{cond("nop-1", ConditionEffectNoOpinion, errResult)},
				allowConditions:     []Condition{cond("allow-1", ConditionEffectAllow, trueResult)},
			},
			wantString: `NoOpinion(reason="one or more conditional evaluation errors occurred", err="NoOpinion condition \"nop-1\" produced error: eval error")`,
		},
		{
			name: "deny errors + deny unevaluatable -> error takes precedence over unevaluatable",
			cm: ConditionsMap{denyConditions: []Condition{
				cond("deny-err", ConditionEffectDeny, errResult),
				unevalCond("deny-uneval", ConditionEffectDeny),
			}},
			wantString: `Deny(reason="one or more conditional evaluation errors occurred", err="Deny condition \"deny-err\" produced error: eval error")`,
		},
		{
			name: "deny no match, noopinion errors",
			cm: ConditionsMap{
				denyConditions:      []Condition{cond("deny-1", ConditionEffectDeny, falseResult)},
				noOpinionConditions: []Condition{cond("nop-1", ConditionEffectNoOpinion, errResult)},
			},
			wantString: `NoOpinion(reason="one or more conditional evaluation errors occurred", err="NoOpinion condition \"nop-1\" produced error: eval error")`,
		},

		// ===== Allow errors =====
		{
			name: "allow one errors one matches -> allow with error warning",
			cm: ConditionsMap{allowConditions: []Condition{
				cond("allow-err", ConditionEffectAllow, errResult),
				cond("allow-ok", ConditionEffectAllow, trueResult),
			}},
			wantString: `Allow(reason="[condition \"allow-ok\" allowed the request]", err="Allow condition \"allow-err\" produced error: eval error")`,
		},
		{
			name: "allow both error",
			cm: ConditionsMap{allowConditions: []Condition{
				cond("allow-err1", ConditionEffectAllow, errResult),
				cond("allow-err2", ConditionEffectAllow, errResult),
			}},
			wantString: `NoOpinion(reason="one or more conditional evaluation errors occurred", err="[Allow condition \"allow-err1\" produced error: eval error, Allow condition \"allow-err2\" produced error: eval error]")`,
		},

		// ===== Unevaluatable -> refined ConditionsMap (requirement a) =====
		{
			name: "deny unevaluatable -> refined ConditionsMap with deep-copied nop and allow",
			cm: ConditionsMap{
				denyConditions:      []Condition{unevalCond("deny-1", ConditionEffectDeny)},
				noOpinionConditions: []Condition{cond("nop-1", ConditionEffectNoOpinion, trueResult)},
				allowConditions:     []Condition{cond("allow-1", ConditionEffectAllow, trueResult)},
			},
			wantString:          `ConditionsMap(len=3)`,
			wantIsConditionsMap: true,
			wantDenyCount:       1,
			wantNoOpinionCount:  1,
			wantAllowCount:      1,
		},
		{
			name: "deny one false one unevaluatable -> refined ConditionsMap with only unevaluated deny",
			cm: ConditionsMap{
				denyConditions: []Condition{
					cond("deny-false", ConditionEffectDeny, falseResult),
					unevalCond("deny-uneval", ConditionEffectDeny),
				},
				noOpinionConditions: []Condition{cond("nop-1", ConditionEffectNoOpinion, trueResult)},
				allowConditions:     []Condition{cond("allow-1", ConditionEffectAllow, trueResult)},
			},
			wantString:          `ConditionsMap(len=3)`,
			wantIsConditionsMap: true,
			wantDenyCount:       1,
			wantNoOpinionCount:  1,
			wantAllowCount:      1,
		},
		{
			name: "deny matches trumps unevaluatable nop and allow",
			cm: ConditionsMap{
				denyConditions:      []Condition{cond("deny-1", ConditionEffectDeny, trueResult)},
				noOpinionConditions: []Condition{unevalCond("nop-1", ConditionEffectNoOpinion)},
				allowConditions:     []Condition{unevalCond("allow-1", ConditionEffectAllow)},
			},
			wantString: `Deny(reason="[condition \"deny-1\" denied the request]")`,
		},
		{
			name: "noopinion unevaluatable + allow present -> refined ConditionsMap",
			cm: ConditionsMap{
				noOpinionConditions: []Condition{unevalCond("nop-1", ConditionEffectNoOpinion)},
				allowConditions:     []Condition{cond("allow-1", ConditionEffectAllow, trueResult)},
			},
			wantString:          `ConditionsMap(len=2)`,
			wantIsConditionsMap: true,
			wantNoOpinionCount:  1,
			wantAllowCount:      1,
		},
		{
			name:       "noopinion unevaluatable + no allow -> NoOpinion",
			cm:         ConditionsMap{noOpinionConditions: []Condition{unevalCond("nop-1", ConditionEffectNoOpinion)}},
			wantString: `NoOpinion(reason="at least one NoOpinion condition matched, or no conditions matched")`,
		},
		{
			name:                "allow unevaluatable -> refined ConditionsMap",
			cm:                  ConditionsMap{allowConditions: []Condition{unevalCond("allow-1", ConditionEffectAllow)}},
			wantString:          `ConditionsMap(len=1)`,
			wantIsConditionsMap: true,
			wantAllowCount:      1,
		},
		{
			name: "noopinion matches trumps unevaluatable allow",
			cm: ConditionsMap{
				noOpinionConditions: []Condition{cond("nop-1", ConditionEffectNoOpinion, trueResult)},
				allowConditions:     []Condition{unevalCond("allow-1", ConditionEffectAllow)},
			},
			wantString: `NoOpinion(reason="[condition \"nop-1\" evaluated to NoOpinion]")`,
		},

		// ===== evaluateFunc behavior (requirement b) =====
		{
			name:       "evaluateFunc nil, condition evaluates to true",
			cm:         ConditionsMap{allowConditions: []Condition{cond("allow-1", ConditionEffectAllow, trueResult)}},
			wantString: `Allow(reason="[condition \"allow-1\" allowed the request]")`,
		},
		{
			name:                "evaluateFunc nil, condition unevaluatable -> refined ConditionsMap",
			cm:                  ConditionsMap{allowConditions: []Condition{unevalCond("allow-1", ConditionEffectAllow)}},
			wantString:          `ConditionsMap(len=1)`,
			wantIsConditionsMap: true,
			wantAllowCount:      1,
		},
		{
			name: "condition evaluates to true, evaluateFunc not called",
			cm:   ConditionsMap{allowConditions: []Condition{cond("allow-1", ConditionEffectAllow, trueResult)}},
			evaluateFunc: func(context.Context, ConditionsData, Condition) ConditionEvaluationResult {
				panic("evaluateFunc should not be called when condition.Evaluate returns non-unevaluatable")
			},
			wantString: `Allow(reason="[condition \"allow-1\" allowed the request]")`,
		},
		{
			name: "condition errors, evaluateFunc not called",
			cm:   ConditionsMap{allowConditions: []Condition{cond("allow-1", ConditionEffectAllow, errResult)}},
			evaluateFunc: func(context.Context, ConditionsData, Condition) ConditionEvaluationResult {
				panic("evaluateFunc should not be called when condition.Evaluate returns non-unevaluatable")
			},
			wantString: `NoOpinion(reason="one or more conditional evaluation errors occurred", err="Allow condition \"allow-1\" produced error: eval error")`,
		},
		{
			name: "condition unevaluatable, evaluateFunc returns true",
			cm:   ConditionsMap{allowConditions: []Condition{unevalCond("allow-1", ConditionEffectAllow)}},
			evaluateFunc: func(context.Context, ConditionsData, Condition) ConditionEvaluationResult {
				return ConditionEvaluationResultBoolean(true)
			},
			wantString: `Allow(reason="[condition \"allow-1\" allowed the request]")`,
		},
		{
			name: "condition unevaluatable, evaluateFunc returns false",
			cm:   ConditionsMap{allowConditions: []Condition{unevalCond("allow-1", ConditionEffectAllow)}},
			evaluateFunc: func(context.Context, ConditionsData, Condition) ConditionEvaluationResult {
				return ConditionEvaluationResultBoolean(false)
			},
			wantString: `NoOpinion(reason="no conditions matched")`,
		},
		{
			name: "condition unevaluatable, evaluateFunc returns error",
			cm:   ConditionsMap{allowConditions: []Condition{unevalCond("allow-1", ConditionEffectAllow)}},
			evaluateFunc: func(context.Context, ConditionsData, Condition) ConditionEvaluationResult {
				return ConditionEvaluationResultError(evalErr)
			},
			wantString: `NoOpinion(reason="one or more conditional evaluation errors occurred", err="Allow condition \"allow-1\" produced error: eval error")`,
		},
		{
			name: "condition unevaluatable, evaluateFunc also unevaluatable",
			cm:   ConditionsMap{allowConditions: []Condition{unevalCond("allow-1", ConditionEffectAllow)}},
			evaluateFunc: func(context.Context, ConditionsData, Condition) ConditionEvaluationResult {
				return ConditionsEvaluationResultUnevaluatable()
			},
			wantString:          `ConditionsMap(len=1)`,
			wantIsConditionsMap: true,
			wantAllowCount:      1,
		},
		{
			name: "deny condition unevaluatable, evaluateFunc returns true for deny",
			cm: ConditionsMap{
				denyConditions:  []Condition{unevalCond("deny-1", ConditionEffectDeny)},
				allowConditions: []Condition{cond("allow-1", ConditionEffectAllow, trueResult)},
			},
			evaluateFunc: func(context.Context, ConditionsData, Condition) ConditionEvaluationResult {
				return ConditionEvaluationResultBoolean(true)
			},
			wantString: `Deny(reason="[condition \"deny-1\" denied the request]")`,
		},

		// ===== Empty =====
		{
			name:       "empty ConditionsMap",
			cm:         ConditionsMap{},
			wantString: `NoOpinion(reason="no conditions matched")`,
		},
		{
			name:       "empty condition slices",
			cm:         ConditionsMap{denyConditions: []Condition{}, noOpinionConditions: []Condition{}, allowConditions: []Condition{}},
			wantString: `NoOpinion(reason="no conditions matched")`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TODO: Construct cm from the list of conditions, to exercise more of the flow.
			result := tt.cm.Evaluate(t.Context(), ConditionsData{}, tt.evaluateFunc)
			if got := result.String(); got != tt.wantString {
				t.Errorf("got decision %s, want %s", got, tt.wantString)
			}
			if tt.wantIsConditionsMap {
				if !result.IsConditionsMap() {
					t.Fatalf("expected ConditionsMap decision, got %s", result.String())
				}
				cm := result.ConditionsMap()
				if got := len(cm.denyConditions); got != tt.wantDenyCount {
					t.Errorf("deny count = %d, want %d", got, tt.wantDenyCount)
				}
				if got := len(cm.noOpinionConditions); got != tt.wantNoOpinionCount {
					t.Errorf("noopinion count = %d, want %d", got, tt.wantNoOpinionCount)
				}
				if got := len(cm.allowConditions); got != tt.wantAllowCount {
					t.Errorf("allow count = %d, want %d", got, tt.wantAllowCount)
				}
			}
		})
	}
}

// TestConditionsMapEvaluateDeepCopy verifies that when a refined ConditionsMap is returned
// because some conditions are unevaluatable, the non-evaluated conditions from lower-priority
// effect groups are deep-copied and independent from the original.
func TestConditionsMapEvaluateDeepCopy(t *testing.T) {
	ctx := context.Background()
	data := ConditionsData{}

	marker := "original"
	original := ConditionsMap{
		denyConditions: []Condition{
			// Unevaluatable deny → triggers refined ConditionsMap with deep-copied nop and allow
			GenericCondition{ID: "deny-uneval", Effect: ConditionEffectDeny},
		},
		noOpinionConditions: []Condition{
			&deepCopyTracker{id: "nop-1", effect: ConditionEffectNoOpinion, marker: &marker},
		},
		allowConditions: []Condition{
			&deepCopyTracker{id: "allow-1", effect: ConditionEffectAllow, marker: &marker},
		},
	}

	result := original.Evaluate(ctx, data, nil)
	if !result.IsConditionsMap() {
		t.Fatalf("expected ConditionsMap, got %s", result.String())
	}

	refined := result.ConditionsMap()
	if refined.Length() != 3 {
		t.Fatalf("expected 3 conditions in refined map, got %d", refined.Length())
	}

	// Mutate the original marker
	marker = "mutated"

	// Verify the deep-copied conditions in the refined ConditionsMap still have "original"
	for c := range refined.NoOpinionConditions() {
		tracker := c.(*deepCopyTracker)
		if *tracker.marker != "original" {
			t.Errorf("deep copy failed for noopinion condition: marker = %q, want %q", *tracker.marker, "original")
		}
	}
	for c := range refined.AllowConditions() {
		tracker := c.(*deepCopyTracker)
		if *tracker.marker != "original" {
			t.Errorf("deep copy failed for allow condition: marker = %q, want %q", *tracker.marker, "original")
		}
	}

	// Verify that appending to the original slices doesn't affect the refined map
	originalNopLen := len(refined.noOpinionConditions)
	originalAllowLen := len(refined.allowConditions)
	original.noOpinionConditions = append(original.noOpinionConditions, GenericCondition{ID: "extra-nop", Effect: ConditionEffectNoOpinion})
	original.allowConditions = append(original.allowConditions, GenericCondition{ID: "extra-allow", Effect: ConditionEffectAllow})
	if len(refined.noOpinionConditions) != originalNopLen {
		t.Errorf("appending to original affected refined noopinion: got %d, want %d", len(refined.noOpinionConditions), originalNopLen)
	}
	if len(refined.allowConditions) != originalAllowLen {
		t.Errorf("appending to original affected refined allow: got %d, want %d", len(refined.allowConditions), originalAllowLen)
	}
}

// deepCopyTracker is a Condition implementation with a pointer field to verify deep copy behavior.
type deepCopyTracker struct {
	id     string
	effect ConditionEffect
	marker *string
}

func (c *deepCopyTracker) GetID() string              { return c.id }
func (c *deepCopyTracker) GetEffect() ConditionEffect { return c.effect }
func (c *deepCopyTracker) GetType() string            { return "" }
func (c *deepCopyTracker) GetCondition() string       { return "" }
func (c *deepCopyTracker) GetDescription() string     { return "" }
func (c *deepCopyTracker) Evaluate(context.Context, ConditionsData) ConditionEvaluationResult {
	return ConditionsEvaluationResultUnevaluatable()
}
func (c *deepCopyTracker) DeepCopy() Condition {
	cp := *c
	if c.marker != nil {
		m := *c.marker
		cp.marker = &m
	}
	return &cp
}
