package fuzz

import (
	"encoding/json"
	"testing"

	"hegel.dev/go/hegel"

	leanauthzffi "k8s.io/kubernetes/plan/lean-authz-ffi"

	genericfeatures "k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
)

// ---------------------------------------------------------------------------
// hegel-go property test
// ---------------------------------------------------------------------------

// TestHegelDifferential uses structured generation via hegel-go to produce
// arbitrary authorizer chains and compare the Lean oracle against the
// production Go code. Unlike FuzzDifferential (which uses byte-level mutation
// on JSON), this generates valid chains directly at the type level, making it
// effective at finding bugs that require specific structural properties like
// "chain has 6+ handlers".
func TestHegelDifferential(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, genericfeatures.ConditionalAuthorization, true)

	hegel.Test(t, func(ht *hegel.T) {
		handlers := hegel.Draw(ht, genChain())
		input := leanauthzffi.AuthzInput{Handlers: handlers}

		// Lean oracle (formally proven, called via C FFI)
		leanResult, err := leanauthzffi.CallLean(input)
		if err != nil {
			ht.Fatalf("Lean FFI error: %v", err)
		}

		// Production Go code (real union authorizer)
		goResult := goProductionOracle(input)

		inputJSON, err := json.Marshal(input)
		if err != nil {
			ht.Fatal("json marshalling error", err)
		}
		compareResults(ht, inputJSON, leanResult, goResult)
	}, hegel.WithTestCases(5000)) // At some point: might want to use the test database if we find regressions
}

// ---------------------------------------------------------------------------
// Structured generators for authorization chains
// ---------------------------------------------------------------------------

func genChain() hegel.Generator[[]leanauthzffi.HandlerInput] {
	return hegel.Lists(genHandler()).MinSize(0).MaxSize(10)
}

func genHandler() hegel.Generator[leanauthzffi.HandlerInput] {
	return hegel.Composite(func(tc *hegel.TestCase) leanauthzffi.HandlerInput {
		condAware := hegel.Draw(tc, hegel.SampledFrom([]string{"Allow", "Deny", "NoOpinion", "ConditionsMap"}))
		var ideal, metadata, evalCond string
		var canBecomeAllowed bool
		switch condAware {
		case "Allow", "Deny", "NoOpinion":
			// Unconditional: ideal = metadata = the decision itself.
			// (ax_metadata_unconditional: ca ≠ ConditionsMap → metadata = ideal)
			ideal = condAware
			metadata = condAware
			evalCond = condAware
			if condAware == "Allow" {
				canBecomeAllowed = true
			}
		case "ConditionsMap":
			// Generate the condition evaluation result based on what condition effects exist.
			possibleEvalCondResults := []string{"NoOpinion"}
			hasDenyEffectCondition := hegel.Draw(tc, hegel.Booleans())
			if hasDenyEffectCondition {
				possibleEvalCondResults = append(possibleEvalCondResults, "Deny")
			}
			hasAllowEffectCondition := hegel.Draw(tc, hegel.Booleans())
			if hasAllowEffectCondition {
				possibleEvalCondResults = append(possibleEvalCondResults, "Allow")
				canBecomeAllowed = true
			}
			evalCond = hegel.Draw(tc, hegel.SampledFrom(possibleEvalCondResults))

			// ax_conditional: ideal = evaluateConditions
			ideal = evalCond

			// ax_metadata_*: metadata is at least as restrictive as ideal.
			// Allow→Allow, Deny→Deny, NoOpinion→NoOpinion or Deny (fail-closed).
			switch ideal {
			case "Allow":
				metadata = "Allow" // ax_metadata_allow
			case "Deny":
				metadata = "Deny" // ax_metadata_deny
			case "NoOpinion":
				// ax_metadata_noOpinion_fail_closed: NoOpinion or Deny
				if hegel.Draw(tc, hegel.Booleans()) {
					metadata = "Deny" // fail closed
				} else {
					metadata = "NoOpinion"
				}
			}
		default:
			tc.Errorf("unexpected condAware=%s generated", condAware)
		}

		return leanauthzffi.HandlerInput{
			AuthorizeIdeal:           ideal,
			AuthorizeMetadata:        metadata,
			ConditionsAwareAuthorize: condAware,
			CmCanBecomeAllowed:       canBecomeAllowed,
			EvaluateConditions:       evalCond,
		}
	})
}
