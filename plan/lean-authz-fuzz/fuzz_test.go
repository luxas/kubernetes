// Package fuzz provides differential fuzz tests comparing the production Go
// authorization code against the formally verified Lean model via C FFI.
//
// The Lean side is the oracle (proven correct by TranspiledAuthz.lean).
// The Go side uses the real production union authorizer (union.New).
//
// Run seeds:  GOWORK=off go test -v -run=FuzzDifferential -count=1 .
// Run fuzzer: GOWORK=off go test -fuzz=FuzzDifferential -fuzztime=60s .
// (CGO_CFLAGS and CGO_LDFLAGS must be set; see lean-authz-ffi/env.sh)
package fuzz

import (
	"context"
	"encoding/json"
	"testing"

	leanauthzffi "k8s.io/kubernetes/plan/lean-authz-ffi"

	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/union"
	genericfeatures "k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
)

// ---------------------------------------------------------------------------
// Production Go oracle: calls the real union authorizer
// ---------------------------------------------------------------------------

// fuzzHandler implements authorizer.Authorizer using pre-determined decisions.
// Each handler in the fuzz input becomes one of these.
type fuzzHandler struct {
	input leanauthzffi.HandlerInput
}

func parseDecision(s string) authorizer.Decision {
	switch s {
	case "Allow":
		return authorizer.DecisionAllow
	case "Deny":
		return authorizer.DecisionDeny
	default:
		return authorizer.DecisionNoOpinion
	}
}

// Authorize implements the old single-phase path.
func (h *fuzzHandler) Authorize(_ context.Context, _ authorizer.Attributes) (authorizer.Decision, string, error) {
	return parseDecision(h.input.Authorize), "", nil
}

// ConditionsAwareAuthorize implements the new two-phase path (phase 1).
func (h *fuzzHandler) ConditionsAwareAuthorize(_ context.Context, _ authorizer.Attributes) authorizer.ConditionsAwareDecision {
	switch h.input.ConditionsAwareAuthorize {
	case "Allow":
		return authorizer.ConditionsAwareDecisionAllow("", nil)
	case "Deny":
		return authorizer.ConditionsAwareDecisionDeny("", nil)
	case "NoOpinion":
		return authorizer.ConditionsAwareDecisionNoOpinion("", nil)
	case "ConditionsMap":
		// Build a ConditionsMap with a single Allow condition whose evaluation
		// returns the pre-determined result. If cmCanBecomeAllowed is false,
		// use only a NoOpinion condition (no Allow conditions → cba=false).
		evalResult := parseDecision(h.input.EvaluateConditions)
		if h.input.CmCanBecomeAllowed {
			return authorizer.ConditionsAwareDecisionConditionsMap(
				authorizer.GenericCondition{
					ID:     "fuzz-allow",
					Effect: authorizer.ConditionEffectAllow,
					EvaluateFunc: func(_ context.Context, _ authorizer.ConditionsData) authorizer.ConditionEvaluationResult {
						// The Allow condition evaluates to true only if the pre-determined result is Allow
						return authorizer.ConditionEvaluationResultBoolean(evalResult == authorizer.DecisionAllow)
					},
				},
				authorizer.GenericCondition{
					ID:     "fuzz-deny",
					Effect: authorizer.ConditionEffectDeny,
					EvaluateFunc: func(_ context.Context, _ authorizer.ConditionsData) authorizer.ConditionEvaluationResult {
						// The Deny condition evaluates to true only if the pre-determined result is Deny
						return authorizer.ConditionEvaluationResultBoolean(evalResult == authorizer.DecisionDeny)
					},
				},
			)
		}
		// cba=false: only NoOpinion/Deny conditions, no Allow conditions
		return authorizer.ConditionsAwareDecisionConditionsMap(
			authorizer.GenericCondition{
				ID:     "fuzz-deny",
				Effect: authorizer.ConditionEffectDeny,
				EvaluateFunc: func(_ context.Context, _ authorizer.ConditionsData) authorizer.ConditionEvaluationResult {
					return authorizer.ConditionEvaluationResultBoolean(evalResult == authorizer.DecisionDeny)
				},
			},
			authorizer.GenericCondition{
				ID:     "fuzz-noop",
				Effect: authorizer.ConditionEffectNoOpinion,
				EvaluateFunc: func(_ context.Context, _ authorizer.ConditionsData) authorizer.ConditionEvaluationResult {
					// If evalResult is NoOpinion, this fires; otherwise it's false
					return authorizer.ConditionEvaluationResultBoolean(evalResult == authorizer.DecisionNoOpinion)
				},
			},
		)
	default:
		return authorizer.ConditionsAwareDecisionNoOpinion("", nil)
	}
}

// EvaluateConditions implements phase 2: evaluate the ConditionsMap.
func (h *fuzzHandler) EvaluateConditions(_ context.Context, decision authorizer.ConditionsAwareDecision, data authorizer.ConditionsData) (authorizer.Decision, string, error) {
	if decision.IsUnconditional() {
		return decision.UnconditionalParts()
	}
	if decision.IsConditionsMap() {
		cm := decision.ConditionsMap()
		result := cm.Evaluate(context.Background(), data, nil)
		return result.UnconditionalParts()
	}
	return authorizer.DecisionDeny, "unexpected", nil
}

// goProductionOracle runs the production Go code and returns results
// in the same format as the Lean oracle.
func goProductionOracle(input leanauthzffi.AuthzInput) leanauthzffi.AuthzOutput {
	// Build production authorizer chain
	handlers := make([]authorizer.Authorizer, len(input.Handlers))
	for i := range input.Handlers {
		handlers[i] = &fuzzHandler{input: input.Handlers[i]}
	}
	unionAuthz := union.New(handlers...)
	ctx := context.Background()

	// Old path: Authorize
	authDecision, _, _ := unionAuthz.Authorize(ctx, nil)

	// New path: ConditionsAwareAuthorize → check CanBecomeAllowed → EvaluateConditions
	caDecision := unionAuthz.ConditionsAwareAuthorize(ctx, nil)

	var pipelineDecision authorizer.Decision
	if caDecision.IsAllowed() {
		pipelineDecision = authorizer.DecisionAllow
	} else if caDecision.CanBecomeAllowed() {
		pipelineDecision, _, _ = unionAuthz.EvaluateConditions(ctx, caDecision, authorizer.ConditionsData{})
	} else {
		pipelineDecision = authorizer.DecisionDeny
	}

	// Build the entries for EvaluateEntries comparison
	// The union's EvaluateConditions already does this internally,
	// so pipelineDecision IS the evaluateEntries result when cba=true.
	evaluateEntriesResult := pipelineDecision
	if !caDecision.IsAllowed() && !caDecision.CanBecomeAllowed() {
		// When cba=false, the pipeline returns Deny but evaluateEntries
		// would return whatever the conditions evaluate to.
		// We need to call EvaluateConditions anyway to get the raw result.
		evaluateEntriesResult, _, _ = unionAuthz.EvaluateConditions(ctx, caDecision, authorizer.ConditionsData{})
	}

	return leanauthzffi.AuthzOutput{
		UnionAuthorize:  authDecision.String(),
		Pipeline:        pipelineDecision.String(),
		EvaluateEntries: evaluateEntriesResult.String(),
		SliceCBA:        caDecision.CanBecomeAllowed(),
	}
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

func validDecision(s string) bool {
	return s == "Allow" || s == "Deny" || s == "NoOpinion"
}

func validLeafDecision(s string) bool {
	return validDecision(s) || s == "ConditionsMap"
}

// ---------------------------------------------------------------------------
// Fuzz target
// ---------------------------------------------------------------------------

// FuzzDifferential generates arbitrary authorizer chains and compares:
// - The Lean model (formally proven, called via C FFI)
// - The production Go code (union.New, Authorize, ConditionsAwareAuthorize, EvaluateConditions)
//
// Any mismatch means either the Lean model or the Go code has a bug.
// Since the Lean model is proven correct, a mismatch implies a Go bug.
func FuzzDifferential(f *testing.F) {
	featuregatetesting.SetFeatureGateDuringTest(f, utilfeature.DefaultFeatureGate, genericfeatures.ConditionalAuthorization, true)

	seeds := []leanauthzffi.AuthzInput{
		{Handlers: []leanauthzffi.HandlerInput{}},
		{Handlers: []leanauthzffi.HandlerInput{
			{Authorize: "Allow", ConditionsAwareAuthorize: "Allow",
				CmCanBecomeAllowed: false, EvaluateConditions: "Allow"},
		}},
		{Handlers: []leanauthzffi.HandlerInput{
			{Authorize: "Deny", ConditionsAwareAuthorize: "Deny",
				CmCanBecomeAllowed: false, EvaluateConditions: "Deny"},
		}},
		{Handlers: []leanauthzffi.HandlerInput{
			{Authorize: "NoOpinion", ConditionsAwareAuthorize: "NoOpinion",
				CmCanBecomeAllowed: false, EvaluateConditions: "NoOpinion"},
		}},
		{Handlers: []leanauthzffi.HandlerInput{
			{Authorize: "Allow", ConditionsAwareAuthorize: "ConditionsMap",
				CmCanBecomeAllowed: true, EvaluateConditions: "Allow"},
		}},
		{Handlers: []leanauthzffi.HandlerInput{
			{Authorize: "NoOpinion", ConditionsAwareAuthorize: "ConditionsMap",
				CmCanBecomeAllowed: false, EvaluateConditions: "NoOpinion"},
		}},
		// Chain resumption: Conditional→NoOpinion, then Allow
		{Handlers: []leanauthzffi.HandlerInput{
			{Authorize: "NoOpinion", ConditionsAwareAuthorize: "ConditionsMap",
				CmCanBecomeAllowed: true, EvaluateConditions: "NoOpinion"},
			{Authorize: "Allow", ConditionsAwareAuthorize: "Allow",
				CmCanBecomeAllowed: false, EvaluateConditions: "Allow"},
		}},
		// Three-authorizer chain with conditional deny in the middle
		{Handlers: []leanauthzffi.HandlerInput{
			{Authorize: "NoOpinion", ConditionsAwareAuthorize: "ConditionsMap",
				CmCanBecomeAllowed: true, EvaluateConditions: "Deny"},
			{Authorize: "NoOpinion", ConditionsAwareAuthorize: "NoOpinion",
				CmCanBecomeAllowed: false, EvaluateConditions: "NoOpinion"},
			{Authorize: "Allow", ConditionsAwareAuthorize: "Allow",
				CmCanBecomeAllowed: false, EvaluateConditions: "Allow"},
		}},
	}
	for _, seed := range seeds {
		b, _ := json.Marshal(seed)
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var input leanauthzffi.AuthzInput
		if err := json.Unmarshal(data, &input); err != nil {
			t.Skip()
		}
		// Reject inputs where Go's case-insensitive JSON parsing accepted
		// mangled field names that Lean's case-sensitive parser would read
		// differently. Re-marshal and compare to ensure exact field names.
		canonical, _ := json.Marshal(input)
		var roundtrip leanauthzffi.AuthzInput
		_ = json.Unmarshal(canonical, &roundtrip)
		recanonical, _ := json.Marshal(roundtrip)
		if string(canonical) != string(recanonical) {
			t.Skip()
		}
		// Also reject if the raw input doesn't match the canonical form,
		// which catches case-mangled field names.
		if string(data) != string(canonical) {
			t.Skip()
		}
		if input.Handlers == nil {
			t.Skip()
		}
		if len(input.Handlers) > 8 {
			t.Skip()
		}
		for _, h := range input.Handlers {
			if !validDecision(h.Authorize) || !validLeafDecision(h.ConditionsAwareAuthorize) ||
				!validDecision(h.EvaluateConditions) {
				t.Skip()
			}
			// Enforce the per-authorizer coherence invariant (ax_cba_sound):
			// when cmCanBecomeAllowed=false, evaluateConditions cannot be Allow,
			// because a ConditionsMap with no Allow conditions can never produce Allow.
			if h.ConditionsAwareAuthorize == "ConditionsMap" &&
				!h.CmCanBecomeAllowed && h.EvaluateConditions == "Allow" {
				t.Skip()
			}
		}

		// Lean oracle (formally proven)
		leanResult, err := leanauthzffi.CallLean(input)
		if err != nil {
			t.Fatalf("Lean FFI error: %v", err)
		}

		// Production Go code
		goResult := goProductionOracle(input)

		// Compare all outputs
		if leanResult.UnionAuthorize != goResult.UnionAuthorize {
			t.Errorf("UnionAuthorize: lean=%s go=%s input=%s",
				leanResult.UnionAuthorize, goResult.UnionAuthorize, data)
		}
		if leanResult.Pipeline != goResult.Pipeline {
			t.Errorf("Pipeline: lean=%s go=%s input=%s",
				leanResult.Pipeline, goResult.Pipeline, data)
		}
		if leanResult.EvaluateEntries != goResult.EvaluateEntries {
			t.Errorf("EvaluateEntries: lean=%s go=%s input=%s",
				leanResult.EvaluateEntries, goResult.EvaluateEntries, data)
		}
		if leanResult.SliceCBA != goResult.SliceCBA {
			t.Errorf("SliceCBA: lean=%v go=%v input=%s",
				leanResult.SliceCBA, goResult.SliceCBA, data)
		}
	})
}
