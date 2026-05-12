package leanffi

import (
	"encoding/json"
	"testing"
)

// goAuthorize is a Go reimplementation of TranspiledAuthz.UnionAuthorize,
// mirroring the production union.Authorize() code. This is the "production side"
// of the differential test.
func goAuthorize(handlers []HandlerInput) string {
	for _, h := range handlers {
		switch h.Authorize {
		case "Allow":
			return "Allow"
		case "Deny":
			return "Deny"
		case "NoOpinion":
			continue
		}
	}
	return "NoOpinion"
}

// goEntry pairs a handler with its phase-1 decision (like union.go index correlation).
type goEntry struct {
	handler  HandlerInput
	decision string
}

// goBuildEntries mirrors TranspiledAuthz.UnionConditionsAwareAuthorize (union.go:73-96).
func goBuildEntries(handlers []HandlerInput) []goEntry {
	var entries []goEntry
	for _, h := range handlers {
		d := h.ConditionsAwareAuthorize
		entries = append(entries, goEntry{handler: h, decision: d})
		// ContainsAllowOrDeny for a leaf: true for Allow/Deny
		if d == "Allow" || d == "Deny" {
			break
		}
	}
	return entries
}

// goEvaluateEntries mirrors TranspiledAuthz.UnionEvaluateConditions (union.go:117-149).
func goEvaluateEntries(entries []goEntry) string {
	for _, e := range entries {
		switch e.decision {
		case "Allow":
			return "Allow"
		case "Deny":
			return "Deny"
		case "NoOpinion":
			continue
		case "ConditionsMap":
			switch e.handler.EvaluateConditions {
			case "Allow":
				return "Allow"
			case "Deny":
				return "Deny"
			case "NoOpinion":
				continue
			}
		}
	}
	return "NoOpinion"
}

// goSliceCBA mirrors TranspiledAuthz.UnionSliceCanBecomeAllowed (conditions.go:910-926).
func goSliceCBA(entries []goEntry) bool {
	for _, e := range entries {
		switch e.decision {
		case "Deny":
			return false
		case "Allow":
			return true
		case "NoOpinion":
			continue
		case "ConditionsMap":
			if e.handler.CmCanBecomeAllowed {
				return true
			}
			continue
		}
	}
	return false
}

// goPipeline mirrors TranspiledAuthz.Pipeline.
func goPipeline(handlers []HandlerInput) string {
	entries := goBuildEntries(handlers)
	if goSliceCBA(entries) {
		return goEvaluateEntries(entries)
	}
	return "Deny"
}

func goOracle(handlers []HandlerInput) AuthzOutput {
	entries := goBuildEntries(handlers)
	return AuthzOutput{
		UnionAuthorize:  goAuthorize(handlers),
		Pipeline:        goPipeline(handlers),
		EvaluateEntries: goEvaluateEntries(entries),
		SliceCBA:        goSliceCBA(entries),
	}
}

// validDecision checks that a string is a valid Decision value.
func validDecision(s string) bool {
	return s == "Allow" || s == "Deny" || s == "NoOpinion"
}

// validLeafDecision checks that a string is a valid LeafDecision value.
func validLeafDecision(s string) bool {
	return validDecision(s) || s == "ConditionsMap"
}

// FuzzDifferential is a coverage-guided fuzz test that generates arbitrary
// authorizer chains (as JSON) and verifies that:
// 1. The Lean model (called via C FFI) matches the Go reimplementation
// 2. All four outputs (UnionAuthorize, Pipeline, EvaluateEntries, SliceCBA) agree
//
// Run: go test -fuzz=FuzzDifferential -fuzztime=60s
func FuzzDifferential(f *testing.F) {
	// Seed corpus: representative scenarios
	seeds := []AuthzInput{
		{Handlers: []HandlerInput{}},
		{Handlers: []HandlerInput{
			{Authorize: "Allow", ConditionsAwareAuthorize: "Allow",
				CmCanBecomeAllowed: false, EvaluateConditions: "Allow"},
		}},
		{Handlers: []HandlerInput{
			{Authorize: "Deny", ConditionsAwareAuthorize: "Deny",
				CmCanBecomeAllowed: false, EvaluateConditions: "Deny"},
		}},
		{Handlers: []HandlerInput{
			{Authorize: "NoOpinion", ConditionsAwareAuthorize: "NoOpinion",
				CmCanBecomeAllowed: false, EvaluateConditions: "NoOpinion"},
		}},
		{Handlers: []HandlerInput{
			{Authorize: "Allow", ConditionsAwareAuthorize: "ConditionsMap",
				CmCanBecomeAllowed: true, EvaluateConditions: "Allow"},
		}},
		{Handlers: []HandlerInput{
			{Authorize: "NoOpinion", ConditionsAwareAuthorize: "ConditionsMap",
				CmCanBecomeAllowed: false, EvaluateConditions: "NoOpinion"},
		}},
		{Handlers: []HandlerInput{
			{Authorize: "NoOpinion", ConditionsAwareAuthorize: "ConditionsMap",
				CmCanBecomeAllowed: true, EvaluateConditions: "NoOpinion"},
			{Authorize: "Allow", ConditionsAwareAuthorize: "Allow",
				CmCanBecomeAllowed: false, EvaluateConditions: "Allow"},
		}},
		{Handlers: []HandlerInput{
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
		var input AuthzInput
		if err := json.Unmarshal(data, &input); err != nil {
			t.Skip()
		}
		if input.Handlers == nil {
			t.Skip()
		}
		// Validate and cap chain length
		if len(input.Handlers) > 8 {
			t.Skip()
		}
		for _, h := range input.Handlers {
			if !validDecision(h.Authorize) || !validLeafDecision(h.ConditionsAwareAuthorize) ||
				!validDecision(h.EvaluateConditions) {
				t.Skip()
			}
		}

		// Call Lean oracle via C FFI
		leanResult, err := CallLean(input)
		if err != nil {
			t.Fatalf("Lean FFI error: %v", err)
		}

		// Call Go oracle (mirrors production code)
		goResult := goOracle(input.Handlers)

		// Differential comparison: all four outputs must match
		if leanResult.UnionAuthorize != goResult.UnionAuthorize {
			t.Errorf("UnionAuthorize mismatch: lean=%s go=%s input=%s",
				leanResult.UnionAuthorize, goResult.UnionAuthorize, string(data))
		}
		if leanResult.Pipeline != goResult.Pipeline {
			t.Errorf("Pipeline mismatch: lean=%s go=%s input=%s",
				leanResult.Pipeline, goResult.Pipeline, string(data))
		}
		if leanResult.EvaluateEntries != goResult.EvaluateEntries {
			t.Errorf("EvaluateEntries mismatch: lean=%s go=%s input=%s",
				leanResult.EvaluateEntries, goResult.EvaluateEntries, string(data))
		}
		if leanResult.SliceCBA != goResult.SliceCBA {
			t.Errorf("SliceCBA mismatch: lean=%v go=%v input=%s",
				leanResult.SliceCBA, goResult.SliceCBA, string(data))
		}
	})
}
