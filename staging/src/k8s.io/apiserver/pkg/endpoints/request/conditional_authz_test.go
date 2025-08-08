package request

import (
	"errors"
	"fmt"
	"log"
	"reflect"
	"testing"

	"github.com/google/cel-go/cel"
)

func TestCarryContextUpwards(t *testing.T) {

	env, err := cel.NewEnv()
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	ast, issues := env.Compile(`1 + 1 == 2`)
	if issues != nil && issues.Err() != nil {
		t.Fatalf("failed to compile program: %v", issues.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		log.Fatalf("program construction error: %s", err)
	}

	errCtx := &ConditionalAuthorizationContext{
		Conditions: []CompilationResult{
			{
				Program: prg,
			},
		},
	}

	returnErr := fmt.Errorf("foo: %w", errCtx)

	if !errors.Is(returnErr, errCtx) {
		t.Fatalf("expected error to be %v, got %v", errCtx, returnErr)
	}

	errCtx2 := &ConditionalAuthorizationContext{}
	if !errors.As(returnErr, &errCtx2) {
		t.Fatalf("expected error to be %v, got %v", errCtx, returnErr)
	}

	if !reflect.DeepEqual(*errCtx, *errCtx2) {
		t.Fatalf("expected error to be %v, got %v", errCtx, errCtx2)
	}

	evalResult, _, err := errCtx2.Conditions[0].Program.Eval(map[string]any{})
	if err != nil {
		t.Fatalf("failed to evaluate program: %v", err)
	}

	if evalResult.Value() != true {
		t.Fatalf("expected error to be %v, got %v", errCtx, returnErr)
	}
}
