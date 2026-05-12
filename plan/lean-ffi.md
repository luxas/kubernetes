# Plan: Lean C FFI → Go Differential Fuzzing Pipeline

## Context

We have a transpiled Lean 4 model (`plan/TranspiledAuthz.lean`) with proven
theorems about Kubernetes conditional authorization. We need to verify that the
production Go code matches this Lean model at runtime, for all inputs — not
just those we think of as test cases. This plan describes building a
differential fuzzing pipeline modelled after
[cedar-spec](https://github.com/cedar-policy/cedar-spec), but using Go
tooling instead of Rust.

**cedar-spec architecture** (our reference):
```
cedar-lean/         # Lean 4 formalization + @[export] FFI functions
cedar-lean-ffi/     # Rust FFI bridge (lean_sys, protobuf marshalling)
cedar-drt/          # Differential testing (cargo-fuzz targets)
```

**Our architecture**:
```
plan/lean-authz/         # Lean 4 model + @[export] FFI functions
plan/lean-authz-ffi/     # Go cgo bridge (lean runtime init, JSON marshalling)
plan/lean-authz-fuzz/    # Go fuzz tests (go test -fuzz differential targets)
```

## Design decisions

### JSON as the serialization format (not protobuf)

Cedar uses protobuf because Cedar's types are complex (policies, expressions,
entities). Our types are simple enums and flat lists, so JSON is sufficient
and avoids adding a protobuf dependency. This matches cedar-spec's simpler
FFI functions which take `ByteArray` and return `String` (JSON).

### Go's built-in fuzzing (not cargo-fuzz)

Go 1.18+ has built-in coverage-guided fuzzing via `go test -fuzz`. This is
the Go equivalent of cargo-fuzz. It supports structured inputs through seed
corpora and custom marshalling.

### Static linking of Lean libraries

Like cedar-spec, we compile Lean to static C libraries via `lake build :static`
and link them into the Go binary via cgo `#cgo LDFLAGS`.

## Component 1: Lean FFI module (`plan/lean-authz/`)

### Files

```
plan/lean-authz/
├── lakefile.lean          # Lake project config
├── lean-toolchain         # Lean version pin
├── TranspiledAuthzFFI/
│   └── Main.lean          # @[export] annotated wrappers
└── TranspiledAuthz.lean   # (symlink to ../TranspiledAuthz.lean)
```

### Lean FFI functions

Each transpiled function gets an `@[export]` wrapper that:
1. Accepts a `ByteArray` (JSON input)
2. Parses JSON to Lean types
3. Calls the transpiled function
4. Returns result as a JSON `String`

```lean
-- plan/lean-authz/TranspiledAuthzFFI/Main.lean

import Lean.Data.Json
import TranspiledAuthz

open TranspiledAuthz

-- JSON-serializable input for the authorization chain
structure AuthzInput where
  handlers : List HandlerJson  -- each handler's pre-bound decisions
  deriving Lean.FromJson, Lean.ToJson

structure HandlerJson where
  authorize              : String  -- "Allow" | "Deny" | "NoOpinion"
  conditionsAwareAuthorize : String  -- "Allow" | "Deny" | "NoOpinion" | "ConditionsMap"
  cmCanBecomeAllowed     : Bool
  evaluateConditions     : String  -- "Allow" | "Deny" | "NoOpinion"
  deriving Lean.FromJson, Lean.ToJson

structure AuthzOutput where
  authorize_result : String
  pipeline_result  : String
  evaluate_entries_result : String
  slice_cba        : Bool
  deriving Lean.FromJson, Lean.ToJson

-- Parse decision strings to Lean types
def parseDecision (s : String) : Decision :=
  match s with
  | "Allow" => .Allow
  | "Deny" => .Deny
  | _ => .NoOpinion

def parseLeafDecision (s : String) : LeafDecision :=
  match s with
  | "Allow" => .Allow
  | "Deny" => .Deny
  | "NoOpinion" => .NoOpinion
  | _ => .ConditionsMap

def decisionToString : Decision → String
  | .Allow => "Allow"
  | .Deny => "Deny"
  | .NoOpinion => "NoOpinion"

def toHandler (h : HandlerJson) : Handler :=
  { authorize := parseDecision h.authorize
    conditionsAwareAuthorize := parseLeafDecision h.conditionsAwareAuthorize
    cmCanBecomeAllowed := h.cmCanBecomeAllowed
    evaluateConditions := parseDecision h.evaluateConditions }

-- The main FFI function: given a JSON-encoded AuthzInput, compute all results
@[export leanAuthzEvaluate]
unsafe def leanAuthzEvaluate (input : ByteArray) : String :=
  let inputStr := String.fromUTF8! input
  match Lean.Json.parse inputStr >>= Lean.fromJson? (α := AuthzInput) with
  | .error e => s!"\{\"error\": \"{e}\"}"
  | .ok inp =>
    let handlers := inp.handlers.map toHandler
    let entries := BuildEntries handlers
    let result : AuthzOutput := {
      authorize_result := decisionToString (Authorize handlers)
      pipeline_result := decisionToString (Pipeline handlers)
      evaluate_entries_result := decisionToString (EvaluateEntries entries)
      slice_cba := SliceCBA entries
    }
    toString (Lean.toJson result)
```

### lakefile.lean

```lean
import Lake
open Lake DSL

package «lean-authz» where
  leanOptions := #[⟨`autoImplicit, false⟩]

@[default_target]
lean_lib TranspiledAuthz
lean_lib TranspiledAuthzFFI
```

### Build process

```bash
cd plan/lean-authz
lake update
lake build TranspiledAuthzFFI:static
# Produces: .lake/build/lib/libTranspiledAuthzFFI.a (and dependencies)
```

## Component 2: Go cgo bridge (`plan/lean-authz-ffi/`)

### Files

```
plan/lean-authz-ffi/
├── go.mod
├── lean.go        # cgo declarations, Lean runtime init, FFI call wrapper
├── lean_test.go   # Basic smoke test
└── build.sh       # Sets env vars and builds Lean libs
```

### lean.go — cgo bridge

Following cedar-spec's pattern of `lean_initialize_runtime_module_locked()` +
`initialize_<Module>()` + `lean_io_mark_end_initialization()`:

```go
package leanffi

/*
#cgo CFLAGS: -I${SRCDIR}/../lean-authz/.lake/build/include
#cgo LDFLAGS: -L${SRCDIR}/../lean-authz/.lake/build/lib
#cgo LDFLAGS: -lTranspiledAuthzFFI -lTranspiledAuthz
#cgo LDFLAGS: -L${LEAN_LIB_DIR} -lleanrt -lc -lm -lstdc++ -lgmp

#include <lean/lean.h>
#include <stdlib.h>
#include <string.h>

// Declare the Lean-exported function and initializer
extern lean_object* leanAuthzEvaluate(lean_object* input);
extern lean_object* initialize_TranspiledAuthzFFI(uint8_t builtin, lean_object* w);

// Initialize the Lean runtime (call once)
static int lean_init_done = 0;
static void lean_init() {
    if (lean_init_done) return;
    lean_initialize_runtime_module_locked();
    lean_object* res = initialize_TranspiledAuthzFFI(1, lean_io_mk_world());
    if (lean_io_result_is_ok(res)) {
        lean_dec_ref(res);
    } else {
        lean_io_result_show_error(res);
        lean_dec(res);
        // Fatal: cannot continue
        abort();
    }
    lean_io_mark_end_initialization();
    lean_set_exit_on_panic(1);
    lean_init_done = 1;
}

// Call the Lean function with a JSON byte array, return JSON string
static const char* call_lean_authz(const char* json_input, int len) {
    lean_init();
    lean_initialize_thread();

    // Create Lean ByteArray from the input
    lean_object* arr = lean_alloc_sarray(1, len, len);
    memcpy(lean_sarray_cptr(arr), json_input, len);

    // Call the Lean function
    lean_object* result = leanAuthzEvaluate(arr);

    // Extract C string from Lean String object
    const char* str = lean_string_cstr(result);

    // Copy so we can release the Lean object
    // (caller must free this)
    char* copy = strdup(str);
    lean_dec(result);

    lean_finalize_thread();
    return copy;
}
*/
import "C"

import (
    "encoding/json"
    "fmt"
    "unsafe"
)

// AuthzInput matches the Lean AuthzInput structure
type AuthzInput struct {
    Handlers []HandlerInput `json:"handlers"`
}

type HandlerInput struct {
    Authorize                string `json:"authorize"`
    ConditionsAwareAuthorize string `json:"conditionsAwareAuthorize"`
    CmCanBecomeAllowed       bool   `json:"cmCanBecomeAllowed"`
    EvaluateConditions       string `json:"evaluateConditions"`
}

// AuthzOutput matches the Lean AuthzOutput structure
type AuthzOutput struct {
    AuthorizeResult        string `json:"authorize_result"`
    PipelineResult         string `json:"pipeline_result"`
    EvaluateEntriesResult  string `json:"evaluate_entries_result"`
    SliceCBA               bool   `json:"slice_cba"`
}

// CallLean sends a JSON-encoded AuthzInput to the Lean model and returns
// the parsed AuthzOutput. This is the oracle for differential testing.
func CallLean(input AuthzInput) (AuthzOutput, error) {
    jsonBytes, err := json.Marshal(input)
    if err != nil {
        return AuthzOutput{}, fmt.Errorf("marshal input: %w", err)
    }

    cInput := C.CString(string(jsonBytes))
    defer C.free(unsafe.Pointer(cInput))

    cResult := C.call_lean_authz(cInput, C.int(len(jsonBytes)))
    defer C.free(unsafe.Pointer(cResult))

    goResult := C.GoString(cResult)

    var output AuthzOutput
    if err := json.Unmarshal([]byte(goResult), &output); err != nil {
        return AuthzOutput{}, fmt.Errorf("unmarshal lean output %q: %w", goResult, err)
    }
    return output, nil
}
```

## Component 3: Go fuzz tests (`plan/lean-authz-fuzz/`)

### Files

```
plan/lean-authz-fuzz/
├── go.mod
├── fuzz_test.go       # Fuzz targets
└── go_oracle.go       # Production Go code oracle (calls real authorizer pkg)
```

### fuzz_test.go — Differential fuzz targets

Uses Go's built-in `go test -fuzz` for coverage-guided fuzzing. The fuzz
corpus is JSON-encoded `AuthzInput` structs. The fuzzer mutates the JSON bytes,
which is effective because the JSON fields are small enums.

```go
package fuzz

import (
    "encoding/json"
    "testing"

    leanffi "plan/lean-authz-ffi"
)

func FuzzAuthorizeEquivalence(f *testing.F) {
    // Seed corpus: a few representative chains
    seeds := []leanffi.AuthzInput{
        {Handlers: nil},  // empty chain
        {Handlers: []leanffi.HandlerInput{
            {Authorize: "Allow", ConditionsAwareAuthorize: "Allow",
             CmCanBecomeAllowed: false, EvaluateConditions: "Allow"},
        }},
        {Handlers: []leanffi.HandlerInput{
            {Authorize: "NoOpinion", ConditionsAwareAuthorize: "ConditionsMap",
             CmCanBecomeAllowed: true, EvaluateConditions: "Allow"},
            {Authorize: "Deny", ConditionsAwareAuthorize: "Deny",
             CmCanBecomeAllowed: false, EvaluateConditions: "Deny"},
        }},
    }
    for _, seed := range seeds {
        b, _ := json.Marshal(seed)
        f.Add(b)
    }

    f.Fuzz(func(t *testing.T, data []byte) {
        var input leanffi.AuthzInput
        if err := json.Unmarshal(data, &input); err != nil {
            t.Skip("invalid JSON")
        }
        // Validate enum values
        for _, h := range input.Handlers {
            if !validDecision(h.Authorize) || !validLeafDecision(h.ConditionsAwareAuthorize) ||
               !validDecision(h.EvaluateConditions) {
                t.Skip("invalid enum value")
            }
        }
        if len(input.Handlers) > 10 {
            t.Skip("chain too long")
        }

        // Call Lean oracle
        leanResult, err := leanffi.CallLean(input)
        if err != nil {
            t.Fatalf("Lean FFI error: %v", err)
        }

        // Call Go production code
        goResult := goOracle(input)

        // Differential comparison: all four outputs must match
        if leanResult.AuthorizeResult != goResult.AuthorizeResult {
            t.Errorf("Authorize mismatch: lean=%s go=%s input=%s",
                leanResult.AuthorizeResult, goResult.AuthorizeResult, string(data))
        }
        if leanResult.PipelineResult != goResult.PipelineResult {
            t.Errorf("Pipeline mismatch: lean=%s go=%s input=%s",
                leanResult.PipelineResult, goResult.PipelineResult, string(data))
        }
        if leanResult.EvaluateEntriesResult != goResult.EvaluateEntriesResult {
            t.Errorf("EvaluateEntries mismatch: lean=%s go=%s input=%s",
                leanResult.EvaluateEntriesResult, goResult.EvaluateEntriesResult, string(data))
        }
        if leanResult.SliceCBA != goResult.SliceCBA {
            t.Errorf("SliceCBA mismatch: lean=%v go=%v input=%s",
                leanResult.SliceCBA, goResult.SliceCBA, string(data))
        }
    })
}

func validDecision(s string) bool {
    return s == "Allow" || s == "Deny" || s == "NoOpinion"
}

func validLeafDecision(s string) bool {
    return validDecision(s) || s == "ConditionsMap"
}
```

### go_oracle.go — Production Go code oracle

This file calls the actual production authorizer code (union.New, etc.)
with test authorizer implementations that return the pre-determined decisions
from the fuzz input. This is the "production side" of the differential test.

```go
package fuzz

import (
    "context"

    leanffi "plan/lean-authz-ffi"
    "k8s.io/apiserver/pkg/authorization/authorizer"
    "k8s.io/apiserver/pkg/authorization/union"
)

func goOracle(input leanffi.AuthzInput) leanffi.AuthzOutput {
    handlers := make([]authorizer.Authorizer, len(input.Handlers))
    for i, h := range input.Handlers {
        handlers[i] = &fuzzHandler{h: h}
    }
    unionAuthz := union.New(handlers...)

    // Authorize (old path)
    authDecision, _, _ := unionAuthz.Authorize(context.Background(), nil)

    // ConditionsAwareAuthorize + EvaluateConditions (new path)
    caDecision := unionAuthz.ConditionsAwareAuthorize(context.Background(), nil)
    var pipelineDecision authorizer.Decision
    if caDecision.IsAllowed() {
        pipelineDecision = authorizer.DecisionAllow
    } else if caDecision.CanBecomeAllowed() {
        pipelineDecision, _, _ = unionAuthz.EvaluateConditions(
            context.Background(), caDecision, authorizer.ConditionsData{})
    } else {
        pipelineDecision = authorizer.DecisionDeny
    }

    return leanffi.AuthzOutput{
        AuthorizeResult:       decisionString(authDecision),
        PipelineResult:        decisionString(pipelineDecision),
        EvaluateEntriesResult: decisionString(pipelineDecision), // same
        SliceCBA:              caDecision.CanBecomeAllowed(),
    }
}
```

## Build & Run

### One-time setup

```bash
# 1. Build Lean static libraries
cd plan/lean-authz
lake update && lake build TranspiledAuthzFFI:static

# 2. Set LEAN_LIB_DIR to point to Lean's runtime library
export LEAN_LIB_DIR=$(lean --print-libdir)

# 3. Build and test the Go FFI bridge
cd ../lean-authz-ffi
go test -v

# 4. Run the differential fuzzer
cd ../lean-authz-fuzz
go test -fuzz=FuzzAuthorizeEquivalence -fuzztime=5m
```

### CI integration

```yaml
# .github/workflows/lean-ffi-fuzz.yaml
jobs:
  lean-ffi-fuzz:
    steps:
      - uses: leanprover/lean4-action@v1
      - run: cd plan/lean-authz && lake build TranspiledAuthzFFI:static
      - run: export LEAN_LIB_DIR=$(lean --print-libdir)
      - run: cd plan/lean-authz-fuzz && go test -fuzz=FuzzAuthorizeEquivalence -fuzztime=2m
```

## What each component verifies

| Component | What it checks |
|---|---|
| `TranspiledAuthz.lean` (existing) | Proven: `Authorize = Pipeline` for coherent handlers |
| `TranspiledAuthzFFI` | JSON FFI bridge from Go to Lean model |
| `FuzzAuthorizeEquivalence` | Production Go code == Lean model for all fuzzed inputs |

The chain of trust:
1. **Lean proof**: the transpiled code is correct (proven theorem)
2. **FFI bridge**: the Lean model is callable from Go (tested by smoke tests)
3. **Differential fuzzer**: the Go production code matches the Lean model (fuzzed)

Together: `production Go code == Lean model == proven correct`

## Critical files to modify/create

| File | Action |
|---|---|
| `plan/lean-authz/lakefile.lean` | Create: Lake project |
| `plan/lean-authz/TranspiledAuthzFFI/Main.lean` | Create: @[export] wrappers |
| `plan/lean-authz-ffi/lean.go` | Create: cgo bridge |
| `plan/lean-authz-ffi/lean_test.go` | Create: smoke test |
| `plan/lean-authz-fuzz/fuzz_test.go` | Create: fuzz targets |
| `plan/lean-authz-fuzz/go_oracle.go` | Create: production Go oracle |
| `plan/TranspiledAuthz.lean` | No changes needed |

## Verification

1. `lean plan/TranspiledAuthz.lean` — proofs still check (no sorry in core theorems)
2. `cd plan/lean-authz && lake build TranspiledAuthzFFI:static` — Lean compiles to C
3. `cd plan/lean-authz-ffi && go test -v` — FFI bridge works
4. `cd plan/lean-authz-fuzz && go test -fuzz=FuzzAuthorizeEquivalence -fuzztime=30s` — no mismatches found
