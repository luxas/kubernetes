// Package leanffi provides a Go bridge to the Lean 4 transpiled authorization model
// via cgo. It calls the Lean functions compiled to C static libraries, using JSON
// as the serialization format.
//
// Build prerequisites:
//  1. cd plan/lean-authz && lake build TranspiledAuthzFFI:static TranspiledAuthz:static
//  2. Ensure gmp and libuv are installed (brew install gmp libuv)
package leanauthzffi

/*
// Paths are set via CGO_CFLAGS and CGO_LDFLAGS environment variables.
// Run: source plan/lean-authz-ffi/env.sh before building.
//
// CGO_CFLAGS must include:  -I<lean-toolchain>/include
// CGO_LDFLAGS must include: -L<lean-authz>/.lake/build/lib
//                           -llean_x2dauthz_TranspiledAuthzFFI -llean_x2dauthz_TranspiledAuthz
//                           -L<lean-toolchain>/lib/lean -lLean -lStd -lInit -lleanrt
//                           -L/opt/homebrew/lib -lgmp -luv
//                           -lc -lm -lstdc++ -framework CoreFoundation

#include <lean/lean.h>
#include <stdlib.h>
#include <string.h>

// These Lean runtime functions are not in the public lean.h header but are
// exported from libleanrt.a. Cedar-spec declares them via lean_sys; we
// declare them as extern "C" here.
extern void lean_initialize_runtime_module(void);
extern void lean_initialize_thread(void);
extern void lean_finalize_thread(void);

// Declare the Lean-exported FFI function and module initializer.
// These symbols come from the static libraries linked above.
extern lean_object* lean_authz_evaluate(lean_object* input);
extern lean_object* initialize_lean_x2dauthz_TranspiledAuthzFFI(uint8_t builtin, lean_object* w);

// lean_init initializes the Lean runtime. Must be called once before any FFI call.
// Follows the same pattern as cedar-spec (cedar-lean-ffi/src/lean_ffi.rs:574-596).
static int _lean_init_done = 0;
static void lean_init() {
    if (_lean_init_done) return;

    lean_initialize_runtime_module();

    // Initialize our module (which transitively initializes Init, Lean.Data.Json, etc.)
    lean_object* res = initialize_lean_x2dauthz_TranspiledAuthzFFI(1, lean_io_mk_world());
    if (lean_io_result_is_ok(res)) {
        lean_dec_ref(res);
    } else {
        lean_io_result_show_error(res);
        lean_dec(res);
        // Cannot continue without Lean runtime
        abort();
    }

    lean_io_mark_end_initialization();
    lean_set_exit_on_panic(1);
    _lean_init_done = 1;
}

// call_lean_authz calls the Lean FFI function with a JSON byte array.
// Returns a malloc'd C string (caller must free).
static const char* call_lean_authz(const char* json_input, int len) {
    lean_init();
    lean_initialize_thread();

    // Create a Lean ByteArray from the input bytes
    lean_object* arr = lean_alloc_sarray(1, (size_t)len, (size_t)len);
    memcpy(lean_sarray_cptr(arr), json_input, (size_t)len);

    // Call the Lean @[export lean_authz_evaluate] function
    lean_object* result = lean_authz_evaluate(arr);
    // arr is consumed by the Lean function (moved)

    // Extract the C string from the Lean String object
    const char* str = lean_string_cstr(result);
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

// AuthzInput is the JSON input sent to the Lean model.
// Each handler describes a pre-bound authorizer's decisions for a specific request.
type AuthzInput struct {
	Handlers []HandlerInput `json:"handlers"`
}

// HandlerInput describes one authorizer's pre-bound behavior for a specific request.
type HandlerInput struct {
	// AuthorizeIdeal is the abstract ideal result given complete information
	// (attrs + data). Equal to EvaluateConditions when ConditionsAwareAuthorize
	// is "ConditionsMap", and equal to the unconditional decision otherwise.
	AuthorizeIdeal string `json:"authorizeIdeal"`

	// AuthorizeMetadata is the production Authorize(ctx, attrs) result with only
	// metadata. May be more conservative than AuthorizeIdeal (e.g. Deny when ideal
	// is NoOpinion due to fail-closed behavior).
	AuthorizeMetadata string `json:"authorizeMetadata"`

	// ConditionsAwareAuthorize is the result of the new two-phase ConditionsAwareAuthorize().
	// Valid values: "Allow", "Deny", "NoOpinion", "ConditionsMap"
	ConditionsAwareAuthorize string `json:"conditionsAwareAuthorize"`

	// CmCanBecomeAllowed is ConditionsMap.CanBecomeAllowed() — only meaningful when
	// ConditionsAwareAuthorize == "ConditionsMap".
	CmCanBecomeAllowed bool `json:"cmCanBecomeAllowed"`

	// EvaluateConditions is the result of EvaluateConditions() — only meaningful when
	// ConditionsAwareAuthorize == "ConditionsMap".
	// Valid values: "Allow", "Deny", "NoOpinion"
	EvaluateConditions string `json:"evaluateConditions"`
}

// AuthzOutput contains all results computed by the Lean model.
type AuthzOutput struct {
	UnionAuthorize          string `json:"unionAuthorize"`
	UnionAuthorizeMetadata  string `json:"unionAuthorizeMetadata"`
	Pipeline                string `json:"pipeline"`
	UnionEvaluateConditions string `json:"evaluateEntries"`
	SliceCBA                bool   `json:"sliceCBA"`
}

// CallLean sends an AuthzInput to the Lean model via the C FFI bridge
// and returns the parsed AuthzOutput.
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

	// Check for Lean-side parse errors
	var errObj struct {
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(goResult), &errObj) == nil && errObj.Error != "" {
		return AuthzOutput{}, fmt.Errorf("lean error: %s", errObj.Error)
	}

	var output AuthzOutput
	if err := json.Unmarshal([]byte(goResult), &output); err != nil {
		return AuthzOutput{}, fmt.Errorf("unmarshal lean output %q: %w", goResult, err)
	}
	return output, nil
}
