/*
Copyright 2025 The Kubernetes Authors.

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

package webhook

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/cel-go/cel"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apimachinery/pkg/util/version"
	plugincel "k8s.io/apiserver/pkg/admission/plugin/cel"
	apiservercel "k8s.io/apiserver/pkg/cel"
	"k8s.io/apiserver/pkg/cel/common"
	"k8s.io/apiserver/pkg/cel/environment"
	"k8s.io/apiserver/pkg/cel/library"
	"k8s.io/apiserver/pkg/cel/openapi"
	"k8s.io/apiserver/pkg/cel/openapi/resolver"
	"k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
)

type TypeChecker struct {
	SchemaResolver resolver.SchemaResolver
	RestMapper     meta.RESTMapper
}

// TypeCheckingContext holds information about the policy being type-checked.
// The struct is opaque to the caller.
type TypeCheckingContext struct {
	gvks      []schema.GroupVersionKind
	declTypes []*apiservercel.DeclType
}

type typeOverwrite struct {
	object *apiservercel.DeclType
}

// TypeCheckingResult holds the issues found during type checking, any returned
// error, and the gvk that the type checking is performed against.
type TypeCheckingResult struct {
	// GVK is the associated GVK
	GVK schema.GroupVersionKind
	// Issues contain machine-readable information about the typechecking result.
	//Issues error

	// CompilationResult is the result of the compilation.
	CompilationResult plugincel.CompilationResult
}

// TypeCheckingResults is a collection of TypeCheckingResult
/*type TypeCheckingResults []*TypeCheckingResult

func (rs TypeCheckingResults) String() string {
	var messages []string
	for _, r := range rs {
		message := r.String()
		if message != "" {
			messages = append(messages, message)
		}
	}
	return strings.Join(messages, "\n")
}

// String converts the result to human-readable form as a string.
func (r *TypeCheckingResult) String() string {
	if r.Issues == nil {
		return ""
	}
	return fmt.Sprintf("%v: %s\n", r.GVK, r.Issues)
}*/

// Check preforms the type check against the given policy, and format the result
// as []ExpressionWarning that is ready to be set in policy.Status
// The result is nil if type checking returns no warning.
// The policy object is NOT mutated. The caller should update Status accordingly
func (c *TypeChecker) Check(sar *authorizationv1.SubjectAccessReview) (map[field.Path][]TypeCheckingResult, error) {
	ctx, err := c.CreateContext(sar)
	if err != nil {
		return nil, err
	}

	// warnings to return, note that the capacity is optimistically set to zero
	results := make(map[field.Path][]TypeCheckingResult, len(sar.Status.Conditions))

	// check main validation expressions and their message expressions, located in spec.validations[*]
	fieldRef := field.NewPath("status", "conditions")
	for i, v := range sar.Status.Conditions {
		result := c.CheckExpression(ctx, v.Condition)
		results[*fieldRef.Index(i).Child("condition")] = result
	}

	return results, nil
}

// CreateContext resolves all types and their schemas from a policy definition and creates the context.
func (c *TypeChecker) CreateContext(sar *authorizationv1.SubjectAccessReview) (*TypeCheckingContext, error) {
	ctx := new(TypeCheckingContext)
	allGvks, err := c.typesToCheck(sar)
	if err != nil {
		return nil, err
	}
	gvks := make([]schema.GroupVersionKind, 0, len(allGvks))
	declTypes := make([]*apiservercel.DeclType, 0, len(allGvks))
	for _, gvk := range allGvks {
		declType, err := c.declType(gvk)
		if err != nil {
			// TODO: Type-checking for ValidatingAdmissionPolicy is optional, even though it fails, it is evaluated.
			// Should we do the same here, or fail hard if the condition cannot be type-checked correctly?
			return nil, err
		}
		gvks = append(gvks, gvk)
		declTypes = append(declTypes, declType)
	}
	ctx.gvks = gvks
	ctx.declTypes = declTypes
	return ctx, nil
}

func (c *TypeChecker) compiler(typeOverwrite typeOverwrite) (*plugincel.CompositedCompiler, error) {
	envSet, err := buildEnvSet(
		/* hasAuthorizer */ false, // TODO: Maybe add later?
		typeOverwrite)
	if err != nil {
		return nil, err
	}
	env, err := plugincel.NewCompositionEnv(plugincel.VariablesTypeName, envSet)
	if err != nil {
		return nil, err
	}
	compiler := &plugincel.CompositedCompiler{
		Compiler:       &typeCheckingCompiler{typeOverwrite: typeOverwrite, compositionEnv: env},
		CompositionEnv: env,
	}
	return compiler, nil
}

// CheckExpression type checks a single expression, given the context
func (c *TypeChecker) CheckExpression(ctx *TypeCheckingContext, expression string) []TypeCheckingResult {
	var results []TypeCheckingResult
	for i, gvk := range ctx.gvks {
		declType := ctx.declTypes[i]
		compiler, err := c.compiler(typeOverwrite{
			object: declType,
		})
		if err != nil {
			utilruntime.HandleError(err)
			continue
		}
		options := plugincel.OptionalVariableDeclarations{
			HasParams:     false,
			HasAuthorizer: false, // TODO: Maybe add later?
			StrictCost:    utilfeature.DefaultFeatureGate.Enabled(features.StrictCostEnforcementForVAP),
		}
		compilationResult := compiler.CompileCELExpression(celExpression(expression), options, environment.StoredExpressions)
		results = append(results, TypeCheckingResult{
			GVK:               gvk,
			CompilationResult: compilationResult,
		})
	}
	return results
}

type celExpression string

func (c celExpression) GetExpression() string {
	return string(c)
}

func (c celExpression) ReturnTypes() []*cel.Type {
	return []*cel.Type{cel.BoolType}
}
func generateUniqueTypeName(kind string) string {
	return fmt.Sprintf("%s%d", kind, time.Now().Nanosecond())
}

func (c *TypeChecker) declType(gvk schema.GroupVersionKind) (*apiservercel.DeclType, error) {
	if gvk.Empty() {
		return nil, nil
	}
	s, err := c.SchemaResolver.ResolveSchema(gvk)
	if err != nil {
		return nil, err
	}
	return common.SchemaDeclType(&openapi.Schema{Schema: s}, true).MaybeAssignTypeName(generateUniqueTypeName(gvk.Kind)), nil
}

var possiblyConditionalVerbs = sets.New( // TODO: Connect
	"create",
	"update",
	"patch",
	"delete",
)

// typesToCheck extracts a list of GVKs that needs type checking from the policy
// the result is sorted in the order of Group, Version, and Kind
func (c *TypeChecker) typesToCheck(sar *authorizationv1.SubjectAccessReview) ([]schema.GroupVersionKind, error) {
	gvks := sets.New[schema.GroupVersionKind]()

	if sar.Spec.ResourceAttributes == nil {
		return nil, nil
	}
	if !possiblyConditionalVerbs.Has(sar.Spec.ResourceAttributes.Verb) {
		return nil, nil
	}
	if sar.Spec.ResourceAttributes.Group == "*" || sar.Spec.ResourceAttributes.Version == "*" || sar.Spec.ResourceAttributes.Resource == "*" || sar.Spec.ResourceAttributes.Subresource == "*" {
		return nil, nil
	}
	if sar.Status.Conditions == nil {
		return nil, nil
	}

	// TODO: Should we type-check against all versions? That's how it's done in ValidatingAdmissionPolicy, but as
	// Cedar has a schema, it'd mean that we could just take the least common denominator of the APIs, which might be a good idea,
	// but schema changes makes things hard, especially as the lcd shrinks then over time and makes existing policies break.
	gvr := schema.GroupVersionResource{
		Group:    sar.Spec.ResourceAttributes.Group,
		Version:  sar.Spec.ResourceAttributes.Version,
		Resource: sar.Spec.ResourceAttributes.Resource,
	}
	// TODO: With the above conditions, can this ever result in multiple kinds?
	resolved, err := c.RestMapper.KindsFor(gvr)
	if err != nil {
		c.tryRefreshRESTMapper()
		resolved, err = c.RestMapper.KindsFor(gvr)
		if err != nil {
			// TODO: Type-checking for ValidatingAdmissionPolicy is optional, even though it fails, it is evaluated.
			// Should we do the same here, or fail hard if the condition cannot be type-checked correctly?
			return nil, err
		}
	}
	for _, r := range resolved {
		if !r.Empty() {
			gvks.Insert(r)
		}
	}
	if gvks.Len() == 0 {
		return nil, nil
	}
	return sortGVKList(gvks.UnsortedList()), nil
}

// sortGVKList sorts the list by Group, Version, and Kind
// returns the list itself.
func sortGVKList(list []schema.GroupVersionKind) []schema.GroupVersionKind {
	sort.Slice(list, func(i, j int) bool {
		if g := strings.Compare(list[i].Group, list[j].Group); g != 0 {
			return g < 0
		}
		if v := strings.Compare(list[i].Version, list[j].Version); v != 0 {
			return v < 0
		}
		return strings.Compare(list[i].Kind, list[j].Kind) < 0
	})
	return list
}

// tryRefreshRESTMapper refreshes the RESTMapper if it supports refreshing.
func (c *TypeChecker) tryRefreshRESTMapper() {
	if r, ok := c.RestMapper.(meta.ResettableRESTMapper); ok {
		r.Reset()
	}
}

func buildEnvSet(hasAuthorizer bool, types typeOverwrite) (*environment.EnvSet, error) {
	baseEnv := environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion(), utilfeature.DefaultFeatureGate.Enabled(features.StrictCostEnforcementForVAP))
	requestType := plugincel.BuildRequestType()
	namespaceType := plugincel.BuildNamespaceType()

	var varOpts []cel.EnvOption
	var declTypes []*apiservercel.DeclType

	// namespace, hand-crafted type
	declTypes = append(declTypes, namespaceType)
	varOpts = append(varOpts, createVariableOpts(namespaceType, plugincel.NamespaceVarName)...)

	// request, hand-crafted type
	declTypes = append(declTypes, requestType)
	varOpts = append(varOpts, createVariableOpts(requestType, plugincel.RequestVarName)...)

	// object and oldObject, same type, type(s) resolved from constraints
	declTypes = append(declTypes, types.object)
	varOpts = append(varOpts, createVariableOpts(types.object, plugincel.ObjectVarName, plugincel.OldObjectVarName)...)

	// authorizer, implicitly available to all expressions of a policy
	if hasAuthorizer {
		// we only need its structure but not the variable itself
		varOpts = append(varOpts, cel.Variable("authorizer", library.AuthorizerType))
	}

	return baseEnv.Extend(
		environment.VersionedOptions{
			// Feature epoch was actually 1.26, but we artificially set it to 1.0 because these
			// options should always be present.
			IntroducedVersion: version.MajorMinor(1, 0),
			EnvOptions:        varOpts,
			DeclTypes:         declTypes,
		},
	)
}

// createVariableOpts creates a slice of EnvOption
// that can be used for creating a CEL env containing variables of declType.
// declType can be nil, in which case the variables will be of DynType.
func createVariableOpts(declType *apiservercel.DeclType, variables ...string) []cel.EnvOption {
	opts := make([]cel.EnvOption, 0, len(variables))
	t := cel.DynType
	if declType != nil {
		t = declType.CelType()
	}
	for _, v := range variables {
		opts = append(opts, cel.Variable(v, t))
	}
	return opts
}

type typeCheckingCompiler struct {
	compositionEnv *plugincel.CompositionEnv
	typeOverwrite  typeOverwrite
}

// CompileCELExpression compiles the given expression.
// The implementation is the same as that of staging/src/k8s.io/apiserver/pkg/admission/plugin/cel/compile.go
// except that:
// - object, oldObject, and params are typed instead of Dyn
// - compiler does not enforce the output type
// - the compiler does not initialize the program
func (c *typeCheckingCompiler) CompileCELExpression(expressionAccessor plugincel.ExpressionAccessor, options plugincel.OptionalVariableDeclarations, mode environment.Type) plugincel.CompilationResult {
	resultError := func(errorString string, errType apiservercel.ErrorType) plugincel.CompilationResult {
		return plugincel.CompilationResult{
			Error: &apiservercel.Error{
				Type:   errType,
				Detail: errorString,
			},
			ExpressionAccessor: expressionAccessor,
		}
	}
	env, err := c.compositionEnv.Env(mode)
	if err != nil {
		return resultError(fmt.Sprintf("fail to build env: %v", err), apiservercel.ErrorTypeInternal)
	}
	ast, issues := env.Compile(expressionAccessor.GetExpression())
	if issues != nil {
		return resultError(issues.String(), apiservercel.ErrorTypeInvalid)
	}
	if ast.OutputType() != cel.BoolType {
		return resultError(fmt.Sprintf("expression %q must return a boolean value", expressionAccessor.GetExpression()), apiservercel.ErrorTypeInvalid)
	}

	prg, err := env.Program(ast)
	if err != nil {
		return resultError(fmt.Sprintf("program construction error: %s", err), apiservercel.ErrorTypeInvalid)
	}
	return plugincel.CompilationResult{
		OutputType:         ast.OutputType(),
		Program:            prg,
		ExpressionAccessor: expressionAccessor,
	}
}

var _ plugincel.Compiler = (*typeCheckingCompiler)(nil)
