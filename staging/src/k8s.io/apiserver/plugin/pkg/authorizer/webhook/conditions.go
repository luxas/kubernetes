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
	"time"

	"github.com/google/cel-go/cel"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/version"
	plugincel "k8s.io/apiserver/pkg/admission/plugin/cel"
	apiservercel "k8s.io/apiserver/pkg/cel"
	"k8s.io/apiserver/pkg/cel/common"
	"k8s.io/apiserver/pkg/cel/environment"
	"k8s.io/apiserver/pkg/cel/library"
	"k8s.io/apiserver/pkg/cel/openapi"
	"k8s.io/apiserver/pkg/cel/openapi/resolver"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
)

type ConditionCompiler struct {
	SchemaResolver resolver.SchemaResolver
	RestMapper     meta.RESTMapper
}

type typeOverwrite struct {
	object *apiservercel.DeclType
}

// TypeCheckingResult holds the issues found during type checking, any returned
// error, and the gvk that the type checking is performed against.
type TypeCheckingResult struct {
	request.SubjectAccessReviewCondition

	// GVK is the associated GVK
	// GVK schema.GroupVersionKind

	// CompilationResult is the result of the compilation.
	CompilationResult plugincel.CompilationResult
}

type sarWithConditions struct {
	authorizationv1.SubjectAccessReviewSpec
	Conditions request.Conditions
}

// Check should be
func (c *ConditionCompiler) Check(sar *sarWithConditions) ([]*TypeCheckingResult, error) {
	// If there are no conditions, there is nothing to type check.
	if len(sar.Conditions) == 0 {
		return nil, nil
	}

	// If there are conditions, but the request does not support conditional authorization,
	// we should not proceed.
	if !supportsConditionalAuthorization(sar) {
		return nil, fmt.Errorf("unsupported request for conditional authorization")
	}

	gvk, err := c.typeToCheck(sar)
	if err != nil {
		return nil, err
	}

	// If gvk is nil, then the request does not support conditional authorization.
	// However, if we reached here, len(sar.Conditions) != 0, which means that the
	// webhook authorizer expects us to enforce the conditions, even though it is
	// unsupported.
	// TODO: At some point, we might consider whether we allow "untyped" conditions,
	// i.e. conditions that do not type check at this stage. For now, we proceed to
	// other authorizers in the chain, if the webhook authorizer didn't follow the rules.
	if gvk == nil {
		return nil, fmt.Errorf("no matching GVK found for group=%q, version=%q, resource=%q",
			sar.ResourceAttributes.Group,
			sar.ResourceAttributes.Version,
			sar.ResourceAttributes.Resource,
		)
	}

	s, err := c.SchemaResolver.ResolveSchema(*gvk)
	if err != nil {
		return nil, err
	}
	// TODO: Type-checking for ValidatingAdmissionPolicy is optional, even though it fails, it is evaluated.
	// Should we do the same here, or fail hard if the condition cannot be type-checked correctly?
	declType := common.SchemaDeclType(&openapi.Schema{Schema: s}, true).
		MaybeAssignTypeName(generateUniqueTypeName(gvk.Kind))

	results := make([]*TypeCheckingResult, 0, len(sar.Conditions))

	for _, cond := range sar.Conditions {
		result, err := c.CheckExpression(declType, cond)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}

	return results, nil
}

func supportsConditionalAuthorization(sar *sarWithConditions) bool {
	// In general, the GVR must be non-empty, and not a wildcard.
	// However, group="" qualifies as non-empty, as that is the core API group.
	// Also, we can infer version="" in most cases, in case a SAR requestor would
	// not set it (even though kube API server does for all "real" requests),
	// IF the GR maps to a single GVK, i.e. there is only one version for the group.
	return sar.ResourceAttributes != nil &&
		possiblyConditionalVerbs.Has(sar.ResourceAttributes.Verb) &&
		sar.ResourceAttributes.Resource != "" &&
		sar.ResourceAttributes.Group != "*" &&
		sar.ResourceAttributes.Version != "*" &&
		sar.ResourceAttributes.Resource != "*" &&
		sar.ResourceAttributes.Subresource != "*"
}

func (c *ConditionCompiler) compiler(typeOverwrite typeOverwrite) (*plugincel.CompositedCompiler, error) {
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
func (c *ConditionCompiler) CheckExpression(declType *apiservercel.DeclType, condition request.SubjectAccessReviewCondition) (*TypeCheckingResult, error) {
	compiler, err := c.compiler(typeOverwrite{
		object: declType,
	})
	if err != nil {
		return nil, err
	}
	options := plugincel.OptionalVariableDeclarations{
		HasParams:     false,
		HasAuthorizer: false, // TODO: Maybe add later?
		StrictCost:    utilfeature.DefaultFeatureGate.Enabled(features.StrictCostEnforcementForVAP),
	}
	compilationResult := compiler.CompileCELExpression(celExpression(condition.Condition), options, environment.StoredExpressions)
	return &TypeCheckingResult{
		SubjectAccessReviewCondition: condition,
		CompilationResult:            compilationResult,
	}, nil
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

var possiblyConditionalVerbs = sets.New( // TODO: Connect
	"create",
	"update",
	"patch",
	"delete",
)

// typeToCheck extracts a list of GVKs that needs type checking from the policy
// the result is sorted in the order of Group, Version, and Kind
func (c *ConditionCompiler) typeToCheck(sar *sarWithConditions) (*schema.GroupVersionKind, error) {
	gvr := schema.GroupVersionResource{
		Group:    sar.ResourceAttributes.Group,
		Version:  sar.ResourceAttributes.Version,
		Resource: sar.ResourceAttributes.Resource,
	}

	// TODO: If we restrict this to a specific (fully-qualified) GVR, we know there will be only one kind returned.
	resolved, err := c.RestMapper.KindsFor(gvr)
	if err != nil {
		// try to refresh the RESTMapper if it supports refreshing.
		if r, ok := c.RestMapper.(meta.ResettableRESTMapper); ok {
			r.Reset()
		}
		resolved, err = c.RestMapper.KindsFor(gvr)
		if err != nil {
			// TODO: Type-checking for ValidatingAdmissionPolicy is optional, even though it fails, it is evaluated.
			// Should we do the same here, or fail hard if the condition cannot be type-checked correctly?
			return nil, err
		}
	}
	if len(resolved) > 1 {
		return nil, fmt.Errorf("unexpected, multiple kinds found for a fully-qualified GVR, should be exactly one: %v", resolved)
	}
	if len(resolved) == 0 || resolved[0].Empty() {
		return nil, nil
	}
	return &resolved[0], nil
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
