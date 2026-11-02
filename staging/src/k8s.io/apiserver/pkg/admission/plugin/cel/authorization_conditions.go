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

package cel

import (
	"context"
	"fmt"

	celgo "cel.dev/cel-go/cel"
	celtypes "cel.dev/cel-go/common/types"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/admission"
	namespacematcher "k8s.io/apiserver/pkg/admission/plugin/webhook/predicates/namespace"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/cel/environment"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
)

// NewAuthorizationConditionsEvaluatorBuilder creates a new authorizer.BuiltinConditionsEvaluatorBuilder that can evaluate
// authorizer.ConditionTypeAuthorizationCEL-typed conditions.
// runtimeCELCostBudget was added for testing purpose only. Callers should always use const RuntimeCELCostBudget from k8s.io/apiserver/pkg/apis/cel/config.go as input.
// TODO(luxas): Right now the budget is per-condition, not per-evaluator. Should we have two knobs or just that one?
func NewAuthorizationConditionsEvaluatorBuilder(informerFactory informers.SharedInformerFactory, client kubernetes.Interface, runtimeCELCostBudget int64) (*celAuthorizationConditionsEvaluatorBuilder, error) {
	if informerFactory == nil {
		return nil, fmt.Errorf("NewAuthorizationConditionsEvaluator: informerFactory is required")
	}
	if client == nil {
		return nil, fmt.Errorf("NewAuthorizationConditionsEvaluator: client is required")
	}

	compositionEnvTemplateWithStrictCost := environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion())

	return &celAuthorizationConditionsEvaluatorBuilder{
		compiler: NewCompiler(compositionEnvTemplateWithStrictCost),
		// TODO: Add unit test for using the authorizer
		nsmatcher: &namespacematcher.Matcher{
			NamespaceLister: informerFactory.Core().V1().Namespaces().Lister(),
			Client:          client,
		},
		runtimeCELCostBudget: runtimeCELCostBudget,
	}, nil
}

var _ authorizer.BuiltinConditionsEvaluatorBuilder = &celAuthorizationConditionsEvaluatorBuilder{}

type celAuthorizationConditionsEvaluatorBuilder struct {
	compiler             Compiler
	nsmatcher            *namespacematcher.Matcher
	runtimeCELCostBudget int64
}

func (b *celAuthorizationConditionsEvaluatorBuilder) EvaluatorForData(ctx context.Context, data authorizer.ConditionsData, apiServerAuthorizer authorizer.Authorizer) (authorizer.BuiltinConditionsEvaluator, error) {
	if data == nil {
		return nil, fmt.Errorf("programmer error: data is required")
	}

	versionedAttrs, ok := data.(*admission.VersionedAttributes)
	if !ok {
		return nil, fmt.Errorf("in-process conditions evaluation only supported when data is of type *admission.VersionedAttributes")
	}

	admissionRequest := CreateAdmissionRequest(versionedAttrs, metav1.GroupVersionResource(versionedAttrs.GetResource()), metav1.GroupVersionKind(versionedAttrs.GetKind()))

	ns, err := b.getNamespace(ctx, versionedAttrs)
	if err != nil {
		return nil, err
	}

	// if this activation supports composition, we will need the compositionCtx. It may be nil.
	compositionCtx, _ := ctx.(CompositionContext)

	activation, err := newActivation(compositionCtx, versionedAttrs, admissionRequest, OptionalVariableBindings{VersionedParams: nil, Authorizer: apiServerAuthorizer}, ns)
	if err != nil {
		return nil, err
	}

	return &celAuthorizationConditionsEvaluator{
		builder:           b,
		activation:        activation,
		optionalVarsDecls: OptionalVariableDeclarations{HasParams: false, HasAuthorizer: apiServerAuthorizer != nil},
	}, nil
}

// getNamespace exactly mirrors the similar logic in VAP
func (b *celAuthorizationConditionsEvaluatorBuilder) getNamespace(ctx context.Context, attrs admission.Attributes) (*v1.Namespace, error) {
	var namespace *v1.Namespace
	var err error
	namespaceName := attrs.GetNamespace()

	// Special case, the namespace object has the namespace of itself (maybe a bug).
	// unset it if the incoming object is a namespace
	if gvk := attrs.GetKind(); gvk.Kind == "Namespace" && gvk.Version == "v1" && gvk.Group == "" {
		namespaceName = ""
	}

	// if it is cluster scoped, namespaceName will be empty
	// Otherwise, get the Namespace resource.
	if namespaceName != "" {
		namespace, err = b.nsmatcher.GetNamespace(ctx, namespaceName)
		if err != nil {
			return nil, err
		}
	}

	return CreateNamespaceObject(namespace), nil
}

type celAuthorizationConditionsEvaluator struct {
	builder           *celAuthorizationConditionsEvaluatorBuilder
	optionalVarsDecls OptionalVariableDeclarations
	activation        *evaluationActivation
}

func (e *celAuthorizationConditionsEvaluator) EvaluateCondition(ctx context.Context, condition authorizer.Condition) authorizer.ConditionEvaluationResult {
	// First, check all the essentials, that the condition type is correct, and there is some admission data to evaluate
	if condition == nil {
		return authorizer.ConditionsEvaluationResultUnevaluatable()
	}
	if condition.GetType() != authorizer.ConditionTypeAuthorizationCEL {
		return authorizer.ConditionsEvaluationResultUnevaluatable()
	}
	// It's generally valid for condition strings to be empty, if the semantics of the condition is
	// clear from its (required) ID. However, the CEL evaluator cannot evaluate empty condition strings.
	condStr := condition.GetCondition()
	if len(condStr) == 0 {
		return authorizer.ConditionsEvaluationResultUnevaluatable()
	}

	compiledExpr := e.builder.compiler.CompileCELExpression(validationCondition(condStr), e.optionalVarsDecls, environment.StoredExpressions)

	// if this activation supports composition, we will need the compositionCtx. It may be nil.
	compositionCtx, _ := ctx.(CompositionContext)

	evalResult, _, err := e.activation.Evaluate(ctx, compositionCtx, compiledExpr, e.builder.runtimeCELCostBudget)
	if err != nil {
		return authorizer.ConditionEvaluationResultError(err)
	}

	if evalResult.Error != nil {
		return authorizer.ConditionEvaluationResultError(evalResult.Error)
	}

	return authorizer.ConditionEvaluationResultBoolean(evalResult.EvalResult == celtypes.True)
}

type validationCondition string

func (v validationCondition) GetExpression() string {
	return string(v)
}

func (v validationCondition) ReturnTypes() []*celgo.Type {
	return []*celgo.Type{celgo.BoolType}
}
