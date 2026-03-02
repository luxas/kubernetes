package conditionsenforcer

import (
	"context"
	"sync"

	celgo "github.com/google/cel-go/cel"
	celtypes "github.com/google/cel-go/common/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	plugincel "k8s.io/apiserver/pkg/admission/plugin/cel"
	apiscel "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/cel/environment"
)

const (
	ConditionTypeAuthorizationCEL authorizer.ConditionType = "k8s.io/authorization-cel"
)

var (
	lazyCompositionEnvTemplateWithStrictCostInit sync.Once
	lazyCompositionEnvTemplateWithStrictCost     *environment.EnvSet
)

func getCompositionEnvTemplateWithStrictCost() *environment.EnvSet {
	lazyCompositionEnvTemplateWithStrictCostInit.Do(func() {
		lazyCompositionEnvTemplateWithStrictCost = environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion())
	})
	return lazyCompositionEnvTemplateWithStrictCost
}

var _ authorizer.ConditionSetEvaluator = &celConditionsEnforcer{}

type celConditionsEnforcer struct{}

func (e *celConditionsEnforcer) EvaluateConditions(ctx context.Context, unevaluatedDecision authorizer.Decision, data authorizer.ConditionData) (authorizer.Decision, error) {
	wr := data.WriteRequest()
	if wr == nil {
		// Can only evaluate write requests for now
		return unevaluatedDecision, nil
	}
	return e.evaluateWriteRequest(ctx, unevaluatedDecision, wr, apiscel.RuntimeCELCostBudget)
}

// runtimeCELCostBudget was added for testing purpose only. Callers should always use const RuntimeCELCostBudget from k8s.io/apiserver/pkg/apis/cel/config.go as input.
func (e *celConditionsEnforcer) evaluateWriteRequest(ctx context.Context, unevaluatedDecision authorizer.Decision, wr authorizer.WriteRequestConditionData, runtimeCELCostBudget int64) (authorizer.Decision, error) {
	if unevaluatedDecision.IsAllowed() || unevaluatedDecision.IsDenied() || unevaluatedDecision.IsNoOpinion() {
		// Nothing to evaluate
		return unevaluatedDecision, nil
	}

	if !unevaluatedDecision.IsConditional() {
		return unevaluatedDecision, nil // TODO(luxas)
	}

	conditionSet := unevaluatedDecision.ConditionSet()

	attrsShim, ok := wr.(*attrsShim)
	if !ok {
		// TODO(luxas): Make more generic when we have a decision on how much data to include here.
		return unevaluatedDecision, nil
	}

	optionalVarsDecls := plugincel.OptionalVariableDeclarations{HasParams: false, HasAuthorizer: true}
	compositionEnvTemplate := getCompositionEnvTemplateWithStrictCost()
	filterCompiler, err := plugincel.NewCompositedCompiler(compositionEnvTemplate)
	if err != nil {
		return unevaluatedDecision, err
	}

	return authorizer.EvaluateConditionSet(conditionSet, ConditionTypeAuthorizationCEL, func(condStr string) (bool, error) {
		// TODO: Compile all deny conditions at a time, then all no opinion, etc?
		evaluator := filterCompiler.CompileCondition([]plugincel.ExpressionAccessor{validationCondition(condStr)}, optionalVarsDecls, environment.StoredExpressions)

		optionalVars := plugincel.OptionalVariableBindings{VersionedParams: nil, Authorizer: nil} // TODO(luxas): authorizer support
		admissionRequest := plugincel.CreateAdmissionRequest(attrsShim.Attributes, metav1.GroupVersionResource(attrsShim.GetResource()), metav1.GroupVersionKind(attrsShim.VersionedKind))
		// Decide which fields are exposed
		ns := plugincel.CreateNamespaceObject(nil) // TODO(luxas): namespace support
		// TODO(luxas): Do we trust the authorizer to give reasonable-length conditions?
		// Can a webhook authorizer today block a request for e.g. 60s?
		evalResults, _, err := evaluator.ForInput(ctx, attrsShim.VersionedAttributes, admissionRequest, optionalVars, ns, runtimeCELCostBudget)
		if err != nil {
			return false, err
		}
		evalResult := &evalResults[0]
		if evalResult.Error != nil {
			return false, evalResult.Error
		}
		return evalResult.EvalResult == celtypes.True, nil
	})
}

type validationCondition string

func (v validationCondition) GetExpression() string {
	return string(v)
}

func (v validationCondition) ReturnTypes() []*celgo.Type {
	return []*celgo.Type{celgo.BoolType}
}
