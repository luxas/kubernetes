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

package v1

import (
	"k8s.io/apimachinery/pkg/util/sets"
)

var conditionalAuthorizationDecisionTypes = sets.New(
	// unconditional
	ConditionsAwareDecisionTypeAllow,
	ConditionsAwareDecisionTypeDeny,
	ConditionsAwareDecisionTypeNoOpinion,
	// conditional
	ConditionsAwareDecisionTypeConditionsMap,
	ConditionsAwareDecisionTypeUnion,
)

var unconditionalAuthorizationDecisionTypes = sets.New(
	// unconditional
	ConditionsAwareDecisionTypeAllow,
	ConditionsAwareDecisionTypeDeny,
	ConditionsAwareDecisionTypeNoOpinion,
)

func (ao *AuthorizationOptions) SupportsConditionalAuthorization() bool {
	return ao.GetHandledDecisionTypes().IsSuperset(conditionalAuthorizationDecisionTypes)
}

func (ao *AuthorizationOptions) SupportsUnconditionalAuthorization() bool {
	return ao.GetHandledDecisionTypes().IsSuperset(unconditionalAuthorizationDecisionTypes)
}

func (ao *AuthorizationOptions) GetHandledDecisionTypes() sets.Set[ConditionsAwareDecisionType] {
	if ao == nil {
		return UnconditionalAuthorizationDecisionTypes()
	}
	return sets.New(ao.HandledDecisionTypes...)
}

func ConditionalAuthorizationDecisionTypes() sets.Set[ConditionsAwareDecisionType] {
	return conditionalAuthorizationDecisionTypes.Clone() // always return fresh copies, never expose the original data
}

func UnconditionalAuthorizationDecisionTypes() sets.Set[ConditionsAwareDecisionType] {
	return unconditionalAuthorizationDecisionTypes.Clone() // always return fresh copies, never expose the original data
}
