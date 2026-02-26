# Unit tests for authorizer/conditional.go

write unit tests for all cases supported in sampleAuthorizer in staging/src/k8s.io/apiserver/pkg/authorization/authorizer/conditional_test.go. the test case matrix should use an outermost layer which specifies the given            
  attributes, and then a list of inner cases with the object specified, and the wanted final decision (from the Authorize + decision.EvaluateConditions combination). use unstructured.Unstructured for specifying an implementation    
   of the objects in conditiondata

## Union

write a unit test for the evaluation part of the union authorizer (staging/src/k8s.io/apiserver/pkg/authorization/union/union.go). let there be four union authorizers, union0, union1, union2 and union3. let there be five normal           
  authorizer implementations: authz1 to authz5. union0 is a chain of [union1, union2, authz5], union1=[union2, authz3], union2=[authz1, authz2]. this DAG setup should be shared across all test cases. in each test case, let it be             
  configurable what authz1-5 returns, for both Authorize and EvaluateConditions. assert what the result of Authorize + EvaluateConditions of union0 is. Cover all the combinations in the code