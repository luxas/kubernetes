# Considerations to add to the KEP

## 1. Conditions can be written against different types of ConditionData

e.g. normal write requests vs impersonation data

## 2. CEL can be used for MatchConditions

When AuthorizationConfiguration figures out whether to send a SAR

## 3. How to decode the objects in ACR

We encode objects in AdmissionReview only as JSON, so probably JSON is ok.
However, the kube-apiserver could act as a relay in between a webhook
authorizer, and an aggregated API server. Thus might the kube-apiserver
recognize the object, as it might be specific to the aggregated API server. We
need to test that runtime.RawExtension works.
