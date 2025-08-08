package webhook

import (
	"reflect"
	"testing"

	v1 "k8s.io/api/admissionregistration/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	apiextensionsscheme "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/scheme"
	"k8s.io/apiserver/pkg/cel/openapi/resolver"
	"k8s.io/client-go/discovery"
	cacheddiscovery "k8s.io/client-go/discovery/cached"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/kubernetes/pkg/generated/openapi"
)

func TestTypeChecker(t *testing.T) {

	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		nil).ClientConfig()
	if err != nil {
		t.Fatalf("failed to get starting config: %v", err)
	}

	discoveryClient, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create discovery client: %v", err)
	}

	discoverycached := cacheddiscovery.NewMemCacheClient(discoveryClient)

	restMapper := restmapper.NewDeferredDiscoveryRESTMapper(discoverycached)

	schemaResolver := resolver.NewDefinitionsSchemaResolver(openapi.GetOpenAPIDefinitions, scheme.Scheme, apiextensionsscheme.Scheme).
		Combine(&resolver.ClientDiscoveryResolver{Discovery: discoverycached})

	typeChecker := &TypeChecker{
		SchemaResolver: schemaResolver,
		RestMapper:     restMapper,
	}

	tests := []struct {
		name    string
		sar     *authorizationv1.SubjectAccessReview
		want    []v1.ExpressionWarning
		wantErr bool
	}{
		{
			name: "test",
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Verb:     "create",
						Group:    "apps",
						Version:  "v1",
						Resource: "deployments",
					},
				},
				Status: authorizationv1.SubjectAccessReviewStatus{
					Conditions: []authorizationv1.SubjectAccessReviewCondition{
						{
							Condition: "object.metsadata.name == 'test'",
						},
					},
				},
			},
			want:    nil,
			wantErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			warnings, err := typeChecker.Check(test.sar)
			if (err != nil) != test.wantErr {
				t.Errorf("TypeChecker.Check() error = %v, wantErr %v", err, test.wantErr)
			}
			if !reflect.DeepEqual(warnings, test.want) {
				t.Errorf("TypeChecker.Check() = %v, want %v", warnings, test.want)
			}
		})
	}
}
