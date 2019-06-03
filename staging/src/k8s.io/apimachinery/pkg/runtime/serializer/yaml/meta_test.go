/*
Copyright 2019 The Kubernetes Authors.

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

package yaml

import "testing"

func TestSimpleMetaFactoryInterpret(t *testing.T) {
	factory := SimpleMetaFactory{}
	gvk, err := factory.Interpret([]byte(`
apiVersion: a/b
kind: object
`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gvk.Group != "a" || gvk.Version != "b" || gvk.Kind != "object" {
		t.Errorf("unexpected interpret: %#v", gvk)
	}

	// no kind or version
	gvk, err = factory.Interpret([]byte(`
foo: bar
`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gvk.Version != "" || gvk.Kind != "" {
		t.Errorf("unexpected interpret: %#v", gvk)
	}

	// unparsable
	gvk, err = factory.Interpret([]byte(`
invalid <nil>
bar:`))
	if err == nil {
		t.Errorf("unexpected non-error")
	}
}
