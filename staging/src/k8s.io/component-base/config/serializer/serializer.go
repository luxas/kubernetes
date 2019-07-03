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

package serializer

import (
	"io/ioutil"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

// ConfigSerializer provides encoding/decoding for a configuration file
type ConfigSerializer interface {
	DecodeInto([]byte, runtime.Object) error
	DecodeFileInto(string, runtime.Object) error
	Encode(runtime.Object, ...EncodingOptionsFunc) ([]byte, error)
	EncodeToFile(string, runtime.Object, ...EncodingOptionsFunc) error
	DefaultInternal(runtime.Object) error
}

// NewConfigSerializer creates a new implementation of the ConfigSerializer interface
func NewConfigSerializer(scheme *runtime.Scheme) ConfigSerializer {
	codecs := serializer.NewCodecFactory(scheme)
	return &configSerializer{
		scheme: scheme,
		codecs: &codecs,
	}
	// TODO: Strict serializer
}

type configSerializer struct {
	scheme     *runtime.Scheme
	codecs     *serializer.CodecFactory
}

func (cs *configSerializer) DecodeInto(data []byte, obj runtime.Object) error {
	return runtime.DecodeInto(cs.codecs.UniversalDecoder(), data, obj)
}

// ReadConfigFileInto reads a file into a pointer
func (cs *configSerializer) DecodeFileInto(fileName string, obj runtime.Object) error {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return err
	}
	return cs.DecodeInto(data, obj)
}

func (cs *configSerializer) EncodeToFile(fileName string, cfg runtime.Object, optFuncs ...EncodingOptionsFunc) error {
	data, err := cs.Encode(cfg, optFuncs...)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fileName, data, 0664)
}

// Encode writes the config into the given file name as YAML.
func (cs *configSerializer) Encode(cfg runtime.Object, optFuncs ...EncodingOptionsFunc) ([]byte, error) {
	opts := NewEncodingOptions()
	opts.Apply(optFuncs)

	if opts.GroupVersion == nil {
		// Default to using the preferred external version here
		gvk, err := cs.externalGVKForObject(cfg)
		if err != nil {
			return nil, err
		}
		gv := gvk.GroupVersion()
		opts.GroupVersion = &gv
	}
	return cs.encode(cfg, *opts)
}

func (cs *configSerializer) externalGVKForObject(cfg runtime.Object) (*schema.GroupVersionKind, error) {
	gvks, unversioned, err := cs.scheme.ObjectKinds(cfg)
	if unversioned || err != nil || len(gvks) != 1 {
		return nil, fmt.Errorf("unversioned %t or err %v or invalid gvks %v", unversioned, err, gvks)
	}
	gvk := gvks[0]
	gvs := cs.scheme.PrioritizedVersionsForGroup(gvk.Group)
	if len(gvs) < 1 {
		return nil, fmt.Errorf("expected some version to be registered for group %s", gvk.Group)
	}
	// Use the preferred (external) version
	gvk.Version = gvs[0].Version
	return &gvk, nil
}

func (cs *configSerializer) encode(cfg runtime.Object, opts EncodingOptions) ([]byte, error) {
	info, ok := runtime.SerializerInfoForMediaType(cs.codecs.SupportedMediaTypes(), opts.MediaType)
	if !ok {
		return nil, fmt.Errorf("unable to locate encoder -- %q is not a supported media type", opts.MediaType)
	}
	serializer := info.Serializer
	if opts.Pretty {
		serializer = info.PrettySerializer
	}
	encoder := cs.codecs.EncoderForVersion(serializer, *opts.GroupVersion)
	return runtime.Encode(encoder, cfg)
}

// DefaultInternal populates the given internal object with the preferred external version's defaults
func (cs *configSerializer) DefaultInternal(cfg runtime.Object) error {
	gvk, err := cs.externalGVKForObject(cfg)
	if err != nil {
		return err
	}
	external, err := cs.scheme.New(*gvk)
	if err != nil {
		return nil
	}
	if err := cs.scheme.Convert(cfg, external, nil); err != nil {
		return err
	}
	cs.scheme.Default(external)
	return cs.scheme.Convert(external, cfg, nil)
}
