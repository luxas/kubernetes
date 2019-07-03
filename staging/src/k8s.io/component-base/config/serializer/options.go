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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type EncodingOptionsFunc func(*EncodingOptions)

// EncodingOptions provides options for encoding
type EncodingOptions struct {
	MediaType string
	GroupVersion *schema.GroupVersion
	Pretty bool
}

func NewEncodingOptions() *EncodingOptions {
	return &EncodingOptions{
		MediaType: runtime.ContentTypeYAML,
	}
}

func (o *EncodingOptions) Apply(fns []EncodingOptionsFunc) {
	for _, fn := range fns {
		fn(o)
	}
}

func WithMediaType(mediaType string) EncodingOptionsFunc {
	return func(opts *EncodingOptions) {
		opts.MediaType = mediaType
	}
}

func WithGroupVersion(gv *schema.GroupVersion) EncodingOptionsFunc {
	return func(opts *EncodingOptions) {
		opts.GroupVersion = gv
	}
}

func WithPretty() EncodingOptionsFunc {
	return func(opts *EncodingOptions) {
		opts.Pretty = true
	}
}
