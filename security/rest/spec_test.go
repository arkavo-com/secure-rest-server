package rest

import (
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/go-openapi/spec"
	"github.com/golang/protobuf/jsonpb"
	"github.com/stretchr/testify/assert"
)

// github.com/go-openapi/runtime/middleware/string_conversion_test.go
func TestValidate(t *testing.T) {
	o := spec.NewOperation("Role_UPDATE")
	o.Parameters = append(o.Parameters, BodyParameter(spec.Schema{
		SchemaProps: spec.SchemaProps{
			Required: []string{"name"},
			Properties: map[string]spec.Schema{
				"prop1": {
					SchemaProps: spec.SchemaProps{
						MinLength: &[]int64{2}[0],
						MaxLength: &[]int64{255}[0],
						Pattern:   "[a-z0-9]",
					},
					SwaggerSchemaProps: spec.SwaggerSchemaProps{
						ReadOnly: true,
					},
				},
				"prop2": {
					SchemaProps: spec.SchemaProps{
						MinLength: &[]int64{2}[0],
						MaxLength: &[]int64{255}[0],
					},
				},
				"prop3": {
					SchemaProps: spec.SchemaProps{
						ID:                   "",
						Ref:                  spec.Ref{},
						Schema:               "",
						Description:          "",
						Type:                 nil,
						Format:               "",
						Title:                "",
						Default:              nil,
						Maximum:              nil,
						ExclusiveMaximum:     false,
						Minimum:              nil,
						ExclusiveMinimum:     false,
						MaxLength:            &[]int64{3}[0],
						MinLength:            &[]int64{1}[0],
						Pattern:              "",
						MaxItems:             nil,
						MinItems:             nil,
						UniqueItems:          false,
						MultipleOf:           nil,
						Enum:                 nil,
						MaxProperties:        nil,
						MinProperties:        nil,
						Required:             nil,
						Items:                nil,
						AllOf:                nil,
						OneOf:                nil,
						AnyOf:                nil,
						Not:                  nil,
						Properties:           nil,
						AdditionalProperties: nil,
						PatternProperties:    nil,
						Dependencies:         nil,
						AdditionalItems:      nil,
						Definitions:          nil,
					},
				},
			},
		},
	}))
	pb := message{
		Name:  "testName",
		Prop1: "abcd",
		Prop2: "xyz",
		Prop3: 1,
	}
	b, _ := (&jsonpb.Marshaler{}).MarshalToString(&pb)
	w := testHttpWriter{
		h: http.Header{},
	}
	w.h.Add("content-type", "application/json")
	r := http.Request{
		Method: "POST",
		Body:   ioutil.NopCloser(strings.NewReader(b)),
		Header: w.h,
	}
	err := Validate(&r, o, &pb)
	assert.NoError(t, err)
}

type testHttpWriter struct {
	h http.Header
}

func (w testHttpWriter) Header() http.Header               { return w.h }
func (w testHttpWriter) WriteHeader(int)                   {} // no headers
func (w testHttpWriter) Write(p []byte) (n int, err error) { return 0, nil }

type message struct {
	Name  string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
	Prop1 string `protobuf:"bytes,2,opt,name=prop1" json:"prop1,omitempty"`
	Prop2 string `protobuf:"bytes,3,opt,name=prop2" json:"prop2,omitempty"`
	Prop3 int    `protobuf:"bytes,4,opt,name=prop3" json:"prop3,omitempty"`
}

func (m message) Reset()         {}
func (m message) String() string { return "" }
func (m message) ProtoMessage()  {}
