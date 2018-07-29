package rest

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-openapi/spec"
	"github.com/golang/protobuf/jsonpb"
	"github.com/stretchr/testify/assert"
)

var (
	parameterTest = spec.Parameter{
		ParamProps: spec.ParamProps{
			Name:            "TEST",
			In:              "query",
			AllowEmptyValue: true,
			Required:        false,
		},
	}
	parameterCancel = spec.Parameter{
		ParamProps: spec.ParamProps{
			Name:            "CANCEL",
			In:              "query",
			AllowEmptyValue: true,
			Required:        false,
		},
	}
)

func TestValidateParameterQueryAction(t *testing.T) {
	r := httptest.NewRequest("GET", "/account?TEST", nil)
	rn := httptest.NewRequest("GET", "/account", nil)
	ro := httptest.NewRequest("GET", "/account?BOGUS", nil)
	r2 := httptest.NewRequest("GET", "/account?TEST&CANCEL", nil)
	ri := httptest.NewRequest("GET", "/account?TEST=test", nil)
	type args struct {
		r  http.Request
		ps []spec.Parameter
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"valid", args{
			*r,
			[]spec.Parameter{parameterTest},
		}, "TEST"},
		{"none", args{
			*rn,
			[]spec.Parameter{parameterTest},
		}, ""},
		{"other", args{
			*ro,
			[]spec.Parameter{parameterTest},
		}, ""},
		{"valid many", args{
			*r2,
			[]spec.Parameter{parameterTest, parameterCancel},
		}, "TEST"},
		{"valid value", args{
			*ri,
			[]spec.Parameter{parameterTest},
		}, "TEST"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateParameterQueryAction(tt.args.r, tt.args.ps...); got != tt.want {
				t.Errorf("ValidateParameterQueryAction() = %v, want %v", got, tt.want)
			}
		})
	}
}

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
	w := testHTTPWriter{
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

type testHTTPWriter struct {
	h http.Header
}

func (w testHTTPWriter) Header() http.Header               { return w.h }
func (w testHTTPWriter) WriteHeader(int)                   {} // no headers
func (w testHTTPWriter) Write(p []byte) (n int, err error) { return 0, nil }

type message struct {
	Name  string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
	Prop1 string `protobuf:"bytes,2,opt,name=prop1" json:"prop1,omitempty"`
	Prop2 string `protobuf:"bytes,3,opt,name=prop2" json:"prop2,omitempty"`
	Prop3 int    `protobuf:"bytes,4,opt,name=prop3" json:"prop3,omitempty"`
}

func (m message) Reset()         {}
func (m message) String() string { return "" }
func (m message) ProtoMessage()  {}
