package rest

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"github.com/go-openapi/spec"
	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/runtime/protoimpl"
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
	b, err := protojson.Marshal(&pb)
	w := testHTTPWriter{
		h: http.Header{},
	}
	w.h.Add("content-type", "application/json")
	r := http.Request{
		Method: "POST",
		Body:   ioutil.NopCloser(bytes.NewReader(b)),
		Header: w.h,
	}
	err = Validate(&r, o, &pb)
	assert.NoError(t, err)
}

type testHTTPWriter struct {
	h http.Header
}

func (w testHTTPWriter) Header() http.Header               { return w.h }
func (w testHTTPWriter) WriteHeader(int)                   {} // no headers
func (w testHTTPWriter) Write(p []byte) (n int, err error) { return 0, nil }

//syntax = "proto3";
//option go_package = "security";
//
//message TestMessage {
//    string name = 1;
//    string prop1 = 2;
//    string prop2 = 3;
//    int32 prop3 = 4;
//}
const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name  string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Prop1 string `protobuf:"bytes,2,opt,name=prop1,proto3" json:"prop1,omitempty"`
	Prop2 string `protobuf:"bytes,3,opt,name=prop2,proto3" json:"prop2,omitempty"`
	Prop3 int32  `protobuf:"varint,4,opt,name=prop3,proto3" json:"prop3,omitempty"`
}

func (x *message) Reset() {
	*x = message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_message_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*message) ProtoMessage() {}

func (x *message) ProtoReflect() protoreflect.Message {
	mi := &file_message_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TestMessage.ProtoReflect.Descriptor instead.
func (*message) Descriptor() ([]byte, []int) {
	return file_message_proto_rawDescGZIP(), []int{0}
}

func (x *message) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *message) GetProp1() string {
	if x != nil {
		return x.Prop1
	}
	return ""
}

func (x *message) GetProp2() string {
	if x != nil {
		return x.Prop2
	}
	return ""
}

func (x *message) GetProp3() int32 {
	if x != nil {
		return x.Prop3
	}
	return 0
}

var File_message_proto protoreflect.FileDescriptor

var file_message_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x63, 0x0a, 0x0b, 0x54, 0x65, 0x73, 0x74, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x12,
	0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x70, 0x72, 0x6f, 0x70, 0x31, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x05, 0x70, 0x72, 0x6f, 0x70, 0x31, 0x12, 0x14, 0x0a, 0x05, 0x70, 0x72, 0x6f, 0x70,
	0x32, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x70, 0x72, 0x6f, 0x70, 0x32, 0x12, 0x14,
	0x0a, 0x05, 0x70, 0x72, 0x6f, 0x70, 0x33, 0x18, 0x04, 0x20, 0x01, 0x28, 0x05, 0x52, 0x05, 0x70,
	0x72, 0x6f, 0x70, 0x33, 0x42, 0x0a, 0x5a, 0x08, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_message_proto_rawDescOnce sync.Once
	file_message_proto_rawDescData = file_message_proto_rawDesc
)

func file_message_proto_rawDescGZIP() []byte {
	file_message_proto_rawDescOnce.Do(func() {
		file_message_proto_rawDescData = protoimpl.X.CompressGZIP(file_message_proto_rawDescData)
	})
	return file_message_proto_rawDescData
}

var file_message_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_message_proto_goTypes = []interface{}{
	(*message)(nil), // 0: TestMessage
}
var file_message_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_message_proto_init() }
func file_message_proto_init() {
	if File_message_proto != nil {
		return
	}
	if false {
		file_message_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*message); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_message_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_message_proto_goTypes,
		DependencyIndexes: file_message_proto_depIdxs,
		MessageInfos:      file_message_proto_msgTypes,
	}.Build()
	File_message_proto = out.File
	file_message_proto_rawDesc = nil
	file_message_proto_goTypes = nil
	file_message_proto_depIdxs = nil
}
