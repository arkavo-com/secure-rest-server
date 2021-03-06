// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.24.0
// 	protoc        v3.12.3
// source: session.proto

package security

import (
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type Session_State int32

const (
	Session_initial Session_State = 0 // not used
	// Action:CREATE
	Session_Activated Session_State = 2
	// Action:IDLE,Action:REDUCE
	Session_Reduced Session_State = 3
	// Action:EXPIRE,TERMINATE
	Session_Deactivated Session_State = 5
)

// Enum value maps for Session_State.
var (
	Session_State_name = map[int32]string{
		0: "initial",
		2: "Activated",
		3: "Reduced",
		5: "Deactivated",
	}
	Session_State_value = map[string]int32{
		"initial":     0,
		"Activated":   2,
		"Reduced":     3,
		"Deactivated": 5,
	}
)

func (x Session_State) Enum() *Session_State {
	p := new(Session_State)
	*p = x
	return p
}

func (x Session_State) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Session_State) Descriptor() protoreflect.EnumDescriptor {
	return file_session_proto_enumTypes[0].Descriptor()
}

func (Session_State) Type() protoreflect.EnumType {
	return &file_session_proto_enumTypes[0]
}

func (x Session_State) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Session_State.Descriptor instead.
func (Session_State) EnumDescriptor() ([]byte, []int) {
	return file_session_proto_rawDescGZIP(), []int{0, 0}
}

type Session_Action int32

const (
	Session_CREATE    Session_Action = 0
	Session_READ      Session_Action = 1
	Session_IDLE      Session_Action = 2
	Session_EXPIRE    Session_Action = 3
	Session_TERMINATE Session_Action = 4
	Session_REDUCE    Session_Action = 5
)

// Enum value maps for Session_Action.
var (
	Session_Action_name = map[int32]string{
		0: "CREATE",
		1: "READ",
		2: "IDLE",
		3: "EXPIRE",
		4: "TERMINATE",
		5: "REDUCE",
	}
	Session_Action_value = map[string]int32{
		"CREATE":    0,
		"READ":      1,
		"IDLE":      2,
		"EXPIRE":    3,
		"TERMINATE": 4,
		"REDUCE":    5,
	}
)

func (x Session_Action) Enum() *Session_Action {
	p := new(Session_Action)
	*p = x
	return p
}

func (x Session_Action) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Session_Action) Descriptor() protoreflect.EnumDescriptor {
	return file_session_proto_enumTypes[1].Descriptor()
}

func (Session_Action) Type() protoreflect.EnumType {
	return &file_session_proto_enumTypes[1]
}

func (x Session_Action) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Session_Action.Descriptor instead.
func (Session_Action) EnumDescriptor() ([]byte, []int) {
	return file_session_proto_rawDescGZIP(), []int{0, 1}
}

// A container of time-limited permissions shared with a subject
type Session struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// privately shared identifier `json:"-"`
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// account.proto:Account.name
	Account     string        `protobuf:"bytes,2,opt,name=account,proto3" json:"account,omitempty"`
	Csrf        string        `protobuf:"bytes,3,opt,name=csrf,proto3" json:"csrf,omitempty"`
	Permissions []*Permission `protobuf:"bytes,4,rep,name=permissions,proto3" json:"permissions,omitempty"`
	State       Session_State `protobuf:"varint,5,opt,name=state,proto3,enum=security.Session_State" json:"state,omitempty"`
}

func (x *Session) Reset() {
	*x = Session{}
	if protoimpl.UnsafeEnabled {
		mi := &file_session_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Session) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Session) ProtoMessage() {}

func (x *Session) ProtoReflect() protoreflect.Message {
	mi := &file_session_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Session.ProtoReflect.Descriptor instead.
func (*Session) Descriptor() ([]byte, []int) {
	return file_session_proto_rawDescGZIP(), []int{0}
}

func (x *Session) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Session) GetAccount() string {
	if x != nil {
		return x.Account
	}
	return ""
}

func (x *Session) GetCsrf() string {
	if x != nil {
		return x.Csrf
	}
	return ""
}

func (x *Session) GetPermissions() []*Permission {
	if x != nil {
		return x.Permissions
	}
	return nil
}

func (x *Session) GetState() Session_State {
	if x != nil {
		return x.State
	}
	return Session_initial
}

var File_session_proto protoreflect.FileDescriptor

var file_session_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x08, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x1a, 0x10, 0x70, 0x65, 0x72, 0x6d, 0x69,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xc2, 0x02, 0x0a, 0x07,
	0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x61, 0x63, 0x63, 0x6f, 0x75,
	0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x61, 0x63, 0x63, 0x6f, 0x75, 0x6e,
	0x74, 0x12, 0x12, 0x0a, 0x04, 0x63, 0x73, 0x72, 0x66, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x63, 0x73, 0x72, 0x66, 0x12, 0x36, 0x0a, 0x0b, 0x70, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73,
	0x69, 0x6f, 0x6e, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x73, 0x65, 0x63,
	0x75, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x50, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e,
	0x52, 0x0b, 0x70, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x2d, 0x0a,
	0x05, 0x73, 0x74, 0x61, 0x74, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x17, 0x2e, 0x73,
	0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2e,
	0x53, 0x74, 0x61, 0x74, 0x65, 0x52, 0x05, 0x73, 0x74, 0x61, 0x74, 0x65, 0x22, 0x41, 0x0a, 0x05,
	0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x0b, 0x0a, 0x07, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x6c,
	0x10, 0x00, 0x12, 0x0d, 0x0a, 0x09, 0x41, 0x63, 0x74, 0x69, 0x76, 0x61, 0x74, 0x65, 0x64, 0x10,
	0x02, 0x12, 0x0b, 0x0a, 0x07, 0x52, 0x65, 0x64, 0x75, 0x63, 0x65, 0x64, 0x10, 0x03, 0x12, 0x0f,
	0x0a, 0x0b, 0x44, 0x65, 0x61, 0x63, 0x74, 0x69, 0x76, 0x61, 0x74, 0x65, 0x64, 0x10, 0x05, 0x22,
	0x4f, 0x0a, 0x06, 0x41, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x0a, 0x0a, 0x06, 0x43, 0x52, 0x45,
	0x41, 0x54, 0x45, 0x10, 0x00, 0x12, 0x08, 0x0a, 0x04, 0x52, 0x45, 0x41, 0x44, 0x10, 0x01, 0x12,
	0x08, 0x0a, 0x04, 0x49, 0x44, 0x4c, 0x45, 0x10, 0x02, 0x12, 0x0a, 0x0a, 0x06, 0x45, 0x58, 0x50,
	0x49, 0x52, 0x45, 0x10, 0x03, 0x12, 0x0d, 0x0a, 0x09, 0x54, 0x45, 0x52, 0x4d, 0x49, 0x4e, 0x41,
	0x54, 0x45, 0x10, 0x04, 0x12, 0x0a, 0x0a, 0x06, 0x52, 0x45, 0x44, 0x55, 0x43, 0x45, 0x10, 0x05,
	0x42, 0x0a, 0x5a, 0x08, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_session_proto_rawDescOnce sync.Once
	file_session_proto_rawDescData = file_session_proto_rawDesc
)

func file_session_proto_rawDescGZIP() []byte {
	file_session_proto_rawDescOnce.Do(func() {
		file_session_proto_rawDescData = protoimpl.X.CompressGZIP(file_session_proto_rawDescData)
	})
	return file_session_proto_rawDescData
}

var file_session_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_session_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_session_proto_goTypes = []interface{}{
	(Session_State)(0),  // 0: security.Session.State
	(Session_Action)(0), // 1: security.Session.Action
	(*Session)(nil),     // 2: security.Session
	(*Permission)(nil),  // 3: security.Permission
}
var file_session_proto_depIdxs = []int32{
	3, // 0: security.Session.permissions:type_name -> security.Permission
	0, // 1: security.Session.state:type_name -> security.Session.State
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_session_proto_init() }
func file_session_proto_init() {
	if File_session_proto != nil {
		return
	}
	file_permission_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_session_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Session); i {
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
			RawDescriptor: file_session_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_session_proto_goTypes,
		DependencyIndexes: file_session_proto_depIdxs,
		EnumInfos:         file_session_proto_enumTypes,
		MessageInfos:      file_session_proto_msgTypes,
	}.Build()
	File_session_proto = out.File
	file_session_proto_rawDesc = nil
	file_session_proto_goTypes = nil
	file_session_proto_depIdxs = nil
}
