// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.24.0
// 	protoc        v3.12.3
// source: account.proto

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

type Account_State int32

const (
	Account_nonstate Account_State = 0 // not used
	// Account_CREATE,Account_INITIALIZE
	Account_Initialized Account_State = 1
	// Account_ACTIVATE,Account_UPDATE_PASSWORD
	Account_Activated Account_State = 2
	// Account_LOCK
	Account_Locked Account_State = 3
	// Account_DEACTIVATE
	Account_Deactivated Account_State = 4
)

// Enum value maps for Account_State.
var (
	Account_State_name = map[int32]string{
		0: "nonstate",
		1: "Initialized",
		2: "Activated",
		3: "Locked",
		4: "Deactivated",
	}
	Account_State_value = map[string]int32{
		"nonstate":    0,
		"Initialized": 1,
		"Activated":   2,
		"Locked":      3,
		"Deactivated": 4,
	}
)

func (x Account_State) Enum() *Account_State {
	p := new(Account_State)
	*p = x
	return p
}

func (x Account_State) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Account_State) Descriptor() protoreflect.EnumDescriptor {
	return file_account_proto_enumTypes[0].Descriptor()
}

func (Account_State) Type() protoreflect.EnumType {
	return &file_account_proto_enumTypes[0]
}

func (x Account_State) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Account_State.Descriptor instead.
func (Account_State) EnumDescriptor() ([]byte, []int) {
	return file_account_proto_rawDescGZIP(), []int{0, 0}
}

type Account_Action int32

const (
	Account_CREATE          Account_Action = 0
	Account_READ            Account_Action = 1
	Account_UPDATE          Account_Action = 2
	Account_DELETE          Account_Action = 3
	Account_UPDATE_PASSWORD Account_Action = 4
	Account_ACTIVATE        Account_Action = 5
	Account_DEACTIVATE      Account_Action = 6
	Account_LOCK            Account_Action = 7
	Account_INITIALIZE      Account_Action = 8
)

// Enum value maps for Account_Action.
var (
	Account_Action_name = map[int32]string{
		0: "CREATE",
		1: "READ",
		2: "UPDATE",
		3: "DELETE",
		4: "UPDATE_PASSWORD",
		5: "ACTIVATE",
		6: "DEACTIVATE",
		7: "LOCK",
		8: "INITIALIZE",
	}
	Account_Action_value = map[string]int32{
		"CREATE":          0,
		"READ":            1,
		"UPDATE":          2,
		"DELETE":          3,
		"UPDATE_PASSWORD": 4,
		"ACTIVATE":        5,
		"DEACTIVATE":      6,
		"LOCK":            7,
		"INITIALIZE":      8,
	}
)

func (x Account_Action) Enum() *Account_Action {
	p := new(Account_Action)
	*p = x
	return p
}

func (x Account_Action) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Account_Action) Descriptor() protoreflect.EnumDescriptor {
	return file_account_proto_enumTypes[1].Descriptor()
}

func (Account_Action) Type() protoreflect.EnumType {
	return &file_account_proto_enumTypes[1]
}

func (x Account_Action) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Account_Action.Descriptor instead.
func (Account_Action) EnumDescriptor() ([]byte, []int) {
	return file_account_proto_rawDescGZIP(), []int{0, 1}
}

// A system account to allow access for a subject
type Account struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// unique name
	Name  string        `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Salt  string        `protobuf:"bytes,2,opt,name=salt,proto3" json:"salt,omitempty"`
	Hash  string        `protobuf:"bytes,3,opt,name=hash,proto3" json:"hash,omitempty"`
	State Account_State `protobuf:"varint,4,opt,name=state,proto3,enum=security.Account_State" json:"state,omitempty"`
	// []role.proto:Role.name
	Roles []string `protobuf:"bytes,5,rep,name=roles,proto3" json:"roles,omitempty"`
}

func (x *Account) Reset() {
	*x = Account{}
	if protoimpl.UnsafeEnabled {
		mi := &file_account_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Account) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Account) ProtoMessage() {}

func (x *Account) ProtoReflect() protoreflect.Message {
	mi := &file_account_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Account.ProtoReflect.Descriptor instead.
func (*Account) Descriptor() ([]byte, []int) {
	return file_account_proto_rawDescGZIP(), []int{0}
}

func (x *Account) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Account) GetSalt() string {
	if x != nil {
		return x.Salt
	}
	return ""
}

func (x *Account) GetHash() string {
	if x != nil {
		return x.Hash
	}
	return ""
}

func (x *Account) GetState() Account_State {
	if x != nil {
		return x.State
	}
	return Account_nonstate
}

func (x *Account) GetRoles() []string {
	if x != nil {
		return x.Roles
	}
	return nil
}

var File_account_proto protoreflect.FileDescriptor

var file_account_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x61, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x08, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x1a, 0x0a, 0x64, 0x61, 0x74, 0x61, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xf0, 0x02, 0x0a, 0x07, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e,
	0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x18, 0x0a, 0x04, 0x73, 0x61, 0x6c, 0x74, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x42, 0x04, 0x80, 0xb5, 0x18, 0x01, 0x52, 0x04, 0x73, 0x61, 0x6c, 0x74, 0x12,
	0x18, 0x0a, 0x04, 0x68, 0x61, 0x73, 0x68, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x42, 0x04, 0x80,
	0xb5, 0x18, 0x01, 0x52, 0x04, 0x68, 0x61, 0x73, 0x68, 0x12, 0x2d, 0x0a, 0x05, 0x73, 0x74, 0x61,
	0x74, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x17, 0x2e, 0x73, 0x65, 0x63, 0x75, 0x72,
	0x69, 0x74, 0x79, 0x2e, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x2e, 0x53, 0x74, 0x61, 0x74,
	0x65, 0x52, 0x05, 0x73, 0x74, 0x61, 0x74, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x72, 0x6f, 0x6c, 0x65,
	0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x09, 0x52, 0x05, 0x72, 0x6f, 0x6c, 0x65, 0x73, 0x22, 0x52,
	0x0a, 0x05, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x0c, 0x0a, 0x08, 0x6e, 0x6f, 0x6e, 0x73, 0x74,
	0x61, 0x74, 0x65, 0x10, 0x00, 0x12, 0x0f, 0x0a, 0x0b, 0x49, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x6c,
	0x69, 0x7a, 0x65, 0x64, 0x10, 0x01, 0x12, 0x0d, 0x0a, 0x09, 0x41, 0x63, 0x74, 0x69, 0x76, 0x61,
	0x74, 0x65, 0x64, 0x10, 0x02, 0x12, 0x0a, 0x0a, 0x06, 0x4c, 0x6f, 0x63, 0x6b, 0x65, 0x64, 0x10,
	0x03, 0x12, 0x0f, 0x0a, 0x0b, 0x44, 0x65, 0x61, 0x63, 0x74, 0x69, 0x76, 0x61, 0x74, 0x65, 0x64,
	0x10, 0x04, 0x22, 0x83, 0x01, 0x0a, 0x06, 0x41, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x0a, 0x0a,
	0x06, 0x43, 0x52, 0x45, 0x41, 0x54, 0x45, 0x10, 0x00, 0x12, 0x08, 0x0a, 0x04, 0x52, 0x45, 0x41,
	0x44, 0x10, 0x01, 0x12, 0x0a, 0x0a, 0x06, 0x55, 0x50, 0x44, 0x41, 0x54, 0x45, 0x10, 0x02, 0x12,
	0x0a, 0x0a, 0x06, 0x44, 0x45, 0x4c, 0x45, 0x54, 0x45, 0x10, 0x03, 0x12, 0x13, 0x0a, 0x0f, 0x55,
	0x50, 0x44, 0x41, 0x54, 0x45, 0x5f, 0x50, 0x41, 0x53, 0x53, 0x57, 0x4f, 0x52, 0x44, 0x10, 0x04,
	0x12, 0x0c, 0x0a, 0x08, 0x41, 0x43, 0x54, 0x49, 0x56, 0x41, 0x54, 0x45, 0x10, 0x05, 0x12, 0x0e,
	0x0a, 0x0a, 0x44, 0x45, 0x41, 0x43, 0x54, 0x49, 0x56, 0x41, 0x54, 0x45, 0x10, 0x06, 0x12, 0x08,
	0x0a, 0x04, 0x4c, 0x4f, 0x43, 0x4b, 0x10, 0x07, 0x12, 0x0e, 0x0a, 0x0a, 0x49, 0x4e, 0x49, 0x54,
	0x49, 0x41, 0x4c, 0x49, 0x5a, 0x45, 0x10, 0x08, 0x42, 0x0a, 0x5a, 0x08, 0x73, 0x65, 0x63, 0x75,
	0x72, 0x69, 0x74, 0x79, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_account_proto_rawDescOnce sync.Once
	file_account_proto_rawDescData = file_account_proto_rawDesc
)

func file_account_proto_rawDescGZIP() []byte {
	file_account_proto_rawDescOnce.Do(func() {
		file_account_proto_rawDescData = protoimpl.X.CompressGZIP(file_account_proto_rawDescData)
	})
	return file_account_proto_rawDescData
}

var file_account_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_account_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_account_proto_goTypes = []interface{}{
	(Account_State)(0),  // 0: security.Account.State
	(Account_Action)(0), // 1: security.Account.Action
	(*Account)(nil),     // 2: security.Account
}
var file_account_proto_depIdxs = []int32{
	0, // 0: security.Account.state:type_name -> security.Account.State
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_account_proto_init() }
func file_account_proto_init() {
	if File_account_proto != nil {
		return
	}
	file_data_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_account_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Account); i {
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
			RawDescriptor: file_account_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_account_proto_goTypes,
		DependencyIndexes: file_account_proto_depIdxs,
		EnumInfos:         file_account_proto_enumTypes,
		MessageInfos:      file_account_proto_msgTypes,
	}.Build()
	File_account_proto = out.File
	file_account_proto_rawDesc = nil
	file_account_proto_goTypes = nil
	file_account_proto_depIdxs = nil
}
