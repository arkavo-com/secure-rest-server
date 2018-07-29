// Code generated by protoc-gen-go. DO NOT EDIT.
// source: account.proto

package security

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Account_State int32

const (
	Account_nonstate Account_State = 0
	// Account_CREATE,Account_INITIALIZE
	Account_Initialized Account_State = 1
	// Account_ACTIVATE,Account_UPDATE_PASSWORD
	Account_Activated Account_State = 2
	// Account_LOCK
	Account_Locked Account_State = 3
	// Account_DEACTIVATE
	Account_Deactivated Account_State = 4
)

var Account_State_name = map[int32]string{
	0: "nonstate",
	1: "Initialized",
	2: "Activated",
	3: "Locked",
	4: "Deactivated",
}
var Account_State_value = map[string]int32{
	"nonstate":    0,
	"Initialized": 1,
	"Activated":   2,
	"Locked":      3,
	"Deactivated": 4,
}

func (x Account_State) String() string {
	return proto.EnumName(Account_State_name, int32(x))
}
func (Account_State) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_account_6c4246d0d4ffb6ac, []int{0, 0}
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

var Account_Action_name = map[int32]string{
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
var Account_Action_value = map[string]int32{
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

func (x Account_Action) String() string {
	return proto.EnumName(Account_Action_name, int32(x))
}
func (Account_Action) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_account_6c4246d0d4ffb6ac, []int{0, 1}
}

// A system account to allow access for a subject
type Account struct {
	// unique name
	Name string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
	// `json:"-"`
	Salt string `protobuf:"bytes,2,opt,name=salt" json:"-"`
	// `json:"-"`
	Hash  string        `protobuf:"bytes,3,opt,name=hash" json:"-"`
	State Account_State `protobuf:"varint,4,opt,name=state,enum=Account_State" json:"state,omitempty"`
	// []role.proto:Role.name
	Roles                []string `protobuf:"bytes,5,rep,name=roles" json:"roles,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-" bson:"-"`
	XXX_unrecognized     []byte   `json:"-" bson:"-"`
	XXX_sizecache        int32    `json:"-" bson:"-"`
}

func (m *Account) Reset()         { *m = Account{} }
func (m *Account) String() string { return proto.CompactTextString(m) }
func (*Account) ProtoMessage()    {}
func (*Account) Descriptor() ([]byte, []int) {
	return fileDescriptor_account_6c4246d0d4ffb6ac, []int{0}
}
func (m *Account) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Account.Unmarshal(m, b)
}
func (m *Account) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Account.Marshal(b, m, deterministic)
}
func (dst *Account) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Account.Merge(dst, src)
}
func (m *Account) XXX_Size() int {
	return xxx_messageInfo_Account.Size(m)
}
func (m *Account) XXX_DiscardUnknown() {
	xxx_messageInfo_Account.DiscardUnknown(m)
}

var xxx_messageInfo_Account proto.InternalMessageInfo

func (m *Account) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Account) GetSalt() string {
	if m != nil {
		return m.Salt
	}
	return ""
}

func (m *Account) GetHash() string {
	if m != nil {
		return m.Hash
	}
	return ""
}

func (m *Account) GetState() Account_State {
	if m != nil {
		return m.State
	}
	return Account_nonstate
}

func (m *Account) GetRoles() []string {
	if m != nil {
		return m.Roles
	}
	return nil
}

func init() {
	proto.RegisterType((*Account)(nil), "Account")
	proto.RegisterEnum("Account_State", Account_State_name, Account_State_value)
	proto.RegisterEnum("Account_Action", Account_Action_name, Account_Action_value)
}

func init() { proto.RegisterFile("account.proto", fileDescriptor_account_6c4246d0d4ffb6ac) }

var fileDescriptor_account_6c4246d0d4ffb6ac = []byte{
	// 300 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x3c, 0x90, 0xcf, 0x4e, 0x32, 0x31,
	0x14, 0xc5, 0x19, 0xe6, 0x0f, 0xc3, 0xfd, 0x3e, 0xa0, 0xa9, 0x2e, 0x66, 0x49, 0x88, 0x0b, 0x56,
	0x2c, 0xf4, 0x09, 0x2a, 0xed, 0xa2, 0x71, 0x22, 0xa4, 0x8c, 0x9a, 0xb0, 0x31, 0x75, 0x68, 0xc2,
	0x44, 0x6c, 0x0d, 0x53, 0x4c, 0x74, 0xeb, 0x63, 0xfa, 0x32, 0xe6, 0x4e, 0x0d, 0xbb, 0x73, 0x7f,
	0xe7, 0x97, 0x93, 0xa6, 0x30, 0xd2, 0x75, 0xed, 0x4e, 0xd6, 0x2f, 0xde, 0x8f, 0xce, 0xbb, 0xd9,
	0x4f, 0x1f, 0x06, 0x2c, 0x10, 0x4a, 0x21, 0xb1, 0xfa, 0xcd, 0x14, 0xd1, 0x34, 0x9a, 0x0f, 0x55,
	0x97, 0x91, 0xb5, 0xfa, 0xe0, 0x8b, 0x7e, 0x60, 0x98, 0x91, 0xed, 0x75, 0xbb, 0x2f, 0xe2, 0xc0,
	0x30, 0xd3, 0x2b, 0x48, 0x5b, 0xaf, 0xbd, 0x29, 0x92, 0x69, 0x34, 0x1f, 0x5f, 0x8f, 0x17, 0x7f,
	0xa3, 0x8b, 0x0d, 0x52, 0x15, 0x4a, 0x7a, 0x09, 0xe9, 0xd1, 0x1d, 0x4c, 0x5b, 0xa4, 0xd3, 0x78,
	0x3e, 0x54, 0xe1, 0x98, 0x29, 0x48, 0x3b, 0x8b, 0xfe, 0x87, 0xdc, 0x3a, 0xdb, 0xa9, 0xa4, 0x47,
	0x27, 0xf0, 0x4f, 0xda, 0xc6, 0x37, 0xfa, 0xd0, 0x7c, 0x99, 0x1d, 0x89, 0xe8, 0x08, 0x86, 0xac,
	0xf6, 0xcd, 0x87, 0xf6, 0x66, 0x47, 0xfa, 0x14, 0x20, 0x2b, 0x5d, 0xfd, 0x6a, 0x76, 0x24, 0x46,
	0x97, 0x1b, 0x7d, 0x2e, 0x93, 0xd9, 0x77, 0x04, 0x19, 0xca, 0xce, 0xa2, 0xb7, 0x54, 0x82, 0x55,
	0x82, 0xf4, 0x68, 0x0e, 0x89, 0x12, 0x8c, 0x93, 0x08, 0xe9, 0xc3, 0x9a, 0x23, 0xed, 0x96, 0xb8,
	0x28, 0x45, 0x25, 0x48, 0x4c, 0x2f, 0x60, 0x12, 0xf8, 0xf3, 0x9a, 0x6d, 0x36, 0x4f, 0x2b, 0xc5,
	0x49, 0x82, 0x0f, 0x63, 0xcb, 0x4a, 0x3e, 0xa2, 0x9e, 0xd2, 0x31, 0x00, 0x17, 0xe7, 0x3b, 0xc3,
	0xd1, 0x72, 0xb5, 0xbc, 0x23, 0x03, 0x6c, 0xe4, 0xbd, 0xac, 0x24, 0x2b, 0xe5, 0x56, 0x90, 0xfc,
	0x16, 0xb6, 0x79, 0x6b, 0xea, 0xd3, 0xb1, 0xf1, 0x9f, 0x2f, 0x59, 0xf7, 0xe1, 0x37, 0xbf, 0x01,
	0x00, 0x00, 0xff, 0xff, 0xfd, 0xd5, 0xe7, 0x5d, 0x81, 0x01, 0x00, 0x00,
}
