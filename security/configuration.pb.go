// Code generated by protoc-gen-go. DO NOT EDIT.
// source: configuration.proto

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

type Configuration struct {
	Account              *Configuration_Account    `protobuf:"bytes,1,opt,name=account" json:"account,omitempty"`
	Permission           *Configuration_Permission `protobuf:"bytes,2,opt,name=permission" json:"permission,omitempty"`
	Policy               *Configuration_Policy     `protobuf:"bytes,3,opt,name=policy" json:"policy,omitempty"`
	Role                 *Configuration_Role       `protobuf:"bytes,4,opt,name=role" json:"role,omitempty"`
	Session              *Configuration_Session    `protobuf:"bytes,5,opt,name=session" json:"session,omitempty"`
	Server               *Configuration_Server     `protobuf:"bytes,6,opt,name=server" json:"server,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                  `json:"-" bson:"-"`
	XXX_unrecognized     []byte                    `json:"-" bson:"-"`
	XXX_sizecache        int32                     `json:"-" bson:"-"`
}

func (m *Configuration) Reset()         { *m = Configuration{} }
func (m *Configuration) String() string { return proto.CompactTextString(m) }
func (*Configuration) ProtoMessage()    {}
func (*Configuration) Descriptor() ([]byte, []int) {
	return fileDescriptor_configuration_f690adfb4bc02ffb, []int{0}
}
func (m *Configuration) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Configuration.Unmarshal(m, b)
}
func (m *Configuration) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Configuration.Marshal(b, m, deterministic)
}
func (dst *Configuration) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Configuration.Merge(dst, src)
}
func (m *Configuration) XXX_Size() int {
	return xxx_messageInfo_Configuration.Size(m)
}
func (m *Configuration) XXX_DiscardUnknown() {
	xxx_messageInfo_Configuration.DiscardUnknown(m)
}

var xxx_messageInfo_Configuration proto.InternalMessageInfo

func (m *Configuration) GetAccount() *Configuration_Account {
	if m != nil {
		return m.Account
	}
	return nil
}

func (m *Configuration) GetPermission() *Configuration_Permission {
	if m != nil {
		return m.Permission
	}
	return nil
}

func (m *Configuration) GetPolicy() *Configuration_Policy {
	if m != nil {
		return m.Policy
	}
	return nil
}

func (m *Configuration) GetRole() *Configuration_Role {
	if m != nil {
		return m.Role
	}
	return nil
}

func (m *Configuration) GetSession() *Configuration_Session {
	if m != nil {
		return m.Session
	}
	return nil
}

func (m *Configuration) GetServer() *Configuration_Server {
	if m != nil {
		return m.Server
	}
	return nil
}

type Configuration_Account struct {
	Store                *Configuration_Store `protobuf:"bytes,1,opt,name=store" json:"store,omitempty"`
	XXX_NoUnkeyedLiteral struct{}             `json:"-" bson:"-"`
	XXX_unrecognized     []byte               `json:"-" bson:"-"`
	XXX_sizecache        int32                `json:"-" bson:"-"`
}

func (m *Configuration_Account) Reset()         { *m = Configuration_Account{} }
func (m *Configuration_Account) String() string { return proto.CompactTextString(m) }
func (*Configuration_Account) ProtoMessage()    {}
func (*Configuration_Account) Descriptor() ([]byte, []int) {
	return fileDescriptor_configuration_f690adfb4bc02ffb, []int{0, 0}
}
func (m *Configuration_Account) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Configuration_Account.Unmarshal(m, b)
}
func (m *Configuration_Account) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Configuration_Account.Marshal(b, m, deterministic)
}
func (dst *Configuration_Account) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Configuration_Account.Merge(dst, src)
}
func (m *Configuration_Account) XXX_Size() int {
	return xxx_messageInfo_Configuration_Account.Size(m)
}
func (m *Configuration_Account) XXX_DiscardUnknown() {
	xxx_messageInfo_Configuration_Account.DiscardUnknown(m)
}

var xxx_messageInfo_Configuration_Account proto.InternalMessageInfo

func (m *Configuration_Account) GetStore() *Configuration_Store {
	if m != nil {
		return m.Store
	}
	return nil
}

type Configuration_Permission struct {
	Store                *Configuration_Store `protobuf:"bytes,1,opt,name=store" json:"store,omitempty"`
	XXX_NoUnkeyedLiteral struct{}             `json:"-" bson:"-"`
	XXX_unrecognized     []byte               `json:"-" bson:"-"`
	XXX_sizecache        int32                `json:"-" bson:"-"`
}

func (m *Configuration_Permission) Reset()         { *m = Configuration_Permission{} }
func (m *Configuration_Permission) String() string { return proto.CompactTextString(m) }
func (*Configuration_Permission) ProtoMessage()    {}
func (*Configuration_Permission) Descriptor() ([]byte, []int) {
	return fileDescriptor_configuration_f690adfb4bc02ffb, []int{0, 1}
}
func (m *Configuration_Permission) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Configuration_Permission.Unmarshal(m, b)
}
func (m *Configuration_Permission) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Configuration_Permission.Marshal(b, m, deterministic)
}
func (dst *Configuration_Permission) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Configuration_Permission.Merge(dst, src)
}
func (m *Configuration_Permission) XXX_Size() int {
	return xxx_messageInfo_Configuration_Permission.Size(m)
}
func (m *Configuration_Permission) XXX_DiscardUnknown() {
	xxx_messageInfo_Configuration_Permission.DiscardUnknown(m)
}

var xxx_messageInfo_Configuration_Permission proto.InternalMessageInfo

func (m *Configuration_Permission) GetStore() *Configuration_Store {
	if m != nil {
		return m.Store
	}
	return nil
}

type Configuration_Policy struct {
	Store                *Configuration_Store `protobuf:"bytes,1,opt,name=store" json:"store,omitempty"`
	XXX_NoUnkeyedLiteral struct{}             `json:"-" bson:"-"`
	XXX_unrecognized     []byte               `json:"-" bson:"-"`
	XXX_sizecache        int32                `json:"-" bson:"-"`
}

func (m *Configuration_Policy) Reset()         { *m = Configuration_Policy{} }
func (m *Configuration_Policy) String() string { return proto.CompactTextString(m) }
func (*Configuration_Policy) ProtoMessage()    {}
func (*Configuration_Policy) Descriptor() ([]byte, []int) {
	return fileDescriptor_configuration_f690adfb4bc02ffb, []int{0, 2}
}
func (m *Configuration_Policy) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Configuration_Policy.Unmarshal(m, b)
}
func (m *Configuration_Policy) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Configuration_Policy.Marshal(b, m, deterministic)
}
func (dst *Configuration_Policy) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Configuration_Policy.Merge(dst, src)
}
func (m *Configuration_Policy) XXX_Size() int {
	return xxx_messageInfo_Configuration_Policy.Size(m)
}
func (m *Configuration_Policy) XXX_DiscardUnknown() {
	xxx_messageInfo_Configuration_Policy.DiscardUnknown(m)
}

var xxx_messageInfo_Configuration_Policy proto.InternalMessageInfo

func (m *Configuration_Policy) GetStore() *Configuration_Store {
	if m != nil {
		return m.Store
	}
	return nil
}

type Configuration_Role struct {
	Store                *Configuration_Store `protobuf:"bytes,1,opt,name=store" json:"store,omitempty"`
	XXX_NoUnkeyedLiteral struct{}             `json:"-" bson:"-"`
	XXX_unrecognized     []byte               `json:"-" bson:"-"`
	XXX_sizecache        int32                `json:"-" bson:"-"`
}

func (m *Configuration_Role) Reset()         { *m = Configuration_Role{} }
func (m *Configuration_Role) String() string { return proto.CompactTextString(m) }
func (*Configuration_Role) ProtoMessage()    {}
func (*Configuration_Role) Descriptor() ([]byte, []int) {
	return fileDescriptor_configuration_f690adfb4bc02ffb, []int{0, 3}
}
func (m *Configuration_Role) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Configuration_Role.Unmarshal(m, b)
}
func (m *Configuration_Role) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Configuration_Role.Marshal(b, m, deterministic)
}
func (dst *Configuration_Role) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Configuration_Role.Merge(dst, src)
}
func (m *Configuration_Role) XXX_Size() int {
	return xxx_messageInfo_Configuration_Role.Size(m)
}
func (m *Configuration_Role) XXX_DiscardUnknown() {
	xxx_messageInfo_Configuration_Role.DiscardUnknown(m)
}

var xxx_messageInfo_Configuration_Role proto.InternalMessageInfo

func (m *Configuration_Role) GetStore() *Configuration_Store {
	if m != nil {
		return m.Store
	}
	return nil
}

type Configuration_Session struct {
	Store                *Configuration_Store `protobuf:"bytes,1,opt,name=store" json:"store,omitempty"`
	XXX_NoUnkeyedLiteral struct{}             `json:"-" bson:"-"`
	XXX_unrecognized     []byte               `json:"-" bson:"-"`
	XXX_sizecache        int32                `json:"-" bson:"-"`
}

func (m *Configuration_Session) Reset()         { *m = Configuration_Session{} }
func (m *Configuration_Session) String() string { return proto.CompactTextString(m) }
func (*Configuration_Session) ProtoMessage()    {}
func (*Configuration_Session) Descriptor() ([]byte, []int) {
	return fileDescriptor_configuration_f690adfb4bc02ffb, []int{0, 4}
}
func (m *Configuration_Session) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Configuration_Session.Unmarshal(m, b)
}
func (m *Configuration_Session) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Configuration_Session.Marshal(b, m, deterministic)
}
func (dst *Configuration_Session) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Configuration_Session.Merge(dst, src)
}
func (m *Configuration_Session) XXX_Size() int {
	return xxx_messageInfo_Configuration_Session.Size(m)
}
func (m *Configuration_Session) XXX_DiscardUnknown() {
	xxx_messageInfo_Configuration_Session.DiscardUnknown(m)
}

var xxx_messageInfo_Configuration_Session proto.InternalMessageInfo

func (m *Configuration_Session) GetStore() *Configuration_Store {
	if m != nil {
		return m.Store
	}
	return nil
}

type Configuration_Server struct {
	Address              string   `protobuf:"bytes,1,opt,name=address" json:"address,omitempty"`
	Certificate          string   `protobuf:"bytes,2,opt,name=certificate" json:"certificate,omitempty"`
	Key                  string   `protobuf:"bytes,3,opt,name=key" json:"key,omitempty"`
	Origin               string   `protobuf:"bytes,4,opt,name=origin" json:"origin,omitempty"`
	Host                 string   `protobuf:"bytes,5,opt,name=host" json:"host,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-" bson:"-"`
	XXX_unrecognized     []byte   `json:"-" bson:"-"`
	XXX_sizecache        int32    `json:"-" bson:"-"`
}

func (m *Configuration_Server) Reset()         { *m = Configuration_Server{} }
func (m *Configuration_Server) String() string { return proto.CompactTextString(m) }
func (*Configuration_Server) ProtoMessage()    {}
func (*Configuration_Server) Descriptor() ([]byte, []int) {
	return fileDescriptor_configuration_f690adfb4bc02ffb, []int{0, 5}
}
func (m *Configuration_Server) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Configuration_Server.Unmarshal(m, b)
}
func (m *Configuration_Server) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Configuration_Server.Marshal(b, m, deterministic)
}
func (dst *Configuration_Server) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Configuration_Server.Merge(dst, src)
}
func (m *Configuration_Server) XXX_Size() int {
	return xxx_messageInfo_Configuration_Server.Size(m)
}
func (m *Configuration_Server) XXX_DiscardUnknown() {
	xxx_messageInfo_Configuration_Server.DiscardUnknown(m)
}

var xxx_messageInfo_Configuration_Server proto.InternalMessageInfo

func (m *Configuration_Server) GetAddress() string {
	if m != nil {
		return m.Address
	}
	return ""
}

func (m *Configuration_Server) GetCertificate() string {
	if m != nil {
		return m.Certificate
	}
	return ""
}

func (m *Configuration_Server) GetKey() string {
	if m != nil {
		return m.Key
	}
	return ""
}

func (m *Configuration_Server) GetOrigin() string {
	if m != nil {
		return m.Origin
	}
	return ""
}

func (m *Configuration_Server) GetHost() string {
	if m != nil {
		return m.Host
	}
	return ""
}

type Configuration_Store struct {
	Url                  string                     `protobuf:"bytes,1,opt,name=url" json:"url,omitempty"`
	Redis                *Configuration_Store_Redis `protobuf:"bytes,2,opt,name=redis" json:"redis,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                   `json:"-" bson:"-"`
	XXX_unrecognized     []byte                     `json:"-" bson:"-"`
	XXX_sizecache        int32                      `json:"-" bson:"-"`
}

func (m *Configuration_Store) Reset()         { *m = Configuration_Store{} }
func (m *Configuration_Store) String() string { return proto.CompactTextString(m) }
func (*Configuration_Store) ProtoMessage()    {}
func (*Configuration_Store) Descriptor() ([]byte, []int) {
	return fileDescriptor_configuration_f690adfb4bc02ffb, []int{0, 6}
}
func (m *Configuration_Store) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Configuration_Store.Unmarshal(m, b)
}
func (m *Configuration_Store) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Configuration_Store.Marshal(b, m, deterministic)
}
func (dst *Configuration_Store) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Configuration_Store.Merge(dst, src)
}
func (m *Configuration_Store) XXX_Size() int {
	return xxx_messageInfo_Configuration_Store.Size(m)
}
func (m *Configuration_Store) XXX_DiscardUnknown() {
	xxx_messageInfo_Configuration_Store.DiscardUnknown(m)
}

var xxx_messageInfo_Configuration_Store proto.InternalMessageInfo

func (m *Configuration_Store) GetUrl() string {
	if m != nil {
		return m.Url
	}
	return ""
}

func (m *Configuration_Store) GetRedis() *Configuration_Store_Redis {
	if m != nil {
		return m.Redis
	}
	return nil
}

type Configuration_Store_Redis struct {
	Network              string   `protobuf:"bytes,1,opt,name=network" json:"network,omitempty"`
	Address              string   `protobuf:"bytes,2,opt,name=address" json:"address,omitempty"`
	ReadTimeout          string   `protobuf:"bytes,3,opt,name=readTimeout" json:"readTimeout,omitempty"`
	WriteTimeout         string   `protobuf:"bytes,4,opt,name=writeTimeout" json:"writeTimeout,omitempty"`
	Database             int32    `protobuf:"varint,5,opt,name=database" json:"database,omitempty"`
	Password             string   `protobuf:"bytes,6,opt,name=password" json:"password,omitempty"`
	Tls                  bool     `protobuf:"varint,7,opt,name=tls" json:"tls,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-" bson:"-"`
	XXX_unrecognized     []byte   `json:"-" bson:"-"`
	XXX_sizecache        int32    `json:"-" bson:"-"`
}

func (m *Configuration_Store_Redis) Reset()         { *m = Configuration_Store_Redis{} }
func (m *Configuration_Store_Redis) String() string { return proto.CompactTextString(m) }
func (*Configuration_Store_Redis) ProtoMessage()    {}
func (*Configuration_Store_Redis) Descriptor() ([]byte, []int) {
	return fileDescriptor_configuration_f690adfb4bc02ffb, []int{0, 6, 0}
}
func (m *Configuration_Store_Redis) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Configuration_Store_Redis.Unmarshal(m, b)
}
func (m *Configuration_Store_Redis) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Configuration_Store_Redis.Marshal(b, m, deterministic)
}
func (dst *Configuration_Store_Redis) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Configuration_Store_Redis.Merge(dst, src)
}
func (m *Configuration_Store_Redis) XXX_Size() int {
	return xxx_messageInfo_Configuration_Store_Redis.Size(m)
}
func (m *Configuration_Store_Redis) XXX_DiscardUnknown() {
	xxx_messageInfo_Configuration_Store_Redis.DiscardUnknown(m)
}

var xxx_messageInfo_Configuration_Store_Redis proto.InternalMessageInfo

func (m *Configuration_Store_Redis) GetNetwork() string {
	if m != nil {
		return m.Network
	}
	return ""
}

func (m *Configuration_Store_Redis) GetAddress() string {
	if m != nil {
		return m.Address
	}
	return ""
}

func (m *Configuration_Store_Redis) GetReadTimeout() string {
	if m != nil {
		return m.ReadTimeout
	}
	return ""
}

func (m *Configuration_Store_Redis) GetWriteTimeout() string {
	if m != nil {
		return m.WriteTimeout
	}
	return ""
}

func (m *Configuration_Store_Redis) GetDatabase() int32 {
	if m != nil {
		return m.Database
	}
	return 0
}

func (m *Configuration_Store_Redis) GetPassword() string {
	if m != nil {
		return m.Password
	}
	return ""
}

func (m *Configuration_Store_Redis) GetTls() bool {
	if m != nil {
		return m.Tls
	}
	return false
}

func init() {
	proto.RegisterType((*Configuration)(nil), "Configuration")
	proto.RegisterType((*Configuration_Account)(nil), "Configuration.Account")
	proto.RegisterType((*Configuration_Permission)(nil), "Configuration.Permission")
	proto.RegisterType((*Configuration_Policy)(nil), "Configuration.Policy")
	proto.RegisterType((*Configuration_Role)(nil), "Configuration.Role")
	proto.RegisterType((*Configuration_Session)(nil), "Configuration.Session")
	proto.RegisterType((*Configuration_Server)(nil), "Configuration.Server")
	proto.RegisterType((*Configuration_Store)(nil), "Configuration.Store")
	proto.RegisterType((*Configuration_Store_Redis)(nil), "Configuration.Store.Redis")
}

func init() { proto.RegisterFile("configuration.proto", fileDescriptor_configuration_f690adfb4bc02ffb) }

var fileDescriptor_configuration_f690adfb4bc02ffb = []byte{
	// 445 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x93, 0xcd, 0x6e, 0xd3, 0x40,
	0x10, 0xc7, 0xe5, 0x34, 0xb6, 0xe3, 0x29, 0x48, 0x68, 0x0b, 0x95, 0xf1, 0x29, 0xea, 0x85, 0x0a,
	0x89, 0xa8, 0x2a, 0x54, 0x82, 0x23, 0xf0, 0x02, 0x68, 0xca, 0x89, 0xdb, 0xd6, 0x9e, 0x96, 0x55,
	0x5d, 0x6f, 0x34, 0xbb, 0x26, 0xea, 0x95, 0xb7, 0xe0, 0x99, 0x78, 0x11, 0x1e, 0x03, 0xed, 0x87,
	0x83, 0x13, 0x72, 0xf1, 0x6d, 0x3e, 0x7e, 0xff, 0x64, 0xfe, 0xb3, 0x63, 0x38, 0xa9, 0x75, 0x77,
	0xab, 0xee, 0x7a, 0x96, 0x56, 0xe9, 0x6e, 0xb5, 0x66, 0x6d, 0xf5, 0xd9, 0x9f, 0x1c, 0x9e, 0x7e,
	0x1e, 0xd7, 0xc5, 0x05, 0xe4, 0xb2, 0xae, 0x75, 0xdf, 0xd9, 0x32, 0x59, 0x26, 0xe7, 0xc7, 0x97,
	0xa7, 0xab, 0x1d, 0x60, 0xf5, 0x31, 0x74, 0x71, 0xc0, 0xc4, 0x07, 0x80, 0x35, 0xf1, 0x83, 0x32,
	0x46, 0xe9, 0xae, 0x9c, 0x79, 0xd1, 0xcb, 0x3d, 0xd1, 0x97, 0x2d, 0x80, 0x23, 0x58, 0xbc, 0x81,
	0x6c, 0xad, 0x5b, 0x55, 0x3f, 0x96, 0x47, 0x5e, 0xf6, 0x62, 0x5f, 0xe6, 0x9b, 0x18, 0x21, 0xf1,
	0x0a, 0xe6, 0xac, 0x5b, 0x2a, 0xe7, 0x1e, 0x3e, 0xd9, 0x83, 0x51, 0xb7, 0x84, 0x1e, 0x70, 0x26,
	0x0c, 0x85, 0x79, 0xd2, 0x83, 0x26, 0xae, 0x43, 0x17, 0x07, 0xcc, 0x4d, 0x62, 0x88, 0x7f, 0x10,
	0x97, 0xd9, 0xc1, 0x49, 0xae, 0x7d, 0x13, 0x23, 0x54, 0x5d, 0x41, 0x1e, 0xf7, 0x20, 0x5e, 0x43,
	0x6a, 0xac, 0x66, 0x8a, 0xeb, 0x7a, 0xbe, 0x2f, 0x74, 0x3d, 0x0c, 0x48, 0xf5, 0x1e, 0xe0, 0xdf,
	0x26, 0x26, 0x29, 0xdf, 0x41, 0x16, 0x96, 0x31, 0x49, 0x75, 0x09, 0x73, 0xb7, 0x95, 0x49, 0x9a,
	0x2b, 0xc8, 0xe3, 0x76, 0x26, 0xc9, 0x7e, 0x26, 0x90, 0x85, 0x25, 0x89, 0x12, 0x72, 0xd9, 0x34,
	0x4c, 0xc6, 0x78, 0x61, 0x81, 0x43, 0x2a, 0x96, 0x70, 0x5c, 0x13, 0x5b, 0x75, 0xab, 0x6a, 0x69,
	0xc9, 0xdf, 0x4a, 0x81, 0xe3, 0x92, 0x78, 0x06, 0x47, 0xf7, 0x14, 0xce, 0xa1, 0x40, 0x17, 0x8a,
	0x53, 0xc8, 0x34, 0xab, 0x3b, 0xd5, 0xf9, 0x67, 0x2f, 0x30, 0x66, 0x42, 0xc0, 0xfc, 0xbb, 0x36,
	0xd6, 0x3f, 0x70, 0x81, 0x3e, 0xae, 0x7e, 0xcd, 0x20, 0xf5, 0x53, 0xb9, 0xdf, 0xe9, 0xb9, 0x8d,
	0xff, 0xef, 0x42, 0x71, 0x01, 0x29, 0x53, 0xa3, 0x4c, 0xbc, 0xd0, 0xea, 0x90, 0x99, 0x15, 0x3a,
	0x02, 0x03, 0x58, 0xfd, 0x4e, 0x20, 0xf5, 0x05, 0xe7, 0xa8, 0x23, 0xbb, 0xd1, 0x7c, 0x3f, 0x38,
	0x8a, 0xe9, 0xd8, 0xeb, 0xec, 0x3f, 0xaf, 0x4c, 0xb2, 0xf9, 0xaa, 0x1e, 0x48, 0xf7, 0x36, 0x3a,
	0x1a, 0x97, 0xc4, 0x19, 0x3c, 0xd9, 0xb0, 0xb2, 0x34, 0x20, 0xc1, 0xdf, 0x4e, 0x4d, 0x54, 0xb0,
	0x68, 0xa4, 0x95, 0x37, 0xd2, 0x90, 0x77, 0x9a, 0xe2, 0x36, 0x77, 0xbd, 0xb5, 0x34, 0x66, 0xa3,
	0xb9, 0xf1, 0x57, 0x5b, 0xe0, 0x36, 0x77, 0xfe, 0x6d, 0x6b, 0xca, 0x7c, 0x99, 0x9c, 0x2f, 0xd0,
	0x85, 0x9f, 0xe0, 0xdb, 0xc2, 0x50, 0xdd, 0xb3, 0xb2, 0x8f, 0x37, 0x99, 0xff, 0xfa, 0xdf, 0xfe,
	0x0d, 0x00, 0x00, 0xff, 0xff, 0x24, 0xe1, 0xb8, 0x45, 0x14, 0x04, 0x00, 0x00,
}
