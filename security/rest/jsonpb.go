package rest

import (
	"net/http"

	"github.com/arkavo-com/secure-rest-server/security"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

// WriteProtos marshal many protos
func WriteProtos(w http.ResponseWriter, pbs []proto.Message) {
	var err error
	_, _ = w.Write([]byte("["))
	length := len(pbs)
	for index, pb := range pbs {
		Redact(pb)
		var b []byte
		b, err = protojson.Marshal(pb)
		if err != nil {
			break
		}
		_, _ = w.Write(b)
		if index < length-1 {
			_, _ = w.Write([]byte(","))
		}
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
	}
	_, _ = w.Write([]byte("]"))
}

// WriteProto jsonpb marshal a proto
func WriteProto(w http.ResponseWriter, pb proto.Message) {
	Redact(pb)
	b, err := protojson.Marshal(pb)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
	}
	_, _ = w.Write(b)
}

// WriteProtoCreated sets 201 and Location header
func WriteProtoCreated(w http.ResponseWriter, pb proto.Message, location string) {
	Redact(pb)
	w.Header().Add("location", location)
	w.WriteHeader(http.StatusCreated)
	b, err := protojson.Marshal(pb)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
	}
	_, _ = w.Write(b)
}

// Redact clears every sensitive field in pb.
func Redact(pb proto.Message) {
	m := pb.ProtoReflect()
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		opts := fd.Options().(*descriptorpb.FieldOptions)
		if proto.GetExtension(opts, security.E_Sensitive).(bool) {
			m.Clear(fd)
			return true
		}
		return true
	})
}
