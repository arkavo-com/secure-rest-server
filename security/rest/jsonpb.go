package rest

import (
	"net/http"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
)

// WriteProtos jsonpb marshal many protos
func WriteProtos(w http.ResponseWriter, pbs []proto.Message) {
	marshaller := jsonpb.Marshaler{}
	var err error
	w.Write([]byte("["))
	length := len(pbs)
	for index, pb := range pbs {
		err = marshaller.Marshal(w, pb)
		if index < length-1 {
			w.Write([]byte(","))
		}
	}
	if err == nil {
		w.Write([]byte("]"))
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}
}

// WriteProto jsonpb marshal a proto
func WriteProto(w http.ResponseWriter, pb proto.Message) {
	marshaller := jsonpb.Marshaler{}
	err := marshaller.Marshal(w, pb)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}
}

// WriteProtoCreated sets 201 and Location header
func WriteProtoCreated(w http.ResponseWriter, pb proto.Message, location string) {
	w.Header().Add("location", location)
	w.WriteHeader(http.StatusCreated)
	marshaller := jsonpb.Marshaler{}
	err := marshaller.Marshal(w, pb)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}
}
