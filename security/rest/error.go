package rest

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrNotFound     = errors.New("not found")
	ErrInvalid      = errors.New("invalid")
	ErrDuplicate    = errors.New("duplicate")
)

func Errored(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	switch ves := err.(type) {
	case ValidationErrors:
		w.WriteHeader(http.StatusBadRequest)
		b, _ := json.Marshal(ves)
		w.Write(b)
		return true
	}
	w.Header().Set("content-type", "text/plain")
	switch err {
	case ErrUnauthorized:
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(http.StatusText(http.StatusForbidden)))
	case ErrInvalid:
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(http.StatusText(http.StatusBadRequest)))
	case ErrNotFound:
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(http.StatusText(http.StatusNotFound)))
	default:
		switch err.Error() {
		case ErrDuplicate.Error():
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(http.StatusText(http.StatusBadRequest)))
		case ErrNotFound.Error():
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(http.StatusText(http.StatusNotFound)))
		default:
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			panic(err)
		}
	}
	return true
}
