package rest

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
)

var (
	// ErrUnauthorized unauthorized error
	ErrUnauthorized = errors.New(http.StatusText(http.StatusForbidden))
	// ErrNotFound not found error
	ErrNotFound = errors.New(http.StatusText(http.StatusNotFound))
	// ErrInvalid invalid error
	ErrInvalid = errors.New("invalid")
	// ErrDuplicate duplicate error
	ErrDuplicate = errors.New("duplicate")
	// ErrMethodNotAllowed HTTP method not allowed
	ErrMethodNotAllowed = errors.New(http.StatusText(http.StatusMethodNotAllowed))
)

// Errored writes errors to the HTTP response writer
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
	case ErrMethodNotAllowed:
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte(http.StatusText(http.StatusMethodNotAllowed)))
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
			//panic(err)
		}
	}
	return true
}
