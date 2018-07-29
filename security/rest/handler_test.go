package rest

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPathHandlerFunc(t *testing.T) {
	path := "/path/to/test/{id}"
	r := http.Request{
		URL: &url.URL{
			Path: "/path/to/test/abc123",
		},
		RequestURI: "/path/to/test/abc123",
	}
	w := testHTTPWriter{
		h: http.Header{},
	}
	PathHandlerFunc(path, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "abc123", r.Form.Get("id"))
	})
	http.DefaultServeMux.ServeHTTP(w, &r)
}

func TestPathHandlerFuncNo(t *testing.T) {
	path := "/path/to/test0"
	r := http.Request{
		URL: &url.URL{
			Path: "/path/to/test0",
		},
		RequestURI: "/path/to/test0",
	}
	w := testHTTPWriter{
		h: http.Header{},
	}
	PathHandlerFunc(path, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "", r.Form.Get("id"))
	})
	http.DefaultServeMux.ServeHTTP(w, &r)
}

//// not supported
//func TestPathHandlerFuncMiddle(t *testing.T) {
//	path := "/path/to/test1/{id}/action"
//	r := http.Request{
//		URL: &url.URL{
//			Path: "/path/to/test1/abc123/action",
//		},
//		RequestURI: "/path/to/test1/abc123/action",
//	}
//	w := testHttpWriter{
//		h: http.Header{},
//	}
//	PathHandlerFunc(path, func(w http.ResponseWriter, r *http.Request) {
//		t.Log(path)
//		assert.Equal(t, "abc123", r.Form.Get("id"))
//	})
//	http.DefaultServeMux.ServeHTTP(w, &r)
//}
//
//// not supported
//func TestPathHandlerFuncTwo(t *testing.T) {
//	path := "/path/to/test2/{id}/action/{aid}"
//	r := http.Request{
//		URL: &url.URL{
//			Path: "/path/to/test2/abc123/action/xyz890",
//		},
//		RequestURI: "/path/to/test2/abc123/action/xyz890",
//	}
//	w := testHttpWriter{
//		h: http.Header{},
//	}
//	PathHandlerFunc(path, func(w http.ResponseWriter, r *http.Request) {
//		t.Log(path)
//		assert.Equal(t, "abc123", r.Form.Get("id"))
//		assert.Equal(t, "xyz890", r.Form.Get("aid"))
//	})
//	http.DefaultServeMux.ServeHTTP(w, &r)
//}
