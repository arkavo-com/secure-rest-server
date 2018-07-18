package rest

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"secure-rest-server/security"
)

type HeaderHandler struct {
	ServeMux *http.ServeMux
	Origin   string
}

func (h HeaderHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Verifying_Same_Origin_with_Standard_Headers
	if h.Origin != r.Header.Get("origin") {
		log.Println(r.Header.Get("origin"))
		log.Println(r.Header.Get("referer"))
	}
	w.Header().Add("access-control-allow-origin", h.Origin)
	w.Header().Add("access-control-allow-credentials", "true")
	w.Header().Add("content-type", "application/json")
	w.Header().Add("x-xss-protection", "1; mode=block")
	w.Header().Add("x-frame-options", "DENY")
	w.Header().Add("x-content-type-options", "DENY")
	w.Header().Add("content-security-policy", "default-src 'self'")
	if r.Method == "OPTIONS" {
		w.Header().Set("content-type", "text/plain")
		w.Header().Add("access-control-allow-headers", "content-type,origin,accept,referer,if-modified-since,x-csrf-token")
		w.Header().Add("access-control-allow-methods", "GET,PUT,POST,DELETE,OPTIONS")
		w.WriteHeader(http.StatusOK)
		return
	}
	m, _ := h.ServeMux.Handler(r)
	m.ServeHTTP(w, r)
}

// PathHandlerFunc supports single path parameter only /path/{parameter}
// calls http.HandleFunc with DefaultServeMux path
// reference https://www.reddit.com/r/golang/comments/3z10p1/create_dynamic_paths_in_httphandle_with_only/cyicw0t
func PathHandlerFunc(path string, f http.HandlerFunc) http.HandlerFunc {
	pattern := strings.Split(path, "{")
	pf := func(w http.ResponseWriter, r *http.Request) {
		if len(pattern) > 1 {
			r.Form = make(url.Values, 0)
			r.Form.Set(pattern[1][0:len(pattern[1])-1], r.RequestURI[len(pattern[0]):])
		}
		f(w, r)
	}
	http.HandleFunc(pattern[0], pf)
	return pf
}

// PasswordHandlerFunc request.Form must be initialized before
func PasswordHandlerFunc(accountReader security.AccountReader, f http.HandlerFunc) http.HandlerFunc {
	ep := func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil {
			return
		}
		ct := r.Header.Get("Content-Type")
		ct, _, _ = mime.ParseMediaType(ct)
		switch {
		case ct == "application/x-www-form-urlencoded":
			// limit to small form body only
			b, err := ioutil.ReadAll(io.LimitReader(r.Body, 1024))
			r.Body = nil
			if err != nil {
				break //return err
			}
			// p password
			pStart := bytes.Index(b, []byte{'p', '='})
			if pStart == -1 {
				// if no password, restore body
				r.Body = ioutil.NopCloser(bytes.NewReader(b))
				break //return ErrNoPassword
			}
			an := r.Form.Get("name")
			if err != nil {
				break //return err
			}
			ac, err := accountReader.ReadAccount(an)
			if err != nil {
				break //return err
			}
			// encrypt password
			h := hmac.New(sha256.New, []byte(ac.Salt))
			h.Write(b[pStart+2:]) // ??? url.QueryUnescape(string(p))
			pe := hex.EncodeToString(h.Sum(nil))
			for i := 0; i < len(b); i++ {
				b[i] = 0xFF
			}
			// new body reader
			r.Body = ioutil.NopCloser(strings.NewReader(fmt.Sprintf("p=%v", pe)))
			r.Form.Set("p", pe)
		}
		f(w, r)
	}
	return ep
}
