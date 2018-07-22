package account

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"secure-rest-server/security"

	"github.com/go-openapi/spec"
)

var paths spec.Paths

func init() {
	paths.Paths = make(map[string]spec.PathItem)
	RegisterHttpHandler(paths, nil)
}

func TestRegisterHttpHandler(t *testing.T) {
	if len(paths.Paths) != 3 {
		t.Error(len(paths.Paths))
	}
	if paths.Paths["/account"].Get != accountREADAll {
		t.Error()
	}
}

func Test_serveHTTPRead(t *testing.T) {
	ps := []*security.Permission{
		{
			Class:   "Account",
			Actions: []string{"READ"},
		},
	}
	r := httptest.NewRequest("GET", "/account", nil)
	r = r.WithContext(context.WithValue(r.Context(), "session.context", &security.Session{
		Permissions: ps,
	}))
	type args struct {
		w *httptest.ResponseRecorder
		r *http.Request
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{"read account forbidden", args{
			httptest.NewRecorder(),
			httptest.NewRequest("GET", "/account", nil),
		}, 403},
		{"read account no accounts", args{
			httptest.NewRecorder(),
			r,
		}, 404},
		{"read account", args{
			httptest.NewRecorder(),
			r,
		}, 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.want == 200 {
				RegisterStoreProviderMemdb()
			}
			serveHTTP(tt.args.w, tt.args.r)
			if tt.args.w.Code != tt.want {
				t.Errorf("status code = %v, want %v", tt.args.w.Code, tt.want)
			}
		})
	}
}

func Test_serveHTTPCreate(t *testing.T) {
	ps := []*security.Permission{
		{
			Class:   "Account",
			Actions: []string{"CREATE"},
		},
	}
	// invalid
	r := httptest.NewRequest("POST", "/account", strings.NewReader("{}"))
	r = r.WithContext(context.WithValue(r.Context(), "session.context", &security.Session{
		Permissions: ps,
	}))
	// valid
	rv := httptest.NewRequest("POST", "/account", strings.NewReader("{\"name\":\"test\",\"roles\":[\"Administrator\"]}"))
	rv.Header.Set("content-type", "application/json")
	rv = rv.WithContext(context.WithValue(rv.Context(), "session.context", &security.Session{
		Permissions: ps,
	}))
	type args struct {
		w *httptest.ResponseRecorder
		r *http.Request
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{"create account forbidden", args{
			httptest.NewRecorder(),
			httptest.NewRequest("POST", "/account", nil),
		}, 403},
		{"create account invalid", args{
			httptest.NewRecorder(),
			r,
		}, 400},
		{"create account valid", args{
			httptest.NewRecorder(),
			rv,
		}, 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			RegisterStoreProviderMemdb()
			serveHTTP(tt.args.w, tt.args.r)
			if tt.args.w.Code != tt.want {
				t.Errorf("status code = %v, want %v", tt.args.w.Code, tt.want)
			}
		})
	}
}

func Test_serveHTTPCreateDuplicate(t *testing.T) {
	ps := []*security.Permission{
		{
			Class:   "Account",
			Actions: []string{"CREATE"},
		},
	}
	// valid
	rv := httptest.NewRequest("POST", "/account", strings.NewReader("{\"name\":\"test\",\"roles\":[\"Administrator\"]}"))
	rv.Header.Set("content-type", "application/json")
	rv = rv.WithContext(context.WithValue(rv.Context(), "session.context", &security.Session{
		Permissions: ps,
	}))
	// duplicate
	rd := httptest.NewRequest("POST", "/account", strings.NewReader("{\"name\":\"test\",\"roles\":[\"Administrator\"]}"))
	rd.Header.Set("content-type", "application/json")
	rd = rd.WithContext(context.WithValue(rd.Context(), "session.context", &security.Session{
		Permissions: ps,
	}))
	type args struct {
		w *httptest.ResponseRecorder
		r *http.Request
	}
	tests := []struct {
		name string
		args args
		want int
		body string
	}{
		{"create account valid", args{
			httptest.NewRecorder(),
			rv,
		}, 200, "{\"name\":\"test\",\"state\":\"Initialized\",\"roles\":[\"Administrator\"]}"},
		{"create account duplicate", args{
			httptest.NewRecorder(),
			rd,
		}, 400, "[{\"property\":\"name\",\"rule\":\"Unique\"}]"},
	}
	testStore := RegisterStoreProviderMemdb()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s = *testStore
			serveHTTP(tt.args.w, tt.args.r)
			if tt.args.w.Code != tt.want {
				t.Errorf("status code = %v, want %v", tt.args.w.Code, tt.want)
			}
			if tt.args.w.Body.String() != tt.body {
				t.Error("bad body", tt.args.w.Body.String())
			}
		})
	}
}

func Test_serveHTTPparameter(t *testing.T) {
	type args struct {
		w *httptest.ResponseRecorder
		r *http.Request
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{"read account forbidden", args{
			httptest.NewRecorder(),
			httptest.NewRequest("GET", "/account/test", nil),
		}, 403},
		{"update account forbidden", args{
			httptest.NewRecorder(),
			httptest.NewRequest("PUT", "/account/test", nil),
		}, 403},
		{"delete account forbidden", args{
			httptest.NewRecorder(),
			httptest.NewRequest("DELETE", "/account/test", nil),
		}, 403},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serveHTTPparameter(tt.args.w, tt.args.r)
			if tt.args.w.Code != tt.want {
				t.Errorf("status code = %v, want %v", tt.args.w.Code, tt.want)
			}
		})
	}
}

func Test_serveHTTPpassword(t *testing.T) {
	type args struct {
		w *httptest.ResponseRecorder
		r *http.Request
	}

	ps := []*security.Permission{
		{
			Class:   "Account",
			Actions: []string{"UPDATE_PASSWORD"},
		},
	}
	// not found
	rn := httptest.NewRequest("PUT", "/account", strings.NewReader("p="))
	rn.Header.Set("content-type", "application/x-www-form-urlencoded")
	rn = rn.WithContext(context.WithValue(rn.Context(), "session.context", &security.Session{
		Permissions: ps,
	}))
	rn.ParseForm()
	rn.Form.Set("name", "not")
	rn.Form.Set("p", "a")
	// invalid
	ri := httptest.NewRequest("PUT", "/account", strings.NewReader("p="))
	ri.Header.Set("content-type", "application/x-www-form-urlencoded")
	ri = ri.WithContext(context.WithValue(ri.Context(), "session.context", &security.Session{
		Permissions: ps,
	}))
	ri.ParseForm()
	ri.Form.Set("name", "admin")
	ri.Form.Set("p", "a")
	// valid
	rv := httptest.NewRequest("PUT", "/account", strings.NewReader("p=secretpassword"))
	rv.Header.Set("content-type", "application/x-www-form-urlencoded")
	rv = rv.WithContext(context.WithValue(rv.Context(), "session.context", &security.Session{
		Permissions: ps,
	}))
	rv.ParseForm()
	rv.Form.Set("name", "admin")
	rv.Form.Set("p", "secretpassword")
	tests := []struct {
		name string
		args args
		want int
	}{
		{"update password forbidden", args{
			httptest.NewRecorder(),
			httptest.NewRequest("PUT", "/account/test", nil),
		}, 403},
		{"update password not found", args{
			httptest.NewRecorder(),
			rn,
		}, 404},
		{"update password invalid", args{
			httptest.NewRecorder(),
			ri,
		}, 400},
		{"update password", args{
			httptest.NewRecorder(),
			rv,
		}, 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			RegisterStoreProviderMemdb()
			serveHTTPpassword(tt.args.w, tt.args.r)
			if tt.args.w.Code != tt.want {
				t.Errorf("status code = %v, want %v", tt.args.w.Code, tt.want)
			}
		})
	}
}

func Test_authorize(t *testing.T) {
	type args struct {
		ctx context.Context
		a   security.Account_Action
	}
	var tests []struct {
		name    string
		args    args
		wantErr bool
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := authorize(tt.args.ctx, tt.args.a); (err != nil) != tt.wantErr {
				t.Errorf("authorize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_transition(t *testing.T) {
	type args struct {
		state   security.Account_State
		trigger security.Account_Action
	}
	tests := []struct {
		name string
		args args
		want security.Account_State
	}{
		{
			name: "update password",
			args: args{
				state:   security.Account_Initialized,
				trigger: security.Account_UPDATE_PASSWORD,
			},
			want: security.Account_Activated,
		},
		{
			name: "lock",
			args: args{
				state:   security.Account_Activated,
				trigger: security.Account_LOCK,
			},
			want: security.Account_Locked,
		},
		{
			name: "initialize",
			args: args{
				state:   security.Account_Locked,
				trigger: security.Account_INITIALIZE,
			},
			want: security.Account_Initialized,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := transition(tt.args.state, tt.args.trigger); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("transition() = %v, want %v", got, tt.want)
			}
		})
	}
}
