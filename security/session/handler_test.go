package session

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"secure-rest-server/security"
)

var (
	server *httptest.Server
	url    string
)

func init() {
	accountReader = testAccountRoleReader{}
	roleReader = testAccountRoleReader{}
	server = httptest.NewServer(&testHandler{})
	url = fmt.Sprintf("%s/users", server.URL)
}

func TestPasswordHttp(t *testing.T) {
	userJson := `{"username": "dennis", "balance": 200}`
	reader := strings.NewReader(userJson)
	request, err := http.NewRequest("POST", url, reader) //Create request with JSON body
	if err != nil {
		t.Error(err) //Something is wrong while sending request
	}
	res, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Error(err) //Something is wrong while sending request
	}
	if len(res.Cookies()) != 1 {
		t.Errorf("Expected one cookie: %v", len(res.Cookies()))
	}
	if res.StatusCode != 201 {
		t.Errorf("Success expected: %d", res.StatusCode) //Uh-oh this means our test failed
	}
}

func TestPasswordPost(t *testing.T) {
	const accountName = "test-account"
	const accountPassword = "secretpassword"
	w := testHttpWriter{
		h: http.Header{},
	}
	w.h.Add("Content-Type", "application/x-www-form-urlencoded")
	r := http.Request{
		Method: "POST",
		Body:   ioutil.NopCloser(strings.NewReader("p=" + accountPassword)),
		Header: w.h,
	}
	serveHTTP(w, &r)
	r.ParseForm()
	if "" != r.FormValue("a") {
		t.Error(r.FormValue("a"))
	}
	// + a p
	b := fmt.Sprintf("a=%v&p=%v", accountName, accountPassword)
	r = http.Request{
		Method: "POST",
		Body:   ioutil.NopCloser(strings.NewReader(b)),
		Header: w.h,
	}
	serveHTTP(w, &r)
	r.ParseForm()
	if accountName != r.FormValue("a") {
		t.Error(r.FormValue("a"))
	}
	// - a
	b = fmt.Sprintf("a=%v", accountName)
	r = http.Request{
		Method: "POST",
		Body:   ioutil.NopCloser(strings.NewReader(b)),
		Header: w.h,
	}
	serveHTTP(w, &r)
	r.ParseForm()
	if accountName != r.FormValue("a") {
		t.Error(r.FormValue("a"))
	}
	t.Log(r.FormValue("p"))
}

// net/http/Handler
type testHandler struct {
}

func (h *testHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	serveHTTPparameter(w, r)
}

// net/http/ResponseWriter
type testHttpWriter struct {
	h http.Header
}

func (w testHttpWriter) Header() http.Header               { return w.h }
func (w testHttpWriter) WriteHeader(int)                   {} // no headers
func (w testHttpWriter) Write(p []byte) (n int, err error) { return 0, nil }

type testAccountRoleReader struct{}

func (r testAccountRoleReader) ReadAccount(name string) (*security.Account, error) {
	return &security.Account{
		Name:  "TestName",
		Roles: []string{"TestRole"},
	}, nil
}
func (r testAccountRoleReader) ReadRole(name string) (*security.Role, error) {
	return &security.Role{}, nil
}
