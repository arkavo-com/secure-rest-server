package policy

import (
	"log"
	"net/http"

	"secure-rest-server/security"

	"github.com/golang/protobuf/jsonpb"
)

var (
	Account  security.Policy_Account
	Audit    security.Policy_Audit
	Password security.Policy_Password
	Role     security.Policy_Role
	Session  security.Policy_Session
)

type httpGetter interface {
	Get(url string) (resp *http.Response, err error)
}

func init() {
	getSet(&http.Client{})
}

func getSet(httpClient httpGetter) {
	// default
	Account = security.Policy_Account{
		LengthMinimum:                        5,
		LengthMaximum:                        128,
		Pattern:                              "[a-zA-Z0-9_@.-]",
		InactiveDurationConsequenceLock:       "90d",
		InactiveDurationConsequenceDeactivate: "180d",
	}
	Audit = security.Policy_Audit{}
	Password = security.Policy_Password{
		LengthMinimum:                        5,
		LengthMaximum:                        1024,
		Pattern:                              "[a-zA-Z0-9_@.-]",
		ReuseMaximum:                         6,
		AuthenticateInitialConsequence:       "RestrictedUser",
		DurationMaximum:                      "90d",
		DurationMaximumConsequence:           "RestrictedUser",
		AuthenticateFailedCountMaximum:       5,
		AuthenticateFailedMaximumConsequence: "LOCK",
	}
	Role = security.Policy_Role{}
	Session = security.Policy_Session{
		Single:          false,
		DurationIdle:    "20m",
		IdleConsequence: "RestrictedUser",
		DurationRenewal: "23h",
		DurationMaximum: "24h",
	}
	// get
	r, err := httpClient.Get("http://127.0.0.1:8500/v1/kv/arkavo/policy?raw")
	if err != nil {
		log.Println("consul unreachable", err)
		logPolicy()
		return
	}
	if r.StatusCode != http.StatusOK {
		log.Println("bad response code", r.StatusCode, r.Request.URL)
		logPolicy()
		return
	}
	var policy security.Policy
	// TODO add validation
	err = jsonpb.Unmarshal(r.Body, &policy)
	if err != nil {
		log.Println("bad JSON", err)
		return
	}
	// set
	Account = *policy.Account
	Audit = *policy.Audit
	Password = *policy.Password
	Role = *policy.Role
	Session = *policy.Session
	httpClient = nil
}
func logPolicy() {
	m := jsonpb.Marshaler{
		EmitDefaults: true,
		Indent:       "  ",
	}
	s, _ := m.MarshalToString(&security.Policy{
		Account:  &Account,
		Audit:    &Audit,
		Password: &Password,
		Role:     &Role,
		Session:  &Session,
	})
	log.Println("policy: \n", s)
}
