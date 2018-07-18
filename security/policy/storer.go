package policy

import (
	"secure-rest-server/security"

	"github.com/globalsign/mgo"
	"github.com/gomodule/redigo/redis"
)

type storeProvider int

const (
	mongodbStore storeProvider = iota + 1
	redisStore
	memdbStore
)

const (
	collection = "policy"
)

var (
	s store
)

func RegisterStoreProviderMgo(info *mgo.DialInfo) *store {
	s = store{
		provider: mongodbStore,
		database: info.Database,
	}
	// FIXME mongodb
	s.policy = &security.Policy{
		Account: &security.Policy_Account{
			InactiveDurationConsequenceLock:       "90d",
			InactiveDurationConsequenceDeactivate: "180d",
		},
		Audit: &security.Policy_Audit{},
		Password: &security.Policy_Password{
			LengthMinimum:                        8,
			LengthMaximum:                        128,
			Pattern:                              "[a-zA-Z0-9_@.-]",
			ReuseMaximum:                         3,
			AuthenticateInitialConsequence:       "RestrictedUser",
			DurationMaximum:                      "90d",
			DurationMaximumConsequence:           "RestrictedUser",
			AuthenticateFailedCountMaximum:       5,
			AuthenticateFailedMaximumConsequence: "LOCK",
		},
		Role: &security.Policy_Role{},
		Session: &security.Policy_Session{
			Single:          false,
			DurationIdle:    "20m",
			IdleConsequence: "RestrictedUser",
			DurationRenewal: "23h",
			DurationMaximum: "24h",
		},
	}
	return &s
}

func RegisterStoreProviderRedis(c redis.Conn) *store {
	s = store{
		provider: redisStore,
		redisPool: &redis.Pool{
			Dial: func() (redis.Conn, error) {
				return c, nil
			},
		},
	}
	return &s
}

func RegisterStoreProviderMemdb() *store {
	s = store{
		provider: memdbStore,
		database: collection,
	}
	s.policy = &security.Policy{
		Account: &security.Policy_Account{
			InactiveDurationConsequenceLock:       "90d",
			InactiveDurationConsequenceDeactivate: "180d",
		},
		Audit: &security.Policy_Audit{},
		Password: &security.Policy_Password{
			LengthMinimum:                        8,
			LengthMaximum:                        128,
			Pattern:                              "[a-zA-Z0-9_@.-]",
			ReuseMaximum:                         3,
			AuthenticateInitialConsequence:       "RestrictedUser",
			DurationMaximum:                      "90d",
			DurationMaximumConsequence:           "RestrictedUser",
			AuthenticateFailedCountMaximum:       5,
			AuthenticateFailedMaximumConsequence: "LOCK",
		},
		Role: &security.Policy_Role{},
		Session: &security.Policy_Session{
			Single:          false,
			DurationIdle:    "20m",
			IdleConsequence: "RestrictedUser",
			DurationRenewal: "23h",
			DurationMaximum: "24h",
		},
	}
	return &s
}

type store struct {
	policy    *security.Policy
	provider  storeProvider
	database  string
	mSession  *mgo.Session
	redisPool *redis.Pool
}

func (s *store) ReadPolicy() *security.Policy {
	return s.policy
}

func (s *store) updatePolicy(p *security.Policy) error {
	var err error
	s.policy = p
	return err
}
