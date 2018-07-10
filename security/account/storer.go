package account

import (
	"errors"
	"log"
	"secure-rest-server/security"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/golang/protobuf/proto"
	"github.com/gomodule/redigo/redis"
	"github.com/hashicorp/go-memdb"
)

type storeProvider int

const (
	mongodbStore storeProvider = iota + 1
	postgresStore
	redisStore
	memdbStore
)

const (
	collection = "account"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrDuplicate = errors.New("duplicate")
	s            store
)

func RegisterStoreProviderMgo(info *mgo.DialInfo) *store {
	s = store{
		provider: mongodbStore,
		database: info.Database,
	}
	s.mSession, _ = mgo.DialWithInfo(info)
	return &s
}

// RegisterStoreProviderMemdb development use only.  Default user admin:nimda
func RegisterStoreProviderMemdb() *store {
	db, err := memdb.NewMemDB(&memdb.DBSchema{
		Tables: map[string]*memdb.TableSchema{
			collection: {
				Name: collection,
				Indexes: map[string]*memdb.IndexSchema{
					"id": {
						Name:    "id",
						Unique:  true,
						Indexer: &memdb.StringFieldIndex{Field: "Name"},
					},
				},
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	s = store{
		provider: memdbStore,
		database: collection,
		mem:      db,
	}
	s.createAccount(&security.Account{
		Name:  "admin",
		Hash:  "79657a17b98ec928ecb332a71aea22abb940efb04d281e07123a96f78b29eec3",
		Roles: []string{"Administrator"},
		State: security.Account_Activated,
	})
	return &s
}

type store struct {
	provider  storeProvider
	database  string
	mSession  *mgo.Session
	redisPool *redis.Pool
	mem       *memdb.MemDB
}

func (s *store) c() *mgo.Collection {
	return s.mSession.Clone().DB(s.database).C(collection)
}

func (s *store) get() redis.Conn {
	return s.redisPool.Get()
}

func (s *store) createAccount(a *security.Account) error {
	switch s.provider {
	case mongodbStore:
		err := s.c().Insert(a)
		if mgo.IsDup(err) {
			return ErrDuplicate
		}
		return err
	case redisStore:
		b, err := proto.Marshal(a)
		if err != nil {
			return err
		}
		_, err = s.get().Do("SET", a.Name, b)
		return err
	case memdbStore:
		txn := s.mem.Txn(true)
		raw, err := txn.First(collection, "id", a.Name)
		if err != nil {
			txn.Abort()
			return err
		}
		if raw != nil {
			txn.Abort()
			return ErrDuplicate
		}
		err = txn.Insert(collection, a)
		if err != nil {
			txn.Abort()
			return err
		}
		txn.Commit()
		return err
	}
	return nil
}

// readAccounts
func (s *store) readAccounts() ([]*security.Account, error) {
	var accounts []*security.Account
	switch s.provider {
	case mongodbStore:
		err := s.c().Find(nil).All(&accounts)
		return accounts, err
	case redisStore:
	case memdbStore:
		txn := s.mem.Txn(false)
		defer txn.Abort()
		result, err := txn.Get(collection, "id")
		if err != nil {
			return nil, err
		}
		var accounts []*security.Account
		for raw := result.Next(); raw != nil; raw = result.Next() {
			accounts = append(accounts, raw.(*security.Account))
		}
		return accounts, err
	}
	return nil, ErrNotFound
}

// ReadAccount name = Account.name
func (s *store) ReadAccount(name string) (*security.Account, error) {
	var a security.Account
	switch s.provider {
	case mongodbStore:
		err := s.c().Find(bson.M{"name": name}).One(&a)
		return &a, err
	case redisStore:
		b, err := redis.Bytes(s.get().Do("GET", name))
		if err != nil {
			return nil, err
		}
		err = proto.Unmarshal(b, &a)
		if err != nil {
			return nil, ErrNotFound
		}
		return &a, err
	case memdbStore:
		txn := s.mem.Txn(false)
		defer txn.Abort()
		raw, err := txn.First(collection, "id", name)
		if err != nil {
			return nil, err
		}
		if raw == nil {
			return nil, ErrNotFound
		}
		return raw.(*security.Account), err
	}
	return nil, ErrNotFound
}

func (s *store) updateAccount(a *security.Account) error {
	switch s.provider {
	case mongodbStore:
		return s.c().Update(bson.M{"name": a.Name}, &a)
	case redisStore:
		b, err := proto.Marshal(a)
		if err != nil {
			return err
		}
		_, err = s.get().Do("SET", a.Name, b)
		return err
	case memdbStore:
		txn := s.mem.Txn(true)
		raw, err := txn.First(collection, "id", a.Name)
		if err != nil {
			txn.Abort()
			return err
		}
		if raw == nil {
			txn.Abort()
			return ErrNotFound
		}
		err = txn.Insert(collection, a)
		if err != nil {
			txn.Abort()
			return err
		}
		txn.Commit()
		return err
	}
	return nil
}

func (s *store) deleteAccount(name string) error {
	switch s.provider {
	case mongodbStore:
		return s.c().Remove(name)
	case redisStore:
		_, err := s.get().Do("DEL", name)
		return err
	case memdbStore:
		txn := s.mem.Txn(true)
		raw, err := txn.First(collection, "id", name)
		if err != nil {
			txn.Abort()
			return err
		}
		if raw == nil {
			txn.Abort()
			return ErrNotFound
		}
		err = txn.Delete(collection, raw)
		if err != nil {
			txn.Abort()
			return err
		}
		txn.Commit()
		return err
	}
	return nil
}
