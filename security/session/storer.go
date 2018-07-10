package session

import (
	"errors"
	"log"
	"secure-rest-server/security"

	"github.com/globalsign/mgo"
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
	collection = "session"
)

var (
	s           store
	ErrNotFound = errors.New("not found")
)

// RegisterStoreProviderMemdb
func RegisterStoreProviderMemdb() *store {
	db, err := memdb.NewMemDB(&memdb.DBSchema{
		Tables: map[string]*memdb.TableSchema{
			collection: {
				Name: collection,
				Indexes: map[string]*memdb.IndexSchema{
					"id": {
						Name:    "id",
						Unique:  true,
						Indexer: &memdb.StringFieldIndex{Field: "SessionId"},
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
	return &s
}

// RegisterStoreProviderRedis
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

type store struct {
	provider  storeProvider
	database  string
	mSession  *mgo.Session
	redisPool *redis.Pool
	mem       *memdb.MemDB
}

func (s *store) createSession(ss security.Session) error {
	switch s.provider {
	case redisStore:
		b, err := proto.Marshal(&ss)
		if err != nil {
			return err
		}
		_, err = s.redisPool.Get().Do("SET", ss.SessionId, b)
		return err
	case memdbStore:
		txn := s.mem.Txn(true)
		err := txn.Insert(collection, &ss)
		if err != nil {
			txn.Abort()
			return err
		}
		txn.Commit()
		return err
	}
	return nil
}

func (s *store) readSession(si string) (*security.Session, error) {
	switch s.provider {
	case redisStore:
		b, err := redis.Bytes(s.redisPool.Get().Do("GET", si))
		if err != nil {
			return nil, err
		}
		ss := security.Session{}
		err = proto.Unmarshal(b, &ss)
		if err != nil {
			return nil, ErrNotFound
		}
		return &ss, nil
	case memdbStore:
		txn := s.mem.Txn(false)
		defer txn.Abort()
		raw, err := txn.First(collection, "id", si)
		if err != nil {
			return nil, err
		}
		if raw == nil {
			return nil, ErrNotFound
		}
		return raw.(*security.Session), err
	}
	return nil, ErrNotFound
}

func (s *store) deleteSession(sessionId string) error {
	switch s.provider {
	case redisStore:
		_, err := s.redisPool.Get().Do("DEL", sessionId)
		return err
	case memdbStore:
		txn := s.mem.Txn(true)
		raw, err := txn.First(collection, "id", sessionId)
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
