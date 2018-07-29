package session

import (
	"database/sql"
	"log"

	"secure-rest-server/security"
	"secure-rest-server/security/rest"

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
	collection = "session"
)

var (
	s store
)

// StoreMongo initializes store, call once
func StoreMongo(session *mgo.Session) {
	if s.provider != 0 {
		return
	}
	s = store{
		provider: mongodbStore,
		mongo:    session,
	}
}

// StorePostgres initializes store, call once
func StorePostgres(db *sql.DB) {
	if s.provider != 0 {
		return
	}
	s = store{
		provider: postgresStore,
		postgres: db,
	}
}

// StoreRedis initializes store, call once
func StoreRedis(c redis.Conn) {
	if s.provider != 0 {
		return
	}
	s = store{
		provider: redisStore,
		redis: &redis.Pool{
			Dial: func() (redis.Conn, error) {
				return c, nil
			},
		},
	}
}

// StoreMem development use only.  Default user admin:nimda
func StoreMem() {
	if s.provider != 0 {
		return
	}
	db, err := memdb.NewMemDB(&memdb.DBSchema{
		Tables: map[string]*memdb.TableSchema{
			collection: {
				Name: collection,
				Indexes: map[string]*memdb.IndexSchema{
					"id": {
						Name:    "id",
						Unique:  true,
						Indexer: &memdb.StringFieldIndex{Field: "Id"},
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
		mem:      db,
	}
}

type store struct {
	provider storeProvider
	mongo    *mgo.Session
	redis    *redis.Pool
	mem      *memdb.MemDB
	postgres *sql.DB
}

func (s *store) c() *mgo.Collection {
	return s.mongo.Clone().DB("").C(collection)
}

func (s *store) get() redis.Conn {
	return s.redis.Get()
}

func (s *store) createSession(ss security.Session) error {
	switch s.provider {
	case mongodbStore:
		return s.c().Insert(ss)
	case redisStore:
		b, err := proto.Marshal(&ss)
		if err != nil {
			return err
		}
		_, err = s.get().Do("SET", ss.Id, b)
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
	case mongodbStore:
		ss := security.Session{}
		err := s.c().Find(bson.M{"id": si}).One(&ss)
		return &ss, err
	case redisStore:
		b, err := redis.Bytes(s.redis.Get().Do("GET", si))
		if err != nil {
			return nil, err
		}
		ss := security.Session{}
		err = proto.Unmarshal(b, &ss)
		if err != nil {
			return nil, rest.ErrNotFound
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
			return nil, rest.ErrNotFound
		}
		return raw.(*security.Session), err
	}
	return nil, rest.ErrNotFound
}

func (s *store) deleteSession(id string) error {
	switch s.provider {
	case mongodbStore:
		return s.c().Remove(bson.M{"id": id})
	case redisStore:
		_, err := s.get().Do("DEL", id)
		return err
	case memdbStore:
		txn := s.mem.Txn(true)
		raw, err := txn.First(collection, "id", id)
		if err != nil {
			txn.Abort()
			return err
		}
		if raw == nil {
			txn.Abort()
			return rest.ErrNotFound
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
