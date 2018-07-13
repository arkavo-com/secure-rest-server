package role

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
	mongodbStore  storeProvider = iota + 1
	postgresStore
	redisStore
	memdbStore
)

const (
	collection = "role"
)

var (
	ErrNotFound       = errors.New("not found")
	ErrDuplicate      = errors.New("duplicate")
	s                 store
	administratorRole = security.Role{
		Name: "Administrator",
		Permissions: []*security.Permission{
			&security.AccountPermission,
			&security.PermissionPermission,
			&security.PolicyPermission,
			&security.RolePermission,
			&security.SessionPermission,
		},
		State: security.Role_Activated,
	}
)

func RegisterStoreProviderMgo(info *mgo.DialInfo) *store {
	s = store{
		provider: mongodbStore,
		database: info.Database,
	}
	s.mSession, _ = mgo.DialWithInfo(info)
	s.createRole(&administratorRole)
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
	s.createRole(&administratorRole)
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

func (s *store) createRole(r *security.Role) error {
	switch s.provider {
	case mongodbStore:
		return s.c().Insert(r)
	case postgresStore:
	case redisStore:
		b, err := proto.Marshal(r)
		if err != nil {
			return err
		}
		_, err = s.get().Do("SET", r.Name, b)
		return err
	case memdbStore:
		txn := s.mem.Txn(true)
		raw, err := txn.First(collection, "id", r.Name)
		if err != nil {
			txn.Abort()
			return err
		}
		if raw != nil {
			txn.Abort()
			return ErrDuplicate
		}
		err = txn.Insert(collection, r)
		if err != nil {
			txn.Abort()
			return err
		}
		txn.Commit()
		return err
	}
	return nil
}

func (s *store) readRoles() ([]*security.Role, error) {
	var roles []*security.Role
	switch s.provider {
	case mongodbStore:
		s.c().Find(nil).All(&roles)
	case postgresStore:
	case redisStore:
	case memdbStore:
		txn := s.mem.Txn(false)
		defer txn.Abort()
		result, err := txn.Get(collection, "id")
		if err != nil {
			return nil, err
		}
		var roles []*security.Role
		for raw := result.Next(); raw != nil; raw = result.Next() {
			roles = append(roles, raw.(*security.Role))
		}
		return roles, err
	}
	return roles, nil
}

func (s *store) ReadRole(name string) (*security.Role, error) {
	var r security.Role
	switch s.provider {
	case mongodbStore:
		err := s.c().Find(bson.M{"name": name}).One(&r)
		return &r, err
	case postgresStore:
	case redisStore:
		b, err := redis.Bytes(s.get().Do("GET", name))
		if err != nil {
			return nil, err
		}
		err = proto.Unmarshal(b, &r)
		if err != nil {
			return nil, err
		}
		return &r, err
	case memdbStore:
		txn := s.mem.Txn(false)
		defer txn.Abort()
		raw, err := txn.First(collection, "id", name)
		if err != nil {
			return nil, err
		}
		return raw.(*security.Role), err
	}
	return &r, nil
}

func (s *store) updateRole(r *security.Role) error {
	switch s.provider {
	case mongodbStore:
		return s.c().Update(bson.M{"name": r.Name}, r)
	case postgresStore:
	case redisStore:
		_, err := s.get().Do("SET", r.Name, r)
		return err
	case memdbStore:
		txn := s.mem.Txn(true)
		raw, err := txn.First(collection, "id", r.Name)
		if err != nil {
			txn.Abort()
			return err
		}
		if raw == nil {
			txn.Abort()
			return ErrNotFound
		}
		err = txn.Insert(collection, r)
		if err != nil {
			txn.Abort()
			return err
		}
		txn.Commit()
		return err
	}
	return nil
}

func (s *store) deleteRole(name string) error {
	switch s.provider {
	case mongodbStore:
		return s.c().Remove(bson.M{"name": name})
	case postgresStore:
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
