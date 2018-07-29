package permission

import (
	"database/sql"
	"errors"
	"log"

	"secure-rest-server/security"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/golang/protobuf/proto"
	"github.com/gomodule/redigo/redis"
	"github.com/hashicorp/go-memdb"
	"github.com/lib/pq"
)

type storeProvider int

const (
	mongodbStore storeProvider = iota + 1
	postgresStore
	redisStore
	memdbStore
)

const (
	collection = "permission"
)

var (
	s store
	// error
	ErrNotFound  = errors.New("not found")
	ErrDuplicate = errors.New("duplicate")
)

// StoreMongo initializes store, call once
func StoreMongo(session *mgo.Session) *store {
	if s.provider != 0 {
		return nil
	}
	s = store{
		provider: mongodbStore,
		mongo:    session,
	}
	return &s
}

// StorePostgres initializes store, call once
func StorePostgres(db *sql.DB) *store {
	if s.provider != 0 {
		return nil
	}
	s = store{
		provider: postgresStore,
		postgres: db,
	}
	return &s
}

// StoreRedis initializes store, call once
func StoreRedis(c redis.Conn) *store {
	if s.provider != 0 {
		return nil
	}
	s = store{
		provider: redisStore,
		redis: &redis.Pool{
			Dial: func() (redis.Conn, error) {
				return c, nil
			},
		},
	}
	return &s
}

// StoreMem development use only.  Default user admin:nimda
func StoreMem() *store {
	db, err := memdb.NewMemDB(&memdb.DBSchema{
		Tables: map[string]*memdb.TableSchema{
			collection: {
				Name: collection,
				Indexes: map[string]*memdb.IndexSchema{
					"id": {
						Name:    "id",
						Unique:  true,
						Indexer: &memdb.StringFieldIndex{Field: "Class"},
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
	return &s
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

func (s *store) createPermission(p *security.Permission) error {
	switch s.provider {
	case mongodbStore:
		return s.c().Insert(p)
	case postgresStore:
		const sqlstr = `INSERT INTO permission (` +
			`permission_class, permission_actions` +
			`) VALUES (` +
			`$1, $2` +
			`)`
		_, err := s.postgres.Exec(sqlstr, p.Class, pq.Array(p.Actions))
		if err != nil {
			if err, ok := err.(*pq.Error); ok {
				if err.Code == "23505" {
					return ErrDuplicate
				}
			}
			return err
		}
	case redisStore:
		b, err := proto.Marshal(p)
		if err != nil {
			return err
		}
		_, err = s.get().Do("SET", p.Class, b)
		return err
	case memdbStore:
		txn := s.mem.Txn(true)
		raw, err := txn.First(collection, "id", p.Class)
		if err != nil {
			txn.Abort()
			return err
		}
		if raw != nil {
			txn.Abort()
			return ErrDuplicate
		}
		err = txn.Insert(collection, p)
		if err != nil {
			txn.Abort()
			return err
		}
		txn.Commit()
		return err
	}
	return nil
}

func (s *store) readPermissions() ([]*security.Permission, error) {
	var permissions []*security.Permission
	switch s.provider {
	case mongodbStore:
		err := s.c().Find(nil).All(&permissions)
		return permissions, err
	case postgresStore:
		const sqlstr = `SELECT ` +
			`permission_class, permission_actions ` +
			`FROM ` + collection
		rows, err := s.postgres.Query(sqlstr)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var p security.Permission
			err := rows.Scan(&p.Class, pq.Array(&p.Actions))
			if err != nil {
				return nil, err
			}
			permissions = append(permissions, &p)
		}
		err = rows.Err()
		return permissions, err
	case memdbStore:
		txn := s.mem.Txn(false)
		defer txn.Abort()
		result, err := txn.Get(collection, "id")
		if err != nil {
			return nil, err
		}
		var permissions []*security.Permission
		for raw := result.Next(); raw != nil; raw = result.Next() {
			permissions = append(permissions, raw.(*security.Permission))
		}
		return permissions, err
	}
	return permissions, nil
}

func (s *store) readPermission(c string) (*security.Permission, error) {
	var p security.Permission
	switch s.provider {
	case mongodbStore:
		err := s.c().Find(bson.M{"class": c}).One(&p)
		return &p, err
	case postgresStore:
		const sqlstr = `SELECT ` +
			`permission_class, permission_actions ` +
			`FROM ` + collection + ` ` +
			`WHERE permission_class = $1`
		err := s.postgres.QueryRow(sqlstr, c).Scan(&p.Class, pq.Array(&p.Actions))
		if err != nil {
			if sql.ErrNoRows == err {
				return &p, ErrNotFound
			}
			return &p, err
		}
		return &p, err
	case memdbStore:
		txn := s.mem.Txn(false)
		defer txn.Abort()
		raw, err := txn.First(collection, "id", c)
		if err != nil {
			return nil, err
		}
		if raw == nil {
			return nil, ErrNotFound
		}
		return raw.(*security.Permission), err
		return &p, err
	}
	return &p, ErrNotFound
}
