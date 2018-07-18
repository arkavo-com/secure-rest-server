package permission

import (
	"database/sql"
	"errors"
	"log"

	"secure-rest-server/security"

	"github.com/globalsign/mgo"
	"github.com/golang/protobuf/proto"
	"github.com/gomodule/redigo/redis"
	"github.com/hashicorp/go-memdb"
	"github.com/lib/pq"
)

type storeProvider int

const (
	mongodbStore  storeProvider = iota + 1
	postgresStore
	redisStore
	memdbStore
)

const (
	collection = "permission"
)

var (
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

func RegisterStoreProviderPostgres(db *sql.DB) *store {
	s = store{
		provider:   postgresStore,
		postgresDB: db,
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
		database: collection,
		mem:      db,
	}
	return &s
}

type store struct {
	provider   storeProvider
	database   string
	mSession   *mgo.Session
	redisPool  *redis.Pool
	mem        *memdb.MemDB
	postgresDB *sql.DB
}

func (s *store) c() *mgo.Collection {
	return s.mSession.Clone().DB(s.database).C(collection)
}

func (s *store) get() redis.Conn {
	return s.redisPool.Get()
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
		_, err := s.postgresDB.Exec(sqlstr, p.Class, pq.Array(p.Actions))
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
		rows, err := s.postgresDB.Query(sqlstr)
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
