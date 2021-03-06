package role

import (
	"database/sql"
	"log"

	"github.com/arkavo-com/secure-rest-server/security"
	"github.com/arkavo-com/secure-rest-server/security/rest"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/gomodule/redigo/redis"
	"github.com/hashicorp/go-memdb"
	"github.com/lib/pq"
	"google.golang.org/protobuf/proto"
)

type storeProvider int

const (
	mongodbStore storeProvider = iota + 1
	postgresStore
	redisStore
	memdbStore
)

const (
	collection = "role"
)

var (
	s Store
	// standard
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

// StoreMongo initializes store, call once
func StoreMongo(session *mgo.Session) *Store {
	if s.provider != 0 {
		return nil
	}
	s = Store{
		provider: mongodbStore,
		mongo:    session,
	}
	_ = s.createRole(&administratorRole)
	return &s
}

// StorePostgres initializes store, call once
func StorePostgres(db *sql.DB) *Store {
	if s.provider != 0 {
		return nil
	}
	s = Store{
		provider: postgresStore,
		postgres: db,
	}
	_ = s.createRole(&administratorRole)
	return &s
}

// StoreRedis initializes store, call once
func StoreRedis(c redis.Conn) *Store {
	if s.provider != 0 {
		return nil
	}
	s = Store{
		provider: redisStore,
		redis: &redis.Pool{
			Dial: func() (redis.Conn, error) {
				return c, nil
			},
		},
	}
	_ = s.createRole(&administratorRole)
	return &s
}

// StoreMem development use only.
func StoreMem() *Store {
	if s.provider != 0 {
		return nil
	}
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
	s = Store{
		provider: memdbStore,
		mem:      db,
	}
	_ = s.createRole(&administratorRole)
	return &s
}

// Store manages various storage mechanisms
type Store struct {
	provider storeProvider
	mongo    *mgo.Session
	redis    *redis.Pool
	mem      *memdb.MemDB
	postgres *sql.DB
}

func (s *Store) c() *mgo.Collection {
	return s.mongo.Clone().DB("").C(collection)
}

func (s *Store) get() redis.Conn {
	return s.redis.Get()
}

func (s *Store) createRole(r *security.Role) error {
	switch s.provider {
	case mongodbStore:
		return s.c().Insert(r)
	case postgresStore:
		txn, err := s.postgres.Begin()
		if err != nil {
			return err
		}
		const sqlstr = `INSERT INTO ` + collection + ` (` +
			`role_name, role_state` +
			`) VALUES (` +
			`$1, $2` +
			`)`
		_, err = txn.Exec(sqlstr, r.Name, r.State)
		if err != nil {
			if err, ok := err.(*pq.Error); ok {
				if err.Code == "23505" {
					return rest.ErrDuplicate
				}
			}
			return err
		}
		const sqlstrSec = `INSERT INTO ` + collection + `_permission (` +
			`role_name, permission_class, permission_actions` +
			`) VALUES (` +
			`$1, $2, $3` +
			`)`
		for _, p := range r.Permissions {
			_, err = txn.Exec(sqlstrSec, r.Name, p.Class, pq.Array(p.Actions))
			if err != nil {
				txn.Rollback()
				return err
			}
		}
		err = txn.Commit()
		return err
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
			return rest.ErrDuplicate
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

func (s *Store) readRoles() ([]*security.Role, error) {
	var roles []*security.Role
	switch s.provider {
	case mongodbStore:
		err := s.c().Find(nil).All(&roles)
		return roles, err
	case postgresStore:
		roleMap := make(map[string]*security.Role)
		const sqlstr = `SELECT ` +
			`role_name, role_state ` +
			`FROM ` + collection
		rows, err := s.postgres.Query(sqlstr)
		if err != nil {
			return roles, err
		}
		defer rows.Close()
		for rows.Next() {
			var r security.Role
			err = rows.Scan(&r.Name, &r.State)
			if err != nil {
				return nil, err
			}
			roles = append(roles, &r)
			roleMap[r.Name] = &r
		}
		const sqlstrSec = `SELECT ` +
			`role_name, permission_class, permission_actions ` +
			`FROM ` + collection + `_permission `
		rowsSec, err := s.postgres.Query(sqlstrSec)
		if err != nil {
			return roles, err
		}
		defer rowsSec.Close()
		for rowsSec.Next() {
			var roleName string
			var p security.Permission
			err = rowsSec.Scan(&roleName, &p.Class, pq.Array(&p.Actions))
			if err != nil {
				return nil, err
			}
			roleMap[roleName].Permissions = append(roleMap[roleName].Permissions, &p)
		}
		return roles, err
	case redisStore:
	case memdbStore:
		txn := s.mem.Txn(false)
		defer txn.Abort()
		result, err := txn.Get(collection, "id")
		if err != nil {
			return nil, err
		}
		for raw := result.Next(); raw != nil; raw = result.Next() {
			roles = append(roles, raw.(*security.Role))
		}
		return roles, err
	}
	return roles, nil
}

// ReadRole return role with name
func (s *Store) ReadRole(name string) (*security.Role, error) {
	var r security.Role
	switch s.provider {
	case mongodbStore:
		err := s.c().Find(bson.M{"name": name}).One(&r)
		return &r, err
	case postgresStore:
		const sqlstr = `SELECT ` +
			`role_name, role_state ` +
			`FROM ` + collection + ` ` +
			`WHERE role_name = $1`
		err := s.postgres.QueryRow(sqlstr, name).Scan(&r.Name, &r.State)
		if err != nil {
			return &r, err
		}
		const sqlstrSec = `SELECT ` +
			`permission_class, permission_actions ` +
			`FROM ` + collection + `_permission ` +
			`WHERE role_name = $1`
		rows, err := s.postgres.Query(sqlstrSec, name)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var p security.Permission
			err = rows.Scan(&p.Class, pq.Array(&p.Actions))
			if err != nil {
				return nil, err
			}
			r.Permissions = append(r.Permissions, &p)
		}
		err = rows.Err()
		return &r, err
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
		if raw == nil {
			return nil, rest.ErrNotFound
		}
		return raw.(*security.Role), err
	}
	return &r, nil
}

func (s *Store) updateRole(r *security.Role) error {
	switch s.provider {
	case mongodbStore:
		return s.c().Update(bson.M{"name": r.Name}, r)
	case postgresStore:
		txn, err := s.postgres.Begin()
		if err != nil {
			return err
		}
		// update state
		const sqlstr = `UPDATE ` + collection + ` SET (` +
			`role_state` +
			`) = ROW( ` +
			`$1` +
			`) WHERE role_name = $2`
		_, err = s.postgres.Exec(sqlstr, r.State, r.Name)
		if err != nil {
			txn.Rollback()
			return err
		}
		// delete permissions
		const sqlstrSec = `DELETE FROM ` + collection + `_permission WHERE role_name = $1`
		_, err = txn.Exec(sqlstrSec, r.Name)
		if err != nil {
			txn.Rollback()
			return err
		}
		// insert permissions
		const sqlstrTer = `INSERT INTO ` + collection + `_permission (` +
			`role_name, permission_class, permission_actions` +
			`) VALUES (` +
			`$1, $2, $3` +
			`)`
		for _, p := range r.Permissions {
			_, err = txn.Exec(sqlstrTer, r.Name, p.Class, pq.Array(p.Actions))
			if err != nil {
				txn.Rollback()
				return err
			}
		}
		err = txn.Commit()
		return err
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
			return rest.ErrNotFound
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

func (s *Store) deleteRole(name string) error {
	switch s.provider {
	case mongodbStore:
		return s.c().Remove(bson.M{"name": name})
	case postgresStore:
		txn, err := s.postgres.Begin()
		if err != nil {
			return err
		}
		const sqlstr = `DELETE FROM ` + collection + `_permission WHERE role_name = $1`
		_, err = txn.Exec(sqlstr, name)
		if err != nil {
			txn.Rollback()
			return err
		}
		const sqlstrSec = `DELETE FROM ` + collection + ` WHERE role_name = $1`
		_, err = txn.Exec(sqlstrSec, name)
		if err != nil {
			txn.Rollback()
			return err
		}
		txn.Commit()
		return err
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
