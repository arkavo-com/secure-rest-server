package account

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
	collection = "account"
)

var (
	s Store
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
	return &s
}

// StoreMem development use only.  Default user admin:nimda
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
	s.createAccount(&security.Account{
		Name:  "admin",
		Hash:  "79657a17b98ec928ecb332a71aea22abb940efb04d281e07123a96f78b29eec3",
		Roles: []string{"Administrator"},
		State: security.Account_Activated,
	})
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

func (s *Store) createAccount(a *security.Account) error {
	switch s.provider {
	case mongodbStore:
		err := s.c().Insert(a)
		if mgo.IsDup(err) {
			return rest.ErrDuplicate
		}
		return err
	case postgresStore:
		const sqlstr = `INSERT INTO ` + collection + ` (` +
			`account_name, account_salt, account_hash, account_state, account_roles` +
			`) VALUES (` +
			`$1, $2, $3, $4, $5` +
			`)`
		_, err := s.postgres.Exec(sqlstr, a.Name, a.Salt, a.Hash, a.State, pq.Array(a.Roles))
		if err != nil {
			if err, ok := err.(*pq.Error); ok {
				if err.Code == "23505" {
					return rest.ErrDuplicate
				}
			}
			return err
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
			return rest.ErrDuplicate
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
func (s *Store) readAccounts() ([]*security.Account, error) {
	var accounts []*security.Account
	switch s.provider {
	case mongodbStore:
		err := s.c().Find(nil).All(&accounts)
		return accounts, err
	case postgresStore:
		const sqlstr = `SELECT ` +
			`account_name, account_salt, account_hash, account_state, account_roles ` +
			`FROM ` + collection
		rows, err := s.postgres.Query(sqlstr)
		if err != nil {
			return accounts, err
		}
		defer rows.Close()
		for rows.Next() {
			var a security.Account
			err = rows.Scan(&a.Name, &a.Salt, &a.Hash, &a.State, pq.Array(&a.Roles))
			if err != nil {
				return nil, err
			}
			accounts = append(accounts, &a)
		}
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
	return nil, rest.ErrNotFound
}

// ReadAccount name = Account.name
func (s *Store) ReadAccount(name string) (*security.Account, error) {
	var a security.Account
	switch s.provider {
	case mongodbStore:
		err := s.c().Find(bson.M{"name": name}).One(&a)
		return &a, err
	case postgresStore:
		const sqlstr = `SELECT ` +
			`account_name, account_salt, account_hash, account_state, account_roles ` +
			`FROM ` + collection + ` ` +
			`WHERE account_name = $1`
		err := s.postgres.QueryRow(sqlstr, name).Scan(&a.Name, &a.Salt, &a.Hash, &a.State, pq.Array(&a.Roles))
		if err != nil {
			if sql.ErrNoRows == err {
				return &a, rest.ErrNotFound
			}
			return &a, err
		}
		return &a, err
	case redisStore:
		b, err := redis.Bytes(s.get().Do("GET", name))
		if err != nil {
			return nil, err
		}
		err = proto.Unmarshal(b, &a)
		if err != nil {
			return nil, rest.ErrNotFound
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
			return nil, rest.ErrNotFound
		}
		return raw.(*security.Account), err
	}
	return nil, rest.ErrNotFound
}

func (s *Store) updateAccount(a *security.Account) error {
	switch s.provider {
	case mongodbStore:
		return s.c().Update(bson.M{"name": a.Name}, &a)
	case postgresStore:
		const sqlstr = `UPDATE ` + collection + ` SET (` +
			`account_salt, account_hash, account_state, account_roles` +
			`) = ROW( ` +
			`$1, $2, $3, $4` +
			`) WHERE account_name = $5`
		_, err := s.postgres.Exec(sqlstr, &a.Salt, &a.Hash, &a.State, pq.Array(&a.Roles), &a.Name)
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
		if raw == nil {
			txn.Abort()
			return rest.ErrNotFound
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

func (s *Store) deleteAccount(name string) error {
	switch s.provider {
	case mongodbStore:
		return s.c().Remove(name)
	case postgresStore:
		const sqlstr = `DELETE FROM ` + collection + ` WHERE account_name = $1`
		_, err := s.postgres.Exec(sqlstr, name)
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
