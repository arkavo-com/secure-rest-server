package account

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
	mongodbStore  storeProvider = iota + 1
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

func RegisterStoreProviderPostgres(db *sql.DB) *store {
	s = store{
		provider:   postgresStore,
		postgresDB: db,
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

func (s *store) createAccount(a *security.Account) error {
	switch s.provider {
	case mongodbStore:
		err := s.c().Insert(a)
		if mgo.IsDup(err) {
			return ErrDuplicate
		}
		return err
	case postgresStore:
		const sqlstr = `INSERT INTO ` + collection + ` (` +
			`account_name, account_salt, account_hash, account_state, account_roles` +
			`) VALUES (` +
			`$1, $2, $3, $4, $5` +
			`)`
		_, err := s.postgresDB.Exec(sqlstr, a.Name, a.Salt, a.Hash, a.State, pq.Array(a.Roles))
		if err != nil {
			if err, ok := err.(*pq.Error); ok {
				if err.Code == "23505" {
					return ErrDuplicate
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
	case postgresStore:
		const sqlstr = `SELECT ` +
			`account_name, account_salt, account_hash, account_state, account_roles ` +
			`FROM ` + collection
		rows, err := s.postgresDB.Query(sqlstr)
		if err != nil {
			return accounts, err
		}
		defer rows.Close()
		for rows.Next() {
			var a security.Account
			err := rows.Scan(&a.Name, &a.Salt, &a.Hash, &a.State, pq.Array(&a.Roles))
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
	return nil, ErrNotFound
}

// ReadAccount name = Account.name
func (s *store) ReadAccount(name string) (*security.Account, error) {
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
		err := s.postgresDB.QueryRow(sqlstr, name).Scan(&a.Name, &a.Salt, &a.Hash, &a.State, pq.Array(&a.Roles))
		if err != nil {
			if sql.ErrNoRows == err {
				return &a, ErrNotFound
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
	case postgresStore:
		const sqlstr = `UPDATE ` + collection + ` SET (` +
			`account_salt, account_hash, account_state, account_roles` +
			`) = ROW( ` +
			`$1, $2, $3, $4` +
			`) WHERE account_name = $5`
		_, err := s.postgresDB.Exec(sqlstr, &a.Salt, &a.Hash, &a.State, pq.Array(&a.Roles), &a.Name)
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
	case postgresStore:
		const sqlstr = `DELETE FROM ` + collection + ` WHERE account_name = $1`
		_, err := s.postgresDB.Exec(sqlstr, name)
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
